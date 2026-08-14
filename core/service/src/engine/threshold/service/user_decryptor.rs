// === Standard Library ===
use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

// === External Crates ===
use algebra::{
    base_ring::Z128,
    galois_rings::{
        common::{ResiduePoly, pack_residue_poly},
        degree_4::ResiduePolyF4Z128,
    },
    structure_traits::{ErrorCorrect, Invert, Ring, Solve},
};
use alloy_primitives::U256;
use anyhow::anyhow;
use kms_grpc::{
    RequestId,
    identifiers::{ContextId, EpochId},
    kms::v1::{
        self, CiphertextFormat, Empty, TypedCiphertext, TypedSigncryptedCiphertext,
        UserDecryptionRequest, UserDecryptionResponse, UserDecryptionResponsePayload,
    },
};
use observability::{
    metrics,
    metrics_names::{
        OP_USER_DECRYPT_INNER, OP_USER_DECRYPT_REQUEST, OP_USER_DECRYPT_RESULT, TAG_PARTY_ID,
        TAG_TFHE_TYPE, TAG_USER_DECRYPTION_KIND,
    },
};
use rand::{CryptoRng, RngCore};
use thread_handles::spawn_compute_bound;
use threshold_execution::{
    endpoints::decryption::{
        DecryptionMode, LowLevelCiphertextAndKeys, OfflineNoiseFloodSession,
        SmallOfflineNoiseFloodSession, partial_decrypt_using_noiseflooding,
        secure_partial_decrypt_using_bitdec,
    },
    runtime::sessions::small_session::SmallSession,
    tfhe_internals::private_keysets::PrivateKeySet,
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use tokio_util::task::TaskTracker;
use tonic::{Code, Request, Response};
use tracing::Instrument;
use zeroize::Zeroizing;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    consts::DURATION_WAITING_ON_RESULT_SECONDS,
    cryptography::{
        encryption::UnifiedPublicEncKey,
        error::CryptographyError,
        internal_crypto_types::LegacySerialization,
        signcryption::{SigncryptFHEPlaintext, UnifiedSigncryptionKeyOwned},
        signing::SigningSchemeType,
    },
    engine::{
        base::{
            BaseKmsStruct, UserDecryptCallValues, deserialize_to_low_level,
            sign_user_decryption_result,
        },
        threshold::{
            service::session::{ImmutableSessionMaker, validate_context_and_epoch},
            traits::UserDecryptor,
        },
        utils::MetricedError,
        validation::{
            DSEP_USER_DECRYPTION, RequestIdParsingErr, parse_grpc_request_id,
            parse_optional_grpc_request_id, validate_user_decrypt_req,
        },
    },
    util::{
        meta_store::{
            MetaStore, add_or_redo_failed_in_meta_store, retrieve_from_meta_store_with_timeout,
            update_req_in_meta_store,
        },
        rate_limiter::RateLimiter,
    },
    vault::storage::{Storage, StorageExt, crypto_material::ThresholdCryptoMaterialStorage},
};

// === Current Module Imports ===
use super::ThresholdFheKeys;

/// A serialized partial decryption, along with its packing factor and how long it took to produce.
///
/// The bytes are a share of the user's plaintext, so they are kept behind a zeroizing guard and
/// wiped once signcryption is done reading them.
type PartialDecryption = (Zeroizing<Vec<u8>>, u32, std::time::Duration);

#[tonic::async_trait]
pub trait NoiseFloodPartialDecryptor: Send + Sync {
    type Prep: OfflineNoiseFloodSession<{ ResiduePolyF4Z128::EXTENSION_DEGREE }> + Send;
    async fn partial_decrypt(
        noiseflood_session: &mut Self::Prep,
        ct: LowLevelCiphertextAndKeys,
        secret_key_share: &PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    ) -> anyhow::Result<(
        HashMap<String, Vec<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>>,
        u32,
        std::time::Duration,
    )>
    where
        ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>: ErrorCorrect + Invert + Solve;
}

pub struct SecureNoiseFloodPartialDecryptor;

#[tonic::async_trait]
impl NoiseFloodPartialDecryptor for SecureNoiseFloodPartialDecryptor {
    type Prep = SmallOfflineNoiseFloodSession<
        { ResiduePolyF4Z128::EXTENSION_DEGREE },
        SmallSession<ResiduePolyF4Z128>,
    >;

    async fn partial_decrypt(
        noiseflood_session: &mut Self::Prep,
        ct: LowLevelCiphertextAndKeys,
        secret_key_share: &PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    ) -> anyhow::Result<(
        HashMap<String, Vec<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>>,
        u32,
        std::time::Duration,
    )>
    where
        ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>: ErrorCorrect + Invert + Solve,
    {
        partial_decrypt_using_noiseflooding(noiseflood_session, ct, secret_key_share).await
    }
}

pub struct RealUserDecryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    Dec: NoiseFloodPartialDecryptor<
            Prep = SmallOfflineNoiseFloodSession<
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                SmallSession<ResiduePolyF4Z128>,
            >,
        > + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub user_decrypt_meta_store: Arc<RwLock<MetaStore<UserDecryptCallValues>>>,
    pub(crate) session_maker: ImmutableSessionMaker,
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub decryption_mode: DecryptionMode,
    pub(crate) _dec: std::marker::PhantomData<Dec>,
}

impl<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    Dec: NoiseFloodPartialDecryptor<
            Prep = SmallOfflineNoiseFloodSession<
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                SmallSession<ResiduePolyF4Z128>,
            >,
        > + 'static,
> RealUserDecryptor<PubS, PrivS, Dec>
{
    /// Helper method for user decryption which carries out the actual threshold decryption using noise
    /// flooding or bit-decomposition.
    ///
    /// This function does not perform user decryption in a background thread.
    ///
    /// Note that the argument `client_enc_key_bytes` must be the original
    /// bytes that was provided by the user, it should not go through any re-serialization.
    /// The same information is in `signcryption_key.receiver_enc_key` but in there it is
    /// already serialized, that's why the original bytes representation is still needed
    /// for signing later on.
    #[expect(clippy::too_many_arguments)]
    async fn inner_user_decrypt(
        req_id: &RequestId,
        session_maker: ImmutableSessionMaker,
        context_id: ContextId,
        epoch_id: EpochId,
        rng: impl CryptoRng + RngCore + Send + 'static,
        typed_ciphertexts: Vec<TypedCiphertext>,
        link: Vec<u8>,
        signcryption_key: Arc<UnifiedSigncryptionKeyOwned>,
        client_enc_key_bytes_orig: Vec<u8>,
        fhe_keys: OwnedRwLockReadGuard<
            HashMap<(RequestId, EpochId), ThresholdFheKeys>,
            ThresholdFheKeys,
        >,
        dec_mode: DecryptionMode,
        domain: &alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
        signing_schemes: Vec<SigningSchemeType>,
        metric_tags: Vec<(&'static str, String)>,
    ) -> anyhow::Result<UserDecryptCallValues> {
        let keys = fhe_keys;

        let mut all_signcrypted_cts = vec![];

        let rng = Arc::new(Mutex::new(rng));
        // TODO: Each iteration of this loop should probably happen
        // inside its own tokio task
        for (ctr, typed_ciphertext) in typed_ciphertexts.into_iter().enumerate() {
            // Create and start a the timer, it'll be dropped and thus
            // exported at the end of the iteration
            let mut inner_timer = metrics::METRICS
                .time_operation(OP_USER_DECRYPT_INNER)
                .tags(metric_tags.clone())
                .start();
            let fhe_type = typed_ciphertext.fhe_type()?;
            let fhe_type_str = typed_ciphertext.fhe_type_string();
            inner_timer.tag(TAG_TFHE_TYPE, fhe_type_str);
            let ct_format = typed_ciphertext.ciphertext_format();
            let external_handle = typed_ciphertext.external_handle.clone();
            let ct = typed_ciphertext.ciphertext;
            let session_id = req_id.derive_session_id_with_counter(ctr as u64)?;

            let hex_req_id = hex::encode(req_id.as_bytes());
            let decimal_req_id = U256::try_from_be_slice(req_id.as_bytes())
                .unwrap_or(U256::ZERO)
                .to_string();
            tracing::debug!(
                request_id = hex_req_id,
                request_id_decimal = decimal_req_id,
                "User Decrypt Request: Decrypting ciphertext #{ctr} with internal session ID: {session_id} and context ID: {context_id}. Handle: {}",
                hex::encode(&typed_ciphertext.external_handle)
            );

            // Only the SmallCompressed format needs the decompression key to deserialize.
            // Fetching it would lazily decompress the (multi-GiB) keyset, so avoid it for
            // the Big*/SmallExpanded formats that don't use it.
            let decomp_key = match ct_format {
                CiphertextFormat::SmallCompressed => keys.decompression_key(),
                _ => None,
            };
            let low_level_ct =
                deserialize_to_low_level(fhe_type, ct_format, &ct, decomp_key.as_deref())?;

            let pdec: Result<PartialDecryption, anyhow::Error> = match dec_mode {
                DecryptionMode::NoiseFloodSmall => {
                    let session = session_maker
                        .make_small_async_session_z128(session_id, context_id, epoch_id)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Could not prepare ddec data for noiseflood decryption: {e}",
                            )
                        })?;
                    let mut noiseflood_session = Dec::Prep::new(session);

                    // Only `Small` ciphertexts need switch&squash; the closure (and hence the
                    // lazy key decompression it triggers) does not run for the Big* variants.
                    let ct = low_level_ct.with_sns_keys(|| {
                        let server_key = keys.integer_server_key();
                        let ck = keys.sns_key().ok_or(anyhow::anyhow!("Missing sns key"))?;
                        Ok((server_key, ck))
                    })?;

                    let pdec =
                        Dec::partial_decrypt(&mut noiseflood_session, ct, &keys.private_keys).await;

                    let res = match pdec {
                        Ok((partial_dec_map, packing_factor, time)) => {
                            let pdec_serialized = match partial_dec_map.get(&session_id.to_string())
                            {
                                Some(partial_dec) => {
                                    // A serialized partial decryption is a share of the user's
                                    // plaintext, so wipe it once signcryption is done with it.
                                    let partial_dec = pack_residue_poly(partial_dec);
                                    Zeroizing::new(bc2wrap::serialize(&partial_dec)?)
                                }
                                None => {
                                    return Err(anyhow!(
                                        "User decryption with session ID {session_id} could not be retrieved for {dec_mode}"
                                    ));
                                }
                            };

                            (pdec_serialized, packing_factor, time)
                        }
                        Err(e) => {
                            return Err(anyhow!("Failed user decryption with noiseflooding: {e}"));
                        }
                    };
                    Ok(res)
                }
                DecryptionMode::BitDecSmall => {
                    let mut session = session_maker
                        .make_small_async_session_z64(session_id, context_id, epoch_id)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Could not prepare ddec data for bitdec decryption: {e}",
                            )
                        })?;

                    let pdec = secure_partial_decrypt_using_bitdec(
                        &mut session,
                        &low_level_ct.try_get_small_ct()?,
                        &keys.private_keys,
                        &keys.key_switching_key()?,
                    )
                    .await;

                    let res = match pdec {
                        Ok((partial_dec_map, time)) => {
                            let pdec_serialized = match partial_dec_map.get(&session_id.to_string())
                            {
                                Some(partial_dec) => {
                                    // let partial_dec = pack_residue_poly(partial_dec); // TODO use more compact packing for bitdec?
                                    // A serialized partial decryption is a share of the user's
                                    // plaintext, so wipe it once signcryption is done with it.
                                    Zeroizing::new(bc2wrap::serialize(&partial_dec)?)
                                }
                                None => {
                                    return Err(anyhow!(
                                        "User decryption with session ID {session_id} could not be retrieved for {dec_mode}"
                                    ));
                                }
                            };

                            // packing factor is always 1 with bitdec for now
                            // we may optionally pack it later
                            (pdec_serialized, 1, time)
                        }
                        Err(e) => return Err(anyhow!("Failed user decryption with bitdec: {e}")),
                    };
                    Ok(res)
                }
                mode => {
                    return Err(anyhow_error_and_log(format!(
                        "Unsupported Decryption Mode for user_decrypt: {mode}"
                    )));
                }
            };

            let (partial_signcryption, packing_factor) = match pdec {
                Ok((pdec_serialized, packing_factor, time)) => {
                    let enc_res = {
                        let mut rng = rng.lock().map_err(|_| {
                            CryptographyError::Other("Poisoned mutex guard".to_string())
                        })?;
                        signcryption_key.signcrypt_plaintext(
                            rng.deref_mut(),
                            &DSEP_USER_DECRYPTION,
                            pdec_serialized.as_slice(),
                            fhe_type,
                            &link,
                        )
                    }?;

                    tracing::debug!(
                        "User decryption {req_id} in session {session_id} completed for type {:?}. Partial decrypt took {:?} ms",
                        fhe_type,
                        time.as_millis()
                    );
                    // LEGACY: for legacy reasons we return the inner payload only
                    (enc_res.payload, packing_factor)
                }
                Err(e) => return Err(anyhow!("Failed user decryption: {e}")),
            };
            all_signcrypted_cts.push(TypedSigncryptedCiphertext {
                fhe_type: fhe_type as i32,
                signcrypted_ciphertext: partial_signcryption,
                external_handle,
                packing_factor,
            });
            //Explicitly drop the timer to record it
            drop(inner_timer);
        }

        let my_role = session_maker
            .my_role(&context_id)
            .await
            .map_err(|e| anyhow::anyhow!("Could not get my role: {e}"))?;
        let threshold = session_maker
            .threshold(&context_id)
            .await
            .map_err(|e| anyhow::anyhow!("Could not get threshold: {e}"))?;
        let payload = UserDecryptionResponsePayload {
            signcrypted_ciphertexts: all_signcrypted_cts,
            digest: link,
            verification_key: signcryption_key
                .signing_key
                .verf_key()
                .to_legacy_bytes()
                .map_err(|e| anyhow::anyhow!("Could not serialize verification key {}", e))?,
            party_id: my_role.one_based() as u32,
            degree: threshold as u32,
        };

        let domain = domain.clone();
        let signed = spawn_compute_bound(move || {
            sign_user_decryption_result(
                &signcryption_key.signing_key,
                &signing_schemes,
                payload,
                &client_enc_key_bytes_orig,
                extra_data,
                &domain,
            )
        })
        .await
        .map_err(|e| anyhow!("Failed to run signing task for user decryption {req_id}: {e}"))?;
        signed.map_err(|e| anyhow!("Failed to sign user decryption {req_id}: {e}"))
    }

    #[cfg(test)]
    async fn init_test(
        base_kms: BaseKmsStruct,
        pub_storage: PubS,
        priv_storage: PrivS,
        session_maker: ImmutableSessionMaker,
    ) -> Self {
        let crypto_storage =
            ThresholdCryptoMaterialStorage::new(pub_storage, priv_storage, None, HashMap::new());

        let tracker = Arc::new(TaskTracker::new());
        let rate_limiter = RateLimiter::default();

        Self {
            base_kms,
            crypto_storage,
            user_decrypt_meta_store: MetaStore::new_unlimited(),
            session_maker,
            tracker,
            rate_limiter,
            decryption_mode: DecryptionMode::NoiseFloodSmall,
            _dec: std::marker::PhantomData,
        }
    }

    #[cfg(test)]
    fn set_bucket_size(&mut self, bucket_size: usize) {
        let config = crate::util::rate_limiter::RateLimiterConfig {
            bucket_size,
            ..Default::default()
        };
        self.rate_limiter = RateLimiter::new(config);
    }
}

#[tonic::async_trait]
impl<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    Dec: NoiseFloodPartialDecryptor<
            Prep = SmallOfflineNoiseFloodSession<
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                SmallSession<ResiduePolyF4Z128>,
            >,
        > + 'static,
> UserDecryptor for RealUserDecryptor<PubS, PrivS, Dec>
{
    async fn user_decrypt(
        &self,
        request: Request<UserDecryptionRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        metrics::METRICS.increment_request_counter(OP_USER_DECRYPT_REQUEST);

        // Check for resource exhaustion once all the other checks are ok
        // because resource exhaustion can be recovered by sending the exact same request
        // but the errors above cannot be tried again.
        let permit = self.rate_limiter.start_user_decrypt().await?;
        // Start timing before any operations
        let mut timer = metrics::METRICS
            .time_operation(OP_USER_DECRYPT_REQUEST)
            .start();

        let inner = Arc::new(request.into_inner());
        tracing::info!("{}", format_user_request(&inner));

        let (
            typed_ciphertexts,
            link,
            client_enc_key_bytes_orig, // the original bytes for the encryption key
            client_address,
            req_id,
            key_id,
            context_id,
            epoch_id,
            domain,
            extra_data,
            signing_schemes,
        ) = validate_user_decrypt_req(inner.as_ref())?;
        let my_role = validate_context_and_epoch(
            OP_USER_DECRYPT_REQUEST,
            &self.session_maker,
            Some(req_id),
            &context_id,
            &epoch_id,
        )
        .await?;
        let dec_mode = self.decryption_mode;
        let metric_tags = vec![
            (TAG_PARTY_ID, my_role.to_string()),
            (TAG_USER_DECRYPTION_KIND, dec_mode.as_str_name().to_string()),
        ];
        timer.tags(metric_tags.clone());

        let meta_store = Arc::clone(&self.user_decrypt_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let rng = self.base_kms.new_rng().await;

        let sk = (*self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                Some(req_id),
                e,
                tonic::Code::FailedPrecondition,
            )
        })?)
        .clone();
        let client_enc_key = UnifiedPublicEncKey::deserialize_and_validate(
            &client_enc_key_bytes_orig,
        )
        .map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                Some(req_id),
                anyhow::anyhow!("Error deserializing UnifiedPublicEncKey: {e}"),
                tonic::Code::Internal,
            )
        })?;
        let signcryption_key = Arc::new(UnifiedSigncryptionKeyOwned::new(
            sk,
            client_enc_key,
            client_address.to_vec(),
        ));
        // the result of the computation is tracked the tracker
        let session_maker = self.session_maker.clone();

        // Note that we'll hold a read lock for some time
        // as it is moved into the tokio task
        // but this should be ok since write locks
        // happen rarely as keygen is a rare event.
        let fhe_keys_rlock = crypto_storage
            .read_guarded_fhe_keys(&key_id.into(), &epoch_id)
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_USER_DECRYPT_REQUEST,
                    Some(req_id),
                    anyhow::anyhow!("fhe key not found due to {e:?}"),
                    tonic::Code::NotFound,
                )
            })?;

        // Below we write to the meta-store, leaving this [req_id] in the
        // "Started" (Pending) state. The management task updates it on every
        // outcome path; should the permit ever be dropped without an update, the
        // store's reaper fails the entry rather than leaving it Pending forever.
        let meta_permit =
            add_or_redo_failed_in_meta_store(&meta_store, &req_id, OP_USER_DECRYPT_REQUEST).await?;
        let inner_dec_future = move |_permit| async move {
            // Capture the timer, it is stopped when it's dropped
            let _timer = timer;
            let meta_permit = meta_permit;

            let result = Self::inner_user_decrypt(
                &req_id,
                session_maker,
                context_id,
                epoch_id,
                rng,
                typed_ciphertexts,
                link,
                signcryption_key,
                client_enc_key_bytes_orig,
                fhe_keys_rlock,
                dec_mode,
                &domain,
                extra_data,
                signing_schemes,
                metric_tags,
            )
            .await;
            update_req_in_meta_store(&meta_store, meta_permit, result, OP_USER_DECRYPT_REQUEST)
                .await;
        };
        self.tracker.spawn(async move {
            // Ignore the result since this is a background thread.
            let _ = inner_dec_future(permit)
                .instrument(tracing::Span::current())
                .await;
        });
        Ok(Response::new(Empty {}))
    }

    async fn user_decrypt_sync(
        &self,
        request: Request<UserDecryptionRequest>,
    ) -> Result<Response<UserDecryptionResponse>, MetricedError> {
        // `user_decrypt` consumes the request, so keep the raw id for fetching the result below.
        let raw_request_id = request.get_ref().request_id.clone();

        match self.user_decrypt(request).await {
            Ok(_empty) => (),
            // Already succeeded, in flight, or tombstoned: attach to the existing entry
            Err(e) if e.code() == tonic::Code::AlreadyExists => e.defuse(),
            Err(e) => return Err(e),
        }

        // `user_decrypt` accepted the request, so its id must parse.
        let req_id: RequestId =
            parse_optional_grpc_request_id(&raw_request_id, RequestIdParsingErr::UserDecRequest)
                .map_err(|e| {
                    MetricedError::new(OP_USER_DECRYPT_REQUEST, None, e, Code::InvalidArgument)
                })?;

        self.get_result(Request::new(req_id.into())).await
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<UserDecryptionResponse>, MetricedError> {
        metrics::METRICS.increment_request_counter(OP_USER_DECRYPT_RESULT);

        let request_id =
            parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::UserDecResponse)
                .map_err(|e| {
                    MetricedError::new(
                        OP_USER_DECRYPT_RESULT,
                        None,
                        e,
                        tonic::Code::InvalidArgument,
                    )
                })?;

        // Retrieve the UserDecryptMetaStore object
        let arc = retrieve_from_meta_store_with_timeout(
            &self.user_decrypt_meta_store,
            &request_id,
            OP_USER_DECRYPT_RESULT,
            DURATION_WAITING_ON_RESULT_SECONDS,
        )
        .await?;
        let UserDecryptCallValues {
            payload,
            signature,
            external_signature,
            extra_data,
            signatures,
        } = (*arc).clone();

        Ok(Response::new(UserDecryptionResponse {
            signature,
            signatures,
            external_signature,
            payload: Some(payload),
            extra_data,
        }))
    }
}

// We want most of the metadata but not the actual ciphertexts
fn format_user_request(request: &UserDecryptionRequest) -> String {
    format!(
        "UserDecryptionRequest {{ request_id: {:?}, key_id: {:?}, context_id: {:?}, epoch_id: {:?}, client_address: {:?}, enc_key: {:?}, domain: {:?}, typed_ciphertexts_count: {} }}",
        request.request_id,
        request.key_id,
        request.context_id,
        request.epoch_id,
        request.client_address,
        hex::encode(&request.enc_key),
        request.domain,
        request.typed_ciphertexts.len(),
    )
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{CiphertextFormat, SigningSchemeType},
        rpc_types::{KMSType, alloy_to_protobuf_domain},
    };
    use rand::SeedableRng;
    use tfhe::FheTypes;
    use threshold_execution::{
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::prss::PRSSSetup, tfhe_internals::utils::expanded_encrypt,
    };

    use crate::{
        consts::{DEFAULT_MPC_CONTEXT, SAFE_SER_SIZE_LIMIT, TEST_PARAM},
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::gen_sig_keys,
        },
        dummy_domain,
        engine::threshold::service::session::SessionMaker,
        util::meta_store::EntryState,
        vault::storage::{crypto_material::PublicKeySet, ram},
    };

    use super::*;

    struct DummyNoiseFloodPartialDecryptor;

    #[tonic::async_trait]
    impl NoiseFloodPartialDecryptor for DummyNoiseFloodPartialDecryptor {
        type Prep = SmallOfflineNoiseFloodSession<
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            SmallSession<ResiduePolyF4Z128>,
        >;

        async fn partial_decrypt(
            noiseflood_session: &mut Self::Prep,
            _ct: LowLevelCiphertextAndKeys,
            _secret_key_share: &PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        ) -> anyhow::Result<(
            HashMap<String, Vec<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>>,
            u32,
            std::time::Duration,
        )> {
            let session = noiseflood_session.get_mut_base_session();
            let sid: u128 = session.session_id().into();
            Ok((
                HashMap::from_iter([(format!("{sid}"), vec![])]),
                1,
                std::time::Duration::from_millis(100),
            ))
        }
    }

    impl RealUserDecryptor<ram::RamStorage, ram::RamStorage, DummyNoiseFloodPartialDecryptor> {
        pub async fn init_test_dummy_decryptor(
            base_kms: BaseKmsStruct,
            session_maker: ImmutableSessionMaker,
        ) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            Self::init_test(base_kms, pub_storage, priv_storage, session_maker).await
        }
    }

    fn make_dummy_enc_pk(rng: &mut AesRng) -> Vec<u8> {
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, rng);
        let (_enc_sk, enc_pk) = encryption.keygen().unwrap();
        let mut enc_key_buf = Vec::new();
        // The key is freshly generated, so we can safely unwrap the serialization
        tfhe::safe_serialization::safe_serialize(&enc_pk, &mut enc_key_buf, SAFE_SER_SIZE_LIMIT)
            .expect("Failed to serialize ephemeral encryption key");
        enc_key_buf
    }

    fn make_valid_request(
        rng: &mut AesRng,
        req_id: RequestId,
        key_id: RequestId,
        epoch_id: EpochId,
        ct_buf: Vec<u8>,
    ) -> UserDecryptionRequest {
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        UserDecryptionRequest {
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
            enc_key: make_dummy_enc_pk(rng),
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf,
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                // NOTE: because the way [setup_user_decryptor] is implemented,
                // the ciphertext format must be SmallExpanded for the dummy decryptor to work
                ciphertext_format: CiphertextFormat::SmallExpanded as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            request_id: Some(req_id.into()),
            client_address: client_address.to_checksum(None),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some(epoch_id.into()),
        }
    }

    async fn setup_user_decryptor(
        rng: &mut AesRng,
    ) -> (
        RequestId,
        EpochId,
        Vec<u8>,
        RealUserDecryptor<ram::RamStorage, ram::RamStorage, DummyNoiseFloodPartialDecryptor>,
    ) {
        let (_pk, sk) = gen_sig_keys(rng);
        let param = TEST_PARAM;
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk.clone()).unwrap();

        let epoch_id = EpochId::new_random(rng);
        let prss_setup_z128 = Some(PRSSSetup::new_testing_prss(vec![], vec![]));
        let prss_setup_z64 = Some(PRSSSetup::new_testing_prss(vec![], vec![]));

        let session_maker = SessionMaker::four_party_dummy_session(
            prss_setup_z128,
            prss_setup_z64,
            &epoch_id,
            base_kms.new_rng().await,
        );

        let key_id = RequestId::new_random(rng);
        let key_meta_store = MetaStore::new_unlimited();
        let meta_store_permit = key_meta_store.write().await.insert(&key_id).unwrap();

        let user_decryptor =
            RealUserDecryptor::init_test_dummy_decryptor(base_kms, session_maker.make_immutable())
                .await;

        // make a dummy private keyset
        let (threshold_fhe_keys, fhe_key_set) =
            ThresholdFheKeys::init_dummy(param, key_id.into(), rng);

        // Not a huge deal if we clone this server key since we only use small/test parameters
        tfhe::set_server_key(fhe_key_set.server_key.clone());
        let ct: tfhe::FheUint8 = expanded_encrypt(&fhe_key_set.public_key, 255u8, 8).unwrap();
        let mut ct_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &ct,
            &mut ct_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        user_decryptor
            .crypto_storage
            .write_fhe_keys(
                &key_id,
                &epoch_id,
                threshold_fhe_keys,
                PublicKeySet::Uncompressed(Arc::new(fhe_key_set)),
                Arc::clone(&key_meta_store),
                meta_store_permit,
                "",
            )
            .await
            .unwrap_or_else(|_| {
                panic!("failed to write threshold keys for key {key_id} in test setup")
            });

        {
            // check existence
            let _guard = user_decryptor
                .crypto_storage
                .read_guarded_fhe_keys(&key_id, &epoch_id)
                .await
                .unwrap();
        }

        (key_id, epoch_id, ct_buf, user_decryptor)
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let valid_request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);
        {
            // missing request ID
            let mut request = valid_request.clone();
            request.request_id = None;
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrongly formatted request ID
            let mut request = valid_request.clone();
            request.request_id = Some(kms_grpc::kms::v1::RequestId {
                request_id: "invalid_id".to_string(),
            });
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // empty typed ciphertexts
            let mut request = valid_request.clone();
            request.typed_ciphertexts.clear();
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // missing domain
            let mut request = valid_request.clone();
            request.domain = None;
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // bad client address
            let mut request = valid_request.clone();
            request.client_address = "bad client address".to_string();
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrongly formatted request ID on the result endpoint
            let bad_req_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_id".to_string(),
            };
            let err = user_decryptor
                .get_result(Request::new(bad_req_id))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrongly formatted key ID
            let mut request = valid_request.clone();
            request.key_id = Some(kms_grpc::kms::v1::RequestId {
                request_id: "invalid_key_id".to_string(),
            });
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, mut user_decryptor) = setup_user_decryptor(&mut rng).await;
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        // Set bucket size to zero, so no operations are allowed
        user_decryptor.set_bucket_size(0);

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);
        let err = user_decryptor
            .user_decrypt(Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // the sync endpoint is rate-limited the same way
        let err = user_decryptor
            .user_decrypt_sync(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // finally reset the bucket size to a non-zero value
        user_decryptor.set_bucket_size(100);
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let valid_request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);

        {
            // unknown key ID
            let mut request = valid_request.clone();
            request.key_id = Some(RequestId::new_random(&mut rng).into());
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        {
            // unknown epoch ID
            let mut request = valid_request.clone();
            request.epoch_id = Some(EpochId::new_random(&mut rng).into());
            let err = user_decryptor
                .user_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);

            let err = user_decryptor
                .user_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        {
            // unknown request ID on the result endpoint
            let another_req_id = RequestId::new_random(&mut rng);
            let err = user_decryptor
                .get_result(Request::new(another_req_id.into()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);
        user_decryptor
            .user_decrypt(Request::new(request.clone()))
            .await
            .unwrap();

        // try sending the same request again
        let err = user_decryptor
            .user_decrypt(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        // finally everything is ok
        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);
        user_decryptor
            .user_decrypt(Request::new(request))
            .await
            .unwrap();
        crate::testing::utils::poll_result_until_ready(|| {
            user_decryptor.get_result(Request::new(req_id.into()))
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sunshine_sync() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);

        // The sync endpoint returns the response directly, no polling needed.
        let response = user_decryptor
            .user_decrypt_sync(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let payload = response
            .payload
            .clone()
            .expect("sync response carries a payload");
        assert_eq!(payload.signcrypted_ciphertexts.len(), 1);
        assert!(!response.signature.is_empty());

        // The request went through the meta-store, so the result stays retrievable through the
        // async result endpoint...
        let again = user_decryptor
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.payload, again.payload);

        // ...and re-sending the same sync request returns that stored result instead of failing
        // with `AlreadyExists`. Attaching is a success path, so nothing may be recorded as a
        // failure along the way.
        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let retry = user_decryptor
            .user_decrypt_sync(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.payload, retry.payload);
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before,
            "attaching to an already-known request ID must not report a failure"
        );
    }

    #[tokio::test]
    async fn sync_call_shares_request_and_result_counters() {
        let mut rng = AesRng::seed_from_u64(42);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);

        let requests_before = metrics::METRICS.request_counter_value(OP_USER_DECRYPT_REQUEST);
        let results_before = metrics::METRICS.request_counter_value(OP_USER_DECRYPT_RESULT);
        user_decryptor
            .user_decrypt_sync(Request::new(request))
            .await
            .unwrap();
        // Check global growth: the counters are shared at the process level.
        assert!(metrics::METRICS.request_counter_value(OP_USER_DECRYPT_REQUEST) > requests_before);
        assert!(metrics::METRICS.request_counter_value(OP_USER_DECRYPT_RESULT) > results_before);
    }

    #[tokio::test]
    async fn sync_attaches_to_async_request() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);

        // Start the decryption through the async endpoint...
        user_decryptor
            .user_decrypt(Request::new(request.clone()))
            .await
            .unwrap();

        // ...then a sync request with the same request ID attaches to that entry rather than
        // starting a second decryption, without reporting a failure along the way.
        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let response = user_decryptor
            .user_decrypt_sync(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response
                .payload
                .clone()
                .expect("sync response carries a payload")
                .signcrypted_ciphertexts
                .len(),
            1
        );
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before,
            "attaching to an in-flight request must not report a failure"
        );

        // The entry the sync call waited on is the one the async request created.
        let stored = user_decryptor
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.payload, stored.payload);
    }

    /// A `request_id` whose previous attempt failed is redone, exactly as re-sending it to the
    /// async endpoint would be, and the sync call returns the new attempt's outcome.
    #[tokio::test]
    async fn sync_redoes_failed_request() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);

        // Leave the request ID in the state a failed attempt would leave it in.
        let permit = user_decryptor
            .user_decrypt_meta_store
            .write()
            .await
            .insert(&req_id)
            .unwrap();
        crate::util::meta_store::update_err_req_in_meta_store(
            &user_decryptor.user_decrypt_meta_store,
            permit,
            "forced failure".to_string(),
            OP_USER_DECRYPT_REQUEST,
        )
        .await;
        assert!(matches!(
            user_decryptor
                .user_decrypt_meta_store
                .read()
                .await
                .retrieve(&req_id),
            Some(EntryState::Done(Err(_)))
        ));

        // The sync call redoes the decryption instead of returning the stored failure.
        let response = user_decryptor
            .user_decrypt_sync(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response
                .payload
                .expect("redone decryption carries a payload")
                .signcrypted_ciphertexts
                .len(),
            1
        );
    }

    /// A failed entry that is still permit-held cannot be redone, so `user_decrypt` answers
    /// `AlreadyExists`, which the sync endpoint reads as "attach to the existing entry". That
    /// internal signal must be defused rather than dropped: dropping a `MetricedError` records
    /// an error and logs a failure for what is only a control-flow decision.
    #[tokio::test]
    async fn sync_attach_signal_is_not_recorded_as_error() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(&mut rng, req_id, key_id, epoch_id, ct_buf);

        // Fail the entry, then hold a permit on it so that `redo_failed` reports `Locked`.
        let permit = user_decryptor
            .user_decrypt_meta_store
            .write()
            .await
            .insert(&req_id)
            .unwrap();
        crate::util::meta_store::update_err_req_in_meta_store(
            &user_decryptor.user_decrypt_meta_store,
            permit,
            "forced failure".to_string(),
            OP_USER_DECRYPT_REQUEST,
        )
        .await;
        let _held_permit = user_decryptor
            .user_decrypt_meta_store
            .write()
            .await
            .lock_entry(&req_id)
            .unwrap();

        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let err = user_decryptor
            .user_decrypt_sync(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        // `err` has not been returned to a caller yet, so nothing should have been recorded so
        // far: an `AlreadyExists` dropped instead of defused would already show up here.
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before,
            "the internal attach signal must not be recorded as a failure"
        );
        // Handing the error back to the caller records it exactly once.
        drop(err);
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before + 1
        );
    }
}
