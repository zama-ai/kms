// === Standard Library ===
use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

// === External Crates ===
use alloy_primitives::U256;
use anyhow::anyhow;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{
        self, Empty, TypedCiphertext, TypedSigncryptedCiphertext, UserDecryptionRequest,
        UserDecryptionResponse, UserDecryptionResponsePayload,
    },
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        OP_USER_DECRYPT_INNER, OP_USER_DECRYPT_REQUEST, OP_USER_DECRYPT_RESULT, TAG_CONTEXT_ID,
        TAG_EPOCH_ID, TAG_KEY_ID, TAG_PARTY_ID, TAG_TFHE_TYPE, TAG_USER_DECRYPTION_KIND,
    },
};
use rand::{CryptoRng, RngCore};
use threshold_fhe::{
    algebra::{
        base_ring::Z128,
        galois_rings::{
            common::{pack_residue_poly, ResiduePoly},
            degree_4::ResiduePolyF4Z128,
        },
        structure_traits::{ErrorCorrect, Invert, Ring, Solve},
    },
    execution::{
        endpoints::decryption::{
            partial_decrypt_using_noiseflooding, secure_partial_decrypt_using_bitdec,
            DecryptionMode, LowLevelCiphertext, OfflineNoiseFloodSession,
            SmallOfflineNoiseFloodSession,
        },
        runtime::sessions::small_session::SmallSession,
        tfhe_internals::private_keysets::PrivateKeySet,
    },
    thread_handles::spawn_compute_bound,
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use tokio_util::task::TaskTracker;
use tonic::{Request, Response};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    cryptography::{
        compute_external_user_decrypt_signature,
        error::CryptographyError,
        internal_crypto_types::LegacySerialization,
        signcryption::{SigncryptFHEPlaintext, UnifiedSigncryptionKeyOwned},
    },
    engine::{
        base::{deserialize_to_low_level, BaseKmsStruct, UserDecryptCallValues},
        threshold::{service::session::ImmutableSessionMaker, traits::UserDecryptor},
        traits::BaseKms,
        utils::MetricedError,
        validation::{
            proto_request_id, validate_user_decrypt_req, RequestIdParsingErr, DSEP_USER_DECRYPTION,
        },
    },
    util::{
        meta_store::{
            add_req_to_meta_store, retrieve_from_meta_store, update_req_in_meta_store, MetaStore,
        },
        rate_limiter::RateLimiter,
    },
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage, StorageExt},
};

// === Current Module Imports ===
use super::ThresholdFheKeys;

#[tonic::async_trait]
pub trait NoiseFloodPartialDecryptor: Send + Sync {
    type Prep: OfflineNoiseFloodSession<{ ResiduePolyF4Z128::EXTENSION_DEGREE }> + Send;
    async fn partial_decrypt(
        noiseflood_session: &mut Self::Prep,
        server_key: Arc<tfhe::integer::ServerKey>,
        ck: Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>,
        ct: LowLevelCiphertext,
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
        server_key: Arc<tfhe::integer::ServerKey>,
        ck: Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>,
        ct: LowLevelCiphertext,
        secret_key_share: &PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
    ) -> anyhow::Result<(
        HashMap<String, Vec<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>>,
        u32,
        std::time::Duration,
    )>
    where
        ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>: ErrorCorrect + Invert + Solve,
    {
        partial_decrypt_using_noiseflooding(
            noiseflood_session,
            server_key,
            ck,
            ct,
            secret_key_share,
        )
        .await
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
    /// The return type should be [UserDecryptCallValues] except the final item in the tuple
    #[allow(clippy::too_many_arguments)]
    async fn inner_user_decrypt(
        req_id: &RequestId,
        session_maker: ImmutableSessionMaker,
        context_id: ContextId,
        epoch_id: EpochId,
        rng: impl CryptoRng + RngCore + Send + 'static,
        typed_ciphertexts: Vec<TypedCiphertext>,
        link: Vec<u8>,
        signcryption_key: Arc<UnifiedSigncryptionKeyOwned>,
        fhe_keys: OwnedRwLockReadGuard<
            HashMap<(RequestId, EpochId), ThresholdFheKeys>,
            ThresholdFheKeys,
        >,
        dec_mode: DecryptionMode,
        domain: &alloy_sol_types::Eip712Domain,
        metric_tags: Vec<(&'static str, String)>,
    ) -> anyhow::Result<(UserDecryptionResponsePayload, Vec<u8>, Vec<u8>)> {
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

            let decomp_key = keys.decompression_key.clone();
            let low_level_ct = spawn_compute_bound(move || {
                deserialize_to_low_level(fhe_type, ct_format, &ct, decomp_key.as_deref())
            })
            .await??;

            let pdec: Result<(Vec<u8>, u32, std::time::Duration), anyhow::Error> = match dec_mode {
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

                    let pdec = Dec::partial_decrypt(
                        &mut noiseflood_session,
                        keys.integer_server_key.clone(),
                        keys.sns_key
                            .clone()
                            .ok_or_else(|| anyhow::anyhow!("missing sns key"))?,
                        low_level_ct,
                        &keys.private_keys,
                    )
                    .await;

                    let res = match pdec {
                        Ok((partial_dec_map, packing_factor, time)) => {
                            let pdec_serialized = match partial_dec_map.get(&session_id.to_string())
                            {
                                Some(partial_dec) => {
                                    let partial_dec = pack_residue_poly(partial_dec);
                                    bc2wrap::serialize(&partial_dec)?
                                }
                                None => {
                                    return Err(anyhow!(
                                        "User decryption with session ID {session_id} could not be retrived for {dec_mode}"
                                    ))
                                }
                            };

                            (pdec_serialized, packing_factor, time)
                        }
                        Err(e) => {
                            return Err(anyhow!("Failed user decryption with noiseflooding: {e}"))
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
                        keys.get_key_switching_key()?,
                    )
                    .await;

                    let res = match pdec {
                        Ok((partial_dec_map, time)) => {
                            let pdec_serialized = match partial_dec_map.get(&session_id.to_string())
                            {
                                Some(partial_dec) => {
                                    // let partial_dec = pack_residue_poly(partial_dec); // TODO use more compact packing for bitdec?
                                    bc2wrap::serialize(&partial_dec)?
                                }
                                None => {
                                    return Err(anyhow!(
                                        "User decryption with session ID {session_id} could not be retrived for {dec_mode}"
                                    ))
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
                    let rng = rng.clone();
                    let signcryption_key_clone = Arc::clone(&signcryption_key);
                    let link_clone = link.clone();

                    let enc_res = spawn_compute_bound(move || {
                        let mut rng = rng.lock().map_err(|_| {
                            CryptographyError::Other("Poisoned mutex guard".to_string())
                        })?;
                        signcryption_key_clone.signcrypt_plaintext(
                            rng.deref_mut(),
                            &DSEP_USER_DECRYPTION,
                            &pdec_serialized,
                            fhe_type,
                            &link_clone,
                        )
                    })
                    .await??;

                    tracing::debug!(
                        "User decryption {req_id} in session {session_id} ccompleted for type {:?}. Inner thread took {:?} ms",
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

        // NOTE: extra_data is not used in the current implementation
        let extra_data = vec![];
        let external_signature = compute_external_user_decrypt_signature(
            &signcryption_key.signing_key,
            &payload,
            domain,
            &signcryption_key.receiver_enc_key,
            extra_data.clone(),
        )?;
        Ok((payload, external_signature, extra_data))
    }

    #[cfg(test)]
    async fn init_test(
        base_kms: BaseKmsStruct,
        pub_storage: PubS,
        priv_storage: PrivS,
        session_maker: ImmutableSessionMaker,
    ) -> Self {
        let crypto_storage = ThresholdCryptoMaterialStorage::new(
            pub_storage,
            priv_storage,
            None,
            HashMap::new(),
            HashMap::new(),
        );

        let tracker = Arc::new(TaskTracker::new());
        let rate_limiter = RateLimiter::default();

        Self {
            base_kms,
            crypto_storage,
            user_decrypt_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
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
        // Check for resource exhaustion once all the other checks are ok
        // because resource exhaustion can be recovered by sending the exact same request
        // but the errors above cannot be tried again.
        let permit = self.rate_limiter.start_user_decrypt().await.map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                None,
                e,
                tonic::Code::ResourceExhausted,
            )
        })?;
        // Start timing and counting before any operations
        let mut timer = metrics::METRICS
            .time_operation(OP_USER_DECRYPT_REQUEST)
            .start();

        let inner = Arc::new(request.into_inner());
        tracing::info!("{}", format_user_request(&inner));

        let (
            typed_ciphertexts,
            link,
            client_enc_key,
            client_address,
            req_id,
            key_id,
            context_id,
            epoch_id,
            domain,
        ) = validate_user_decrypt_req(inner.as_ref()).map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                None,
                e, // Validation error
                tonic::Code::InvalidArgument,
            )
        })?;

        // Find the role of the current server and validate the context exists
        let my_role = self.session_maker.my_role(&context_id).await.map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                Some(req_id),
                e,
                tonic::Code::NotFound,
            )
        })?;
        let dec_mode = self.decryption_mode;
        let metric_tags = vec![
            (TAG_PARTY_ID, my_role.to_string()),
            (TAG_KEY_ID, key_id.as_str()), // TODO will this be too many labels or does it make sense to keep key, context and epoch
            (TAG_CONTEXT_ID, context_id.as_str()),
            (TAG_EPOCH_ID, epoch_id.as_str()),
            (TAG_USER_DECRYPTION_KIND, dec_mode.as_str_name().to_string()),
        ];
        timer.tags(metric_tags.clone());

        let meta_store = Arc::clone(&self.user_decrypt_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let rng = self.base_kms.new_rng().await;
        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        add_req_to_meta_store(
            &mut meta_store.write().await,
            &req_id,
            OP_USER_DECRYPT_REQUEST,
        )?;

        let sk = (*self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                Some(req_id),
                e,
                tonic::Code::FailedPrecondition,
            )
        })?)
        .clone();
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
            .read_guarded_threshold_fhe_keys(&key_id.into(), &epoch_id)
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_USER_DECRYPT_REQUEST,
                    Some(req_id),
                    anyhow::anyhow!("fhe key not found due to {e:?}"),
                    tonic::Code::NotFound,
                )
            })?;

        let inner_dec_future = move |_permit| async move {
            // Capture the timer, it is stopped when it's dropped
            let _timer = timer;

            let result = Self::inner_user_decrypt(
                &req_id,
                session_maker,
                context_id,
                epoch_id,
                rng,
                typed_ciphertexts,
                link,
                signcryption_key,
                fhe_keys_rlock,
                dec_mode,
                &domain,
                metric_tags,
            )
            .await;
            update_req_in_meta_store(
                &mut meta_store.write().await,
                &req_id,
                result,
                OP_USER_DECRYPT_REQUEST,
            );
        };
        self.tracker.spawn(async move {
            // Ignore the result since this is a background thread.
            let _ = inner_dec_future(permit)
                .instrument(tracing::Span::current())
                .await;
        });
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<UserDecryptionResponse>, MetricedError> {
        let request_id =
            proto_request_id(&request.into_inner(), RequestIdParsingErr::UserDecResponse).map_err(
                |e| {
                    MetricedError::new(
                        OP_USER_DECRYPT_RESULT,
                        None,
                        e,
                        tonic::Code::InvalidArgument,
                    )
                },
            )?;

        // Retrieve the UserDecryptMetaStore object
        let (payload, external_signature, extra_data) = retrieve_from_meta_store(
            self.user_decrypt_meta_store.read().await,
            &request_id,
            OP_USER_DECRYPT_RESULT,
        )
        .await?;

        let sig_payload_vec = bc2wrap::serialize(&payload).map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_RESULT,
                Some(request_id),
                anyhow!("Could not convert payload to bytes {payload:?}: {e:?}"),
                tonic::Code::Internal,
            )
        })?;

        let sig = self
            .base_kms
            .sign(&DSEP_USER_DECRYPTION, &sig_payload_vec)
            .map_err(|e| {
                MetricedError::new(
                    OP_USER_DECRYPT_RESULT,
                    Some(request_id),
                    anyhow!("Could not sign payload {payload:?}: {e:?}"),
                    tonic::Code::Internal,
                )
            })?;
        Ok(Response::new(UserDecryptionResponse {
            signature: sig.sig.to_vec(),
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
        request.request_id, request.key_id, request.context_id, request.epoch_id, request.client_address, hex::encode(&request.enc_key), request.domain, request.typed_ciphertexts.len(),
    )
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::CiphertextFormat,
        rpc_types::{alloy_to_protobuf_domain, KMSType},
    };
    use rand::SeedableRng;
    use tfhe::FheTypes;
    use threshold_fhe::execution::{
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
        engine::{
            base::{compute_info_standard_keygen, DSEP_PUBDATA_KEY},
            threshold::service::session::SessionMaker,
        },
        vault::storage::ram,
    };

    use super::*;

    struct DummyNoiseFloodPartialDecryptor;

    #[tonic::async_trait]
    impl NoiseFloodPartialDecryptor for DummyNoiseFloodPartialDecryptor {
        type Prep = SmallOfflineNoiseFloodSession<
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            threshold_fhe::execution::runtime::sessions::small_session::SmallSession<
                ResiduePolyF4Z128,
            >,
        >;

        async fn partial_decrypt(
            noiseflood_session: &mut Self::Prep,
            _server_key: Arc<tfhe::integer::ServerKey>,
            _ck: Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>,
            _ct: LowLevelCiphertext,
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
        let mut key_store = MetaStore::new_unlimited();
        key_store.insert(&key_id).unwrap();
        let key_meta_store = Arc::new(RwLock::new(key_store));

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

        let dummy_prep_id = RequestId::new_random(rng);
        let info = compute_info_standard_keygen(
            &sk,
            &DSEP_PUBDATA_KEY,
            &dummy_prep_id,
            &key_id,
            &fhe_key_set,
            &dummy_domain(),
        )
        .unwrap();

        user_decryptor
            .crypto_storage
            .write_threshold_keys_with_dkg_meta_store(
                &key_id,
                &epoch_id,
                threshold_fhe_keys,
                fhe_key_set,
                info,
                Arc::clone(&key_meta_store),
            )
            .await;

        {
            // check existance
            let _guard = user_decryptor
                .crypto_storage
                .read_guarded_threshold_fhe_keys(&key_id, &epoch_id)
                .await
                .unwrap();
        }

        (key_id, epoch_id, ct_buf, user_decryptor)
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let domain = dummy_domain();

        {
            let bad_req_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_id".to_string(),
            };
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::BigExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
                request_id: Some(bad_req_id),
                client_address: client_address.to_checksum(None),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // empty typed ciphertexts
            let req_id = RequestId::new_random(&mut rng);
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
                request_id: Some(req_id.into()),
                client_address: client_address.to_checksum(None),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // missing domain
            let req_id = RequestId::new_random(&mut rng);
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::BigExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: None,
                request_id: Some(req_id.into()),
                client_address: client_address.to_checksum(None),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // bad client address
            let req_id = RequestId::new_random(&mut rng);
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::BigExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
                request_id: Some(req_id.into()),
                client_address: "bad client address".to_string(),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            let bad_req_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_id".to_string(),
            };
            assert_eq!(
                user_decryptor
                    .get_result(Request::new(bad_req_id))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        // Invalid decryption key id
        {
            let req_id = RequestId::new_random(&mut rng);
            let bad_key_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_key_id".to_string(),
            };
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::BigExpanded as i32,
                }],
                key_id: Some(bad_key_id),
                domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
                request_id: Some(req_id.into()),
                client_address: client_address.to_checksum(None),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, mut user_decryptor) = setup_user_decryptor(&mut rng).await;
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let domain = dummy_domain();
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        // Set bucket size to zero, so no operations are allowed
        user_decryptor.set_bucket_size(0);

        let req_id = RequestId::new_random(&mut rng);
        let request = Request::new(UserDecryptionRequest {
            enc_key: make_dummy_enc_pk(&mut rng),
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf.clone(),
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                ciphertext_format: CiphertextFormat::BigExpanded as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
            request_id: Some(req_id.into()),
            client_address: client_address.to_checksum(None),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some(epoch_id.into()),
        });
        assert_eq!(
            user_decryptor
                .user_decrypt(request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );

        // finally reset the bucket size to a non-zero value
        user_decryptor.set_bucket_size(100);
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let domain = dummy_domain();

        {
            // bad key ID
            let req_id = RequestId::new_random(&mut rng);
            let bad_key_id = RequestId::new_random(&mut rng);
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::BigExpanded as i32,
                }],
                key_id: Some(bad_key_id.into()),
                domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
                request_id: Some(req_id.into()),
                client_address: client_address.to_checksum(None),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
        }

        {
            // bad epoch ID
            let req_id = RequestId::new_random(&mut rng);
            let bad_epoch_id = EpochId::new_random(&mut rng);
            let request = Request::new(UserDecryptionRequest {
                enc_key: make_dummy_enc_pk(&mut rng),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::BigExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
                request_id: Some(req_id.into()),
                client_address: client_address.to_checksum(None),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: Some(bad_epoch_id.into()),
            });
            assert_eq!(
                user_decryptor
                    .user_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
        }

        let another_req_id = RequestId::new_random(&mut rng);
        assert_eq!(
            user_decryptor
                .get_result(Request::new(another_req_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let domain = dummy_domain();

        let req_id = RequestId::new_random(&mut rng);
        let request = UserDecryptionRequest {
            enc_key: make_dummy_enc_pk(&mut rng),
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf.clone(),
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                ciphertext_format: CiphertextFormat::BigExpanded as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
            request_id: Some(req_id.into()),
            client_address: client_address.to_checksum(None),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some(epoch_id.into()),
        };
        user_decryptor
            .user_decrypt(Request::new(request.clone()))
            .await
            .unwrap();

        // try sending the same request again
        assert_eq!(
            user_decryptor
                .user_decrypt(Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(123);
        let (key_id, epoch_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let domain = dummy_domain();

        // finally everything is ok
        let req_id = RequestId::new_random(&mut rng);
        let request = Request::new(UserDecryptionRequest {
            enc_key: make_dummy_enc_pk(&mut rng),
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf.clone(),
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                // NOTE: because the way [setup_user_decryptor] is implemented,
                // the ciphertext format must be SmallExpanded for the dummy decryptor to work
                ciphertext_format: CiphertextFormat::SmallExpanded as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
            request_id: Some(req_id.into()),
            client_address: client_address.to_checksum(None),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some(epoch_id.into()),
        });
        user_decryptor.user_decrypt(request).await.unwrap();
        user_decryptor
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap();
    }
}
