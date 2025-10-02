// === Standard Library ===
use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

// === External Crates ===
use anyhow::anyhow;
use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{
        self, Empty, TypedCiphertext, TypedPlaintext, TypedSigncryptedCiphertext,
        UserDecryptionRequest, UserDecryptionResponse, UserDecryptionResponsePayload,
    },
    utils::tonic_result::BoxedStatus,
    IdentifierError, RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        ERR_USER_DECRYPTION_FAILED, ERR_WITH_META_STORAGE, OP_USER_DECRYPT_INNER,
        OP_USER_DECRYPT_REQUEST, TAG_KEY_ID, TAG_PARTY_ID, TAG_PUBLIC_DECRYPTION_KIND,
        TAG_TFHE_TYPE,
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
        runtime::session::SmallSession,
        tfhe_internals::private_keysets::PrivateKeySet,
    },
    thread_handles::spawn_compute_bound,
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    consts::DEFAULT_MPC_CONTEXT,
    cryptography::{
        internal_crypto_types::{PrivateSigKey, UnifiedPublicEncKey},
        signcryption::SigncryptionPayload,
    },
    engine::{
        base::{
            compute_external_user_decrypt_signature, deserialize_to_low_level, BaseKmsStruct,
            UserDecryptCallValues,
        },
        threshold::{service::session::SessionPreparerGetter, traits::UserDecryptor},
        traits::BaseKms,
        validation::{
            parse_proto_request_id, validate_user_decrypt_req, RequestIdParsingErr,
            DSEP_USER_DECRYPTION,
        },
    },
    ok_or_tonic_abort,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};

// === Current Module Imports ===
use super::{session::SessionPreparer, ThresholdFheKeys};

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
    PrivS: Storage + Send + Sync + 'static,
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
    pub session_preparer_getter: SessionPreparerGetter,
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub decryption_mode: DecryptionMode,
    pub(crate) _dec: std::marker::PhantomData<Dec>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
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
        session_prep: Arc<SessionPreparer>,
        context_id: ContextId,
        rng: impl CryptoRng + RngCore + Send + 'static,
        typed_ciphertexts: Vec<TypedCiphertext>,
        link: Vec<u8>,
        client_enc_key: UnifiedPublicEncKey,
        client_address: alloy_primitives::Address,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
        server_verf_key: Vec<u8>,
        dec_mode: DecryptionMode,
        domain: &alloy_sol_types::Eip712Domain,
        metric_tags: Vec<(&'static str, String)>,
    ) -> anyhow::Result<(UserDecryptionResponsePayload, Vec<u8>, Vec<u8>)> {
        let keys = fhe_keys;

        let mut all_signcrypted_cts = vec![];

        let rng = Arc::new(Mutex::new(rng));
        let client_enc_key = Arc::new(client_enc_key);
        let client_address = Arc::new(client_address);

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
            let decimal_req_id: u128 = (*req_id).try_into().unwrap_or(0);
            tracing::info!(
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
                    let session = ok_or_tonic_abort(
                        session_prep
                            .make_small_async_session_z128(session_id, context_id)
                            .await,
                        "Could not prepare ddec data for noiseflood decryption".to_string(),
                    )?;
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
                                        "User decryption with session ID {} could not be retrived for {dec_mode}",
                                        session_id.to_string()
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
                    let mut session = ok_or_tonic_abort(
                        session_prep
                            .make_small_async_session_z64(session_id, context_id)
                            .await,
                        "Could not prepare ddec data for bitdec decryption".to_string(),
                    )?;

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
                                        "User decryption with session ID {} could not be retrived for {dec_mode}",
                                        session_id.to_string()
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
                    let signcryption_msg = SigncryptionPayload {
                        plaintext: TypedPlaintext::from_bytes(pdec_serialized, fhe_type),
                        link: link.clone(),
                    };

                    let rng = rng.clone();
                    let sig_key = sig_key.clone();
                    let client_enc_key = client_enc_key.clone();
                    let client_address = client_address.clone();

                    let enc_res = spawn_compute_bound(move || {
                        let mut rng = rng
                            .lock()
                            .map_err(|_| anyhow_error_and_log("Poisoned mutex guard"))?;
                        signcrypt(
                            rng.deref_mut(),
                            &DSEP_USER_DECRYPTION,
                            &bc2wrap::serialize(&signcryption_msg)?,
                            &client_enc_key,
                            &client_address,
                            &sig_key,
                        )
                    })
                    .await??;
                    let res = bc2wrap::serialize(&enc_res)?;

                    tracing::info!(
                        "User decryption completed for type {:?}. Inner thread took {:?} ms",
                        fhe_type,
                        time.as_millis()
                    );
                    (res, packing_factor)
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

        let payload = UserDecryptionResponsePayload {
            signcrypted_ciphertexts: all_signcrypted_cts,
            digest: link,
            verification_key: server_verf_key,
            party_id: session_prep.my_role()?.one_based() as u32,
            degree: session_prep.threshold()? as u32,
        };

        // NOTE: extra_data is not used in the current implementation
        let extra_data = vec![];
        let external_signature = compute_external_user_decrypt_signature(
            &sig_key,
            &payload,
            domain,
            &client_enc_key,
            extra_data.clone(),
        )?;
        Ok((payload, external_signature, extra_data))
    }

    #[cfg(test)]
    async fn init_test(
        base_kms: BaseKmsStruct,
        pub_storage: PubS,
        priv_storage: PrivS,
        session_preparer_getter: SessionPreparerGetter,
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
            session_preparer_getter,
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

// We want most of the metadata but not the actual ciphertexts
fn format_user_request(request: &UserDecryptionRequest) -> String {
    format!(
        "UserDecryptionRequest {{ request_id: {:?}, key_id: {:?}, client_address: {:?}, enc_key: {:?}, domain: {:?}, typed_ciphertexts_count: {} }}",
        request.request_id, request.key_id, request.client_address, hex::encode(&request.enc_key), request.domain, request.typed_ciphertexts.len(),
    )
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
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
    ) -> Result<Response<Empty>, Status> {
        let inner = Arc::new(request.into_inner());
        tracing::info!(
            request_id = ?inner.request_id,
            "Received a new user decryption request",
        );

        // TODO(zama-ai/kms-internal/issues/2758)
        // remove the default context when all of context is ready
        let context_id: ContextId = match &inner.context_id {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => *DEFAULT_MPC_CONTEXT,
        };
        let session_preparer = Arc::new(
            self.session_preparer_getter
                .get(&context_id)
                .await
                .map_err(|e| tonic::Status::new(tonic::Code::Internal, e.to_string()))?,
        );

        // Start timing and counting before any operations
        let mut timer = metrics::METRICS
            .time_operation(OP_USER_DECRYPT_REQUEST)
            .tag(
                TAG_PARTY_ID,
                session_preparer
                    .my_role()
                    .map_err(|e| tonic::Status::new(tonic::Code::Internal, e.to_string()))?
                    .to_string(),
            )
            .start();

        let permit = self.rate_limiter.start_user_decrypt().await?;

        let (typed_ciphertexts, link, client_enc_key, client_address, key_id, req_id, domain) = {
            let inner = inner.clone();
            spawn_compute_bound(move || validate_user_decrypt_req(inner.as_ref()))
                .await
                .map_err(|_| {
                    BoxedStatus::from(tonic::Status::new(
                        tonic::Code::Internal,
                        "Error delegating validate_user_decrypt_req to rayon".to_string(),
                    ))
                })?
        }
        .inspect_err(|e| {
            tracing::error!(
                error = ?e,
                request_id = ?inner.request_id,
                "Failed to validate decrypt request {}",
                format_user_request(inner.as_ref())
            );
        })?;

        timer.tags([(TAG_KEY_ID, key_id.as_str())]);

        let meta_store = Arc::clone(&self.user_decrypt_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let rng = self.base_kms.new_rng().await;
        let sig_key = Arc::clone(&self.base_kms.sig_key);

        // Do some checks before we start modifying the database
        {
            let guarded_meta_store = self.user_decrypt_meta_store.read().await;

            if guarded_meta_store.exists(&req_id) {
                return Err(Status::already_exists(format!(
                    "User decryption request with ID {req_id} already exists"
                )));
            }
        }

        self.crypto_storage
            .refresh_threshold_fhe_keys(&key_id)
            .await
            .map_err(|e| {
                tracing::warn!(error=?e, key_id=?key_id, "Failed to refresh threshold FHE keys");
                Status::not_found(format!("Threshold FHE keys with key ID {key_id} not found"))
            })?;

        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        {
            let mut guarded_meta_store = self.user_decrypt_meta_store.write().await;
            ok_or_tonic_abort(
                guarded_meta_store.insert(&req_id),
                "Could not insert user decryption request".to_string(),
            )?;
        }

        let prep = Arc::clone(&session_preparer);
        let dec_mode = self.decryption_mode;

        let metric_tags = vec![
            (TAG_PARTY_ID, prep.my_role_string_unchecked()),
            (TAG_KEY_ID, key_id.as_str()),
            (
                TAG_PUBLIC_DECRYPTION_KIND,
                dec_mode.as_str_name().to_string(),
            ),
        ];

        let server_verf_key = self.base_kms.get_serialized_verf_key();

        // the result of the computation is tracked the tracker
        self.tracker.spawn(
            async move {
                // Capture the timer, it is stopped when it's dropped
                let _timer = timer;
                // explicitly move the rate limiter context
                let _permit = permit;
                // Note that we'll hold a read lock for some time
                // but this should be ok since write locks
                // happen rarely as keygen is a rare event.
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await;
                let tmp = match fhe_keys_rlock {
                    Ok(k) => {
                        Self::inner_user_decrypt(
                            &req_id,
                            prep,
                            context_id,
                            rng,
                            typed_ciphertexts,
                            link.clone(),
                            client_enc_key,
                            client_address,
                            sig_key,
                            k,
                            server_verf_key,
                            dec_mode,
                            &domain,
                            metric_tags,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                let mut guarded_meta_store = meta_store.write().await;
                match tmp {
                    Ok((payload, sig, extra_data)) => {
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store
                            .update(&req_id, Ok((payload, sig, extra_data)))
                            .inspect_err(|_| {
                                metrics::METRICS.increment_error_counter(
                                    OP_USER_DECRYPT_REQUEST,
                                    ERR_WITH_META_STORAGE,
                                );
                            });
                    }
                    Result::Err(e) => {
                        metrics::METRICS.increment_error_counter(
                            OP_USER_DECRYPT_REQUEST,
                            ERR_USER_DECRYPTION_FAILED,
                        );
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store
                            .update(&req_id, Err(format!("Failed decryption: {e}")));
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<UserDecryptionResponse>, Status> {
        let request_id =
            parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::UserDecResponse)?;

        // Retrieve the UserDecryptMetaStore object
        let status = {
            let guarded_meta_store = self.user_decrypt_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (payload, external_signature, extra_data) =
            handle_res_mapping(status, &request_id, "UserDecryption").await?;

        let sig_payload_vec = ok_or_tonic_abort(
            bc2wrap::serialize(&payload),
            format!("Could not convert payload to bytes {payload:?}"),
        )?;

        let sig = ok_or_tonic_abort(
            self.base_kms.sign(&DSEP_USER_DECRYPTION, &sig_payload_vec),
            format!("Could not sign payload {payload:?}"),
        )?;
        Ok(Response::new(UserDecryptionResponse {
            signature: sig.sig.to_vec(),
            external_signature,
            payload: Some(payload),
            extra_data,
        }))
    }
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
        runtime::session::ParameterHandles, small_execution::prss::PRSSSetup,
        tfhe_internals::utils::expanded_encrypt,
    };

    use crate::{
        consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM},
        cryptography::internal_crypto_types::{
            gen_sig_keys, Encryption, EncryptionScheme, EncryptionSchemeType,
        },
        dummy_domain,
        engine::{
            base::{compute_info_standard_keygen, DSEP_PUBDATA_KEY},
            threshold::service::session::SessionPreparerManager,
        },
        vault::storage::ram,
    };

    use super::*;

    struct DummyNoiseFloodPartialDecryptor;

    #[tonic::async_trait]
    impl NoiseFloodPartialDecryptor for DummyNoiseFloodPartialDecryptor {
        type Prep = SmallOfflineNoiseFloodSession<
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            threshold_fhe::execution::runtime::session::SmallSession<ResiduePolyF4Z128>,
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
            session_preparer_getter: SessionPreparerGetter,
        ) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            Self::init_test(base_kms, pub_storage, priv_storage, session_preparer_getter).await
        }
    }

    fn make_dummy_enc_pk(rng: &mut AesRng) -> Vec<u8> {
        let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, rng);
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
        Vec<u8>,
        RealUserDecryptor<ram::RamStorage, ram::RamStorage, DummyNoiseFloodPartialDecryptor>,
    ) {
        let (_pk, sk) = gen_sig_keys(rng);
        let param = TEST_PARAM;
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk.clone()).unwrap();
        let session_preparer_manager = SessionPreparerManager::new_test_session();

        let prss_setup_z128 = Arc::new(RwLock::new(Some(PRSSSetup::new_testing_prss(
            vec![],
            vec![],
        ))));
        let prss_setup_z64 = Arc::new(RwLock::new(Some(PRSSSetup::new_testing_prss(
            vec![],
            vec![],
        ))));

        let session_preparer = SessionPreparer::new_test_session(
            base_kms.new_instance().await,
            prss_setup_z128,
            prss_setup_z64,
        );
        session_preparer_manager
            .insert(*DEFAULT_MPC_CONTEXT, session_preparer)
            .await;
        let user_decryptor = RealUserDecryptor::init_test_dummy_decryptor(
            base_kms,
            session_preparer_manager.make_getter(),
        )
        .await;

        let key_id = RequestId::new_random(rng);

        // make a dummy private keyset
        let (threshold_fhe_keys, fhe_key_set) = ThresholdFheKeys::init_dummy(param, rng);

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

        let dummy_meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
        {
            // initialize the dummy meta store
            let meta_store = dummy_meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&key_id).unwrap();
        }
        user_decryptor
            .crypto_storage
            .write_threshold_keys_with_meta_store(
                &key_id,
                threshold_fhe_keys,
                fhe_key_set,
                info,
                dummy_meta_store,
            )
            .await;

        {
            // check existance
            let _guard = user_decryptor
                .crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                .await
                .unwrap();
        }

        (key_id, ct_buf, user_decryptor)
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1123);
        let (key_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;

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
                epoch_id: None,
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
                epoch_id: None,
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
                epoch_id: None,
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
                epoch_id: None,
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
                epoch_id: None,
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
        let (key_id, ct_buf, mut user_decryptor) = setup_user_decryptor(&mut rng).await;
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
            epoch_id: None,
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
        let (_key_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let domain = dummy_domain();

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
            epoch_id: None,
        });
        assert_eq!(
            user_decryptor
                .user_decrypt(request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );

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
        let (key_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
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
            epoch_id: None,
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
        let (key_id, ct_buf, user_decryptor) = setup_user_decryptor(&mut rng).await;
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
            epoch_id: None,
        });
        user_decryptor.user_decrypt(request).await.unwrap();
        user_decryptor
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap();
    }
}
