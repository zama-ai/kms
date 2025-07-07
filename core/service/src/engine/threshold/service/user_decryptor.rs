// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use anyhow::anyhow;
use kms_grpc::{
    kms::v1::{
        self, Empty, TypedCiphertext, TypedPlaintext, TypedSigncryptedCiphertext,
        UserDecryptionRequest, UserDecryptionResponse, UserDecryptionResponsePayload,
    },
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        ERR_RATE_LIMIT_EXCEEDED, OP_USER_DECRYPT_INNER, OP_USER_DECRYPT_REQUEST, TAG_KEY_ID,
        TAG_PARTY_ID, TAG_PUBLIC_DECRYPTION_KIND, TAG_TFHE_TYPE,
    },
};
use rand::{CryptoRng, RngCore};
use threshold_fhe::{
    algebra::galois_rings::common::pack_residue_poly,
    execution::{
        endpoints::decryption::{
            partial_decrypt_using_noiseflooding, secure_partial_decrypt_using_bitdec,
            DecryptionMode, NoiseFloodSmallSession,
        },
        runtime::session::ParameterHandles,
    },
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    cryptography::{
        internal_crypto_types::{PrivateSigKey, UnifiedPublicEncKey},
        signcryption::{signcrypt, SigncryptionPayload},
    },
    engine::{
        base::{
            compute_external_user_decrypt_signature, deserialize_to_low_level, BaseKmsStruct,
            UserDecryptCallValues,
        },
        threshold::traits::UserDecryptor,
        traits::BaseKms,
        validation::{validate_user_decrypt_req, DSEP_USER_DECRYPTION},
    },
    tonic_handle_potential_err,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};

// === Current Module Imports ===
use super::{session::SessionPreparer, ThresholdFheKeys};

pub struct RealUserDecryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    pub user_decrypt_meta_store: Arc<RwLock<MetaStore<UserDecryptCallValues>>>,
    pub session_preparer: Arc<SessionPreparer>,
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub decryption_mode: DecryptionMode,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealUserDecryptor<PubS, PrivS, BackS>
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
        rng: &mut (impl CryptoRng + RngCore),
        typed_ciphertexts: &[TypedCiphertext],
        link: Vec<u8>,
        client_enc_key: &UnifiedPublicEncKey,
        client_address: &alloy_primitives::Address,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
        server_verf_key: Vec<u8>,
        dec_mode: DecryptionMode,
        domain: &alloy_sol_types::Eip712Domain,
        metric_tags: Vec<(&'static str, String)>,
    ) -> anyhow::Result<(UserDecryptionResponsePayload, Vec<u8>)> {
        let keys = fhe_keys;

        let mut all_signcrypted_cts = vec![];

        // TODO: Each iteration of this loop should probably happen
        // inside its own tokio task
        for (ctr, typed_ciphertext) in typed_ciphertexts.iter().enumerate() {
            // Create and start a the timer, it'll be dropped and thus
            // exported at the end of the iteration
            let mut inner_timer = metrics::METRICS
                .time_operation(OP_USER_DECRYPT_INNER)
                .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
                .and_then(|b| {
                    b.tags(metric_tags.clone()).map_err(|e| {
                        tracing::warn!("Failed to a tag in party_id, key_id or request_id : {}", e)
                    })
                })
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
                .ok();
            let fhe_type = typed_ciphertext.fhe_type()?;
            let fhe_type_str = typed_ciphertext.fhe_type_string();
            inner_timer
                .as_mut()
                .map(|b| b.tag(TAG_TFHE_TYPE, fhe_type_str));
            let ct_format = typed_ciphertext.ciphertext_format();
            let ct = &typed_ciphertext.ciphertext;
            let external_handle = typed_ciphertext.external_handle.clone();
            let session_id = req_id.derive_session_id_with_counter(ctr as u64)?;

            let hex_req_id = hex::encode(req_id.as_bytes());
            let decimal_req_id: u128 = (*req_id).try_into().unwrap_or(0);
            tracing::info!(
                request_id = hex_req_id,
                request_id_decimal = decimal_req_id,
                "User Decrypt Request: Decrypting ciphertext #{ctr} with internal session ID: {session_id}. Handle: {}",
                hex::encode(&typed_ciphertext.external_handle)
            );

            let low_level_ct =
                deserialize_to_low_level(fhe_type, ct_format, ct, &keys.decompression_key)?;

            let pdec: Result<(Vec<u8>, u32, std::time::Duration), anyhow::Error> = match dec_mode {
                DecryptionMode::NoiseFloodSmall => {
                    let session = tonic_handle_potential_err(
                        session_prep
                            .prepare_ddec_data_from_sessionid_z128(session_id)
                            .await,
                        "Could not prepare ddec data for noiseflood decryption".to_string(),
                    )?;
                    let session_parameters = session.to_parameters();
                    let mut noiseflood_session = NoiseFloodSmallSession::new(session);

                    let pdec = partial_decrypt_using_noiseflooding(
                        session_parameters,
                        &mut noiseflood_session,
                        &keys.integer_server_key,
                        keys.sns_key
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("missing sns key"))?,
                        low_level_ct,
                        &keys.private_keys,
                        DecryptionMode::NoiseFloodSmall,
                    )
                    .await;
                    session_prep.destroy_session(session_id).await;

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
                                        "User decryption with session ID {} could not be retrived",
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
                    let mut session = tonic_handle_potential_err(
                        session_prep
                            .prepare_ddec_data_from_sessionid_z64(session_id)
                            .await,
                        "Could not prepare ddec data for bitdec decryption".to_string(),
                    )?;

                    let pdec = secure_partial_decrypt_using_bitdec(
                        &mut session,
                        &low_level_ct.try_get_small_ct()?,
                        &keys.private_keys,
                        &keys.integer_server_key.as_ref().key_switching_key,
                        DecryptionMode::BitDecSmall,
                    )
                    .await;
                    session_prep.destroy_session(session_id).await;

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
                                        "User decryption with session ID {} could not be retrived",
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
                    let enc_res = signcrypt(
                        rng,
                        &DSEP_USER_DECRYPTION,
                        &bc2wrap::serialize(&signcryption_msg)?,
                        client_enc_key,
                        client_address,
                        &sig_key,
                    )?;
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
            party_id: session_prep.my_id as u32,
            degree: session_prep.threshold as u32,
        };

        let external_signature =
            compute_external_user_decrypt_signature(&sig_key, &payload, domain, client_enc_key)?;
        Ok((payload, external_signature))
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > UserDecryptor for RealUserDecryptor<PubS, PrivS, BackS>
{
    async fn user_decrypt(
        &self,
        request: Request<UserDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        // Start timing and counting before any operations
        let mut timer = metrics::METRICS
            .time_operation(OP_USER_DECRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_USER_DECRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        let permit = self.rate_limiter.start_user_decrypt().await.map_err(|e| {
            let _ = metrics::METRICS
                .increment_error_counter(OP_USER_DECRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED);
            Status::resource_exhausted(e.to_string())
        })?;

        let inner = request.into_inner();
        tracing::info!(
            "Party {:?} received a new user decryption request with request_id {:?}",
            self.session_preparer.own_identity(),
            inner.request_id
        );
        let (typed_ciphertexts, link, client_enc_key, client_address, key_id, req_id, domain) =
            tonic_handle_potential_err(
                validate_user_decrypt_req(&inner),
                format!("Failed to validate user decryption request: {inner:?}"),
            )?;

        if let Some(b) = timer.as_mut() {
            //We log but we don't want to return early because timer failed
            let _ = b
                .tags([(TAG_KEY_ID, key_id.as_str())])
                .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
        }

        let meta_store = Arc::clone(&self.user_decrypt_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let mut rng = self.base_kms.new_rng().await;
        let sig_key = Arc::clone(&self.base_kms.sig_key);

        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        {
            let mut guarded_meta_store = self.user_decrypt_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert user decryption request".to_string(),
            )?;
        }

        tonic_handle_potential_err(
            crypto_storage.refresh_threshold_fhe_keys(&key_id).await,
            format!("Cannot find threshold keys with key ID {key_id}"),
        )?;

        let prep = Arc::clone(&self.session_preparer);
        let dec_mode = self.decryption_mode;

        let metric_tags = vec![
            (TAG_PARTY_ID, prep.my_id.to_string()),
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
                            &mut rng,
                            &typed_ciphertexts,
                            link.clone(),
                            &client_enc_key,
                            &client_address,
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
                    Ok((payload, sig)) => {
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(&req_id, Ok((payload, sig)));
                    }
                    Result::Err(e) => {
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
        let request_id: RequestId = request.into_inner().into();
        if !request_id.is_valid() {
            tracing::warn!(
                "The value {} is not a valid request ID!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("The value {request_id} is not a valid request ID!"),
            ));
        }

        // Retrieve the UserDecryptMetaStore object
        let status = {
            let guarded_meta_store = self.user_decrypt_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (payload, external_signature) =
            handle_res_mapping(status, &request_id, "UserDecryption").await?;

        let sig_payload_vec = tonic_handle_potential_err(
            bc2wrap::serialize(&payload),
            format!("Could not convert payload to bytes {payload:?}"),
        )?;

        let sig = tonic_handle_potential_err(
            self.base_kms.sign(&DSEP_USER_DECRYPTION, &sig_payload_vec),
            format!("Could not sign payload {payload:?}"),
        )?;
        Ok(Response::new(UserDecryptionResponse {
            signature: sig.sig.to_vec(),
            external_signature,
            payload: Some(payload),
        }))
    }
}
