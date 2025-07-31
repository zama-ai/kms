// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use anyhow::anyhow;
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{
        self, CiphertextFormat, Empty, PublicDecryptionRequest, PublicDecryptionResponse,
        PublicDecryptionResponsePayload, TypedPlaintext,
    },
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        ERR_PUBLIC_DECRYPTION_FAILED, OP_PUBLIC_DECRYPT_INNER, OP_PUBLIC_DECRYPT_REQUEST,
        TAG_KEY_ID, TAG_PARTY_ID, TAG_PUBLIC_DECRYPTION_KIND, TAG_TFHE_TYPE,
    },
};
use tfhe::FheTypes;
use threshold_fhe::{
    execution::endpoints::decryption::{
        decrypt_using_noiseflooding, secure_decrypt_using_bitdec, DecryptionMode,
        NoiseFloodSmallSession,
    },
    session_id::SessionId,
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    engine::{
        base::{
            compute_external_pt_signature, deserialize_to_low_level, BaseKmsStruct,
            PubDecCallValues,
        },
        threshold::traits::PublicDecryptor,
        traits::BaseKms,
        validation::{validate_public_decrypt_req, validate_request_id, DSEP_PUBLIC_DECRYPTION},
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

pub struct RealPublicDecryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub pub_dec_meta_store: Arc<RwLock<MetaStore<PubDecCallValues>>>,
    pub session_preparer: Arc<SessionPreparer>,
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub decryption_mode: DecryptionMode,
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static>
    RealPublicDecryptor<PubS, PrivS>
{
    /// Helper method for decryption which carries out the actual threshold decryption using noise
    /// flooding or bit-decomposition
    async fn inner_decrypt<T>(
        session_id: SessionId,
        session_prep: Arc<SessionPreparer>,
        ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
        dec_mode: DecryptionMode,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    {
        tracing::info!(
            "{:?} started inner_decrypt with mode {:?}",
            session_prep.own_identity(),
            dec_mode
        );

        let keys = fhe_keys;
        let low_level_ct =
            deserialize_to_low_level(fhe_type, ct_format, ct, &keys.decompression_key)?;

        let dec = match dec_mode {
            DecryptionMode::NoiseFloodSmall => {
                let session = tonic_handle_potential_err(
                    session_prep
                        .prepare_ddec_data_from_sessionid_z128(session_id)
                        .await,
                    "Could not prepare ddec data for noiseflood decryption".to_string(),
                )?;
                let mut noiseflood_session = NoiseFloodSmallSession::new(session);

                decrypt_using_noiseflooding(
                    &mut noiseflood_session,
                    &keys.integer_server_key,
                    keys.sns_key
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing sns key"))?,
                    low_level_ct,
                    &keys.private_keys,
                    dec_mode,
                    session_prep.own_identity()?,
                )
                .await
            }
            DecryptionMode::BitDecSmall => {
                let mut session = tonic_handle_potential_err(
                    session_prep
                        .prepare_ddec_data_from_sessionid_z64(session_id)
                        .await,
                    "Could not prepare ddec data for bitdec decryption".to_string(),
                )?;

                secure_decrypt_using_bitdec(
                    &mut session,
                    &low_level_ct.try_get_small_ct()?,
                    &keys.private_keys,
                    keys.get_key_switching_key()?,
                    dec_mode,
                    session_prep.own_identity()?,
                )
                .await
            }
            mode => {
                return Err(anyhow_error_and_log(format!(
                    "Unsupported Decryption Mode: {mode}"
                )));
            }
        };

        let raw_decryption = match dec {
            Ok((partial_dec, time)) => {
                let raw_decryption = match partial_dec.get(&session_id.to_string()) {
                    Some(raw_decryption) => *raw_decryption,
                    None => {
                        return Err(anyhow!(
                            "Decryption with session ID {} could not be retrived",
                            session_id.to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Decryption completed on {:?}. Inner thread took {:?} ms",
                    session_prep.own_identity(),
                    time.as_millis()
                );
                raw_decryption
            }
            Err(e) => return Err(anyhow!("Failed decryption with noiseflooding: {e}")),
        };
        Ok(raw_decryption)
    }
}

#[tonic::async_trait]
impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static> PublicDecryptor
    for RealPublicDecryptor<PubS, PrivS>
{
    #[tracing::instrument(skip(self, request), fields(
        party_id = ?self.session_preparer.my_id,
        operation = "decrypt"
    ))]
    async fn public_decrypt(
        &self,
        request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        // Start timing and counting before any operations
        let mut timer = metrics::METRICS
            .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        let permit = self
            .rate_limiter
            .start_pub_decrypt()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let inner = request.into_inner();
        tracing::info!(
            request_id = ?inner.request_id,
            "Received new decryption request"
        );

        let (ciphertexts, key_id, req_id, eip712_domain) = tonic_handle_potential_err(
            validate_public_decrypt_req(&inner),
            format!("Failed to validate decrypt request {inner:?}"),
        )
        .map_err(|e| {
            tracing::error!(
                error = ?e,
                request_id = ?inner.request_id,
                "Failed to validate decrypt request"
            );
            let _ = metrics::METRICS
                .increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_PUBLIC_DECRYPTION_FAILED);
            e
        })?;

        // CRITICAL FIX: Release permit immediately after validation
        // Don't hold permits during expensive multi-party coordination
        drop(permit);
        tracing::debug!(
            request_id = ?req_id,
            "Rate limiter permit released after validation - proceeding with async coordination"
        );

        if let Some(b) = timer.as_mut() {
            //We log but we don't want to return early because timer failed
            let _ = b
                .tags([(TAG_KEY_ID, key_id.as_str())])
                .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
        }
        tracing::debug!(
            request_id = ?req_id,
            key_id = ?key_id,
            ciphertexts_count = ciphertexts.len(),
            "Starting decryption process"
        );

        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        // Optimize lock hold time by minimizing operations under lock
        let (lock_acquired_time, total_lock_time) = {
            let lock_start = std::time::Instant::now();
            let mut guarded_meta_store = self.pub_dec_meta_store.write().await;
            let lock_acquired_time = lock_start.elapsed();
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert decryption into meta store".to_string(),
            )?;
            let total_lock_time = lock_start.elapsed();
            (lock_acquired_time, total_lock_time)
        };
        // Log after lock is released
        tracing::info!(
            "MetaStore INITIAL insert - req_id={}, key_id={}, party_id={}, ciphertexts_count={}, lock_acquired_in={:?}, total_lock_held={:?}",
            req_id, key_id, self.session_preparer.my_id, ciphertexts.len(), lock_acquired_time, total_lock_time
        );

        tonic_handle_potential_err(
            self.crypto_storage
                .refresh_threshold_fhe_keys(&key_id)
                .await,
            format!("Cannot find threshold keys with key ID {key_id}"),
        )?;

        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();

        let mut dec_tasks = Vec::new();
        let dec_mode = self.decryption_mode;

        // iterate over ciphertexts in this batch and decrypt each in their own session (so that it happens in parallel)
        for (ctr, typed_ciphertext) in ciphertexts.into_iter().enumerate() {
            let inner_timer = metrics::METRICS
                .time_operation(OP_PUBLIC_DECRYPT_INNER)
                .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
                .and_then(|b| {
                    b.tags([
                        (TAG_PARTY_ID, self.session_preparer.my_id.to_string()),
                        (TAG_KEY_ID, key_id.as_str()),
                        (
                            TAG_PUBLIC_DECRYPTION_KIND,
                            dec_mode.as_str_name().to_string(),
                        ),
                    ])
                    .map_err(|e| {
                        tracing::warn!("Failed to a tag in party_id, key_id or request_id : {}", e)
                    })
                })
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
                .ok();
            let internal_sid = tonic_handle_potential_err(
                req_id.derive_session_id_with_counter(ctr as u64),
                "failed to derive session ID from counter".to_string(),
            )?;

            let hex_req_id = hex::encode(req_id.as_bytes());
            let decimal_req_id: u128 = req_id.try_into().unwrap_or(0);
            tracing::info!(
                request_id = hex_req_id,
                request_id_decimal = decimal_req_id,
                "Public Decrypt Request: Decrypting ciphertext #{ctr} with internal session ID: {internal_sid}. Handle: {}",
                hex::encode(&typed_ciphertext.external_handle)
            );

            let crypto_storage = self.crypto_storage.clone();
            let prep = Arc::clone(&self.session_preparer);

            // we do not need to hold the handle,
            // the result of the computation is tracked by the pub_dec_meta_store
            let decrypt_future = || async move {
                let fhe_type_string = typed_ciphertext.fhe_type_string();
                let fhe_type = if let Ok(f) = typed_ciphertext.fhe_type() {
                    f
                } else {
                    return Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed due to wrong fhe type: {}",
                        typed_ciphertext.fhe_type
                    )));
                };
                // Capture the inner_timer inside the decryption tasks, such that when the task
                // exits, the timer is dropped and thus exported
                let mut inner_timer = inner_timer;
                inner_timer
                    .as_mut()
                    .map(|b| b.tag(TAG_TFHE_TYPE, fhe_type_string));

                let ciphertext = &typed_ciphertext.ciphertext;
                let ct_format = typed_ciphertext.ciphertext_format();
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await?;

                let res_plaintext = match fhe_type {
                    FheTypes::Uint2048 => Self::inner_decrypt::<tfhe::integer::bigint::U2048>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u2048),
                    FheTypes::Uint1024 => Self::inner_decrypt::<tfhe::integer::bigint::U1024>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u1024),
                    FheTypes::Uint512 => Self::inner_decrypt::<tfhe::integer::bigint::U512>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u512),
                    FheTypes::Uint256 => Self::inner_decrypt::<tfhe::integer::U256>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u256),
                    FheTypes::Uint160 => Self::inner_decrypt::<tfhe::integer::U256>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u160),
                    FheTypes::Uint128 => Self::inner_decrypt::<u128>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(|x| TypedPlaintext::new(x, fhe_type)),
                    FheTypes::Uint80 => Self::inner_decrypt::<u128>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(TypedPlaintext::from_u80),
                    FheTypes::Bool
                    | FheTypes::Uint4
                    | FheTypes::Uint8
                    | FheTypes::Uint16
                    | FheTypes::Uint32
                    | FheTypes::Uint64 => Self::inner_decrypt::<u64>(
                        internal_sid,
                        prep,
                        ciphertext,
                        fhe_type,
                        ct_format,
                        fhe_keys_rlock,
                        dec_mode,
                    )
                    .await
                    .map(|x| TypedPlaintext::new(x as u128, fhe_type)),
                    unsupported_fhe_type => {
                        anyhow::bail!("Unsupported fhe type {:?}", unsupported_fhe_type);
                    }
                };
                match res_plaintext {
                    Ok(plaintext) => Ok((ctr, plaintext)),
                    Result::Err(e) => Err(anyhow_error_and_log(format!(
                        "Threshold decryption failed:{e}"
                    ))),
                }
            };
            dec_tasks.push(
                self.tracker
                    .spawn(decrypt_future().instrument(tracing::Span::current())),
            );
        }

        // collect decryption results in async mgmt task so we can return from this call without waiting for the decryption(s) to finish
        let meta_store = Arc::clone(&self.pub_dec_meta_store);
        let sigkey = Arc::clone(&self.base_kms.sig_key);
        let party_id = self.session_preparer.my_id;
        let dec_sig_future = || async move {
            // Move the timer to the management task's context, so as to drop
            // it when decryptions are available
            let _timer = timer;
            // NOTE: Rate limiter permit was already released after validation
            let mut decs = HashMap::new();
            let error_msg: Option<String> = None;

            // Collect all results first, without holding any locks
            while let Some(resp) = dec_tasks.pop() {
                match resp.await {
                    Ok(Ok((idx, plaintext))) => {
                        decs.insert(idx, plaintext);
                    }
                    Ok(Err(e)) => {
                        let msg = format!("Failed decryption with err: {e:?}");
                        tracing::error!(msg);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(&req_id, Err(msg));
                        // exit mgmt task early in case of error
                        return;
                    }
                    Err(e) => {
                        let msg = format!("Failed decryption with JoinError: {e:?}");
                        tracing::error!(msg);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(&req_id, Err(msg));
                        // exit mgmt task early in case of error
                        return;
                    }
                }
            }

            // Handle error case with single lock acquisition
            if let Some(msg) = error_msg {
                let (lock_acquired_time, total_lock_time) = {
                    let lock_start = std::time::Instant::now();
                    let mut guarded_meta_store = meta_store.write().await;
                    let lock_acquired_time = lock_start.elapsed();
                    let _ = guarded_meta_store.update(&req_id, Err(msg));
                    let total_lock_time = lock_start.elapsed();
                    (lock_acquired_time, total_lock_time)
                };
                // Log after lock is released
                tracing::warn!(
                    "MetaStore ERROR update - req_id={}, lock_acquired_in={:?}, total_lock_held={:?}",
                    req_id, lock_acquired_time, total_lock_time
                );
                return;
            }

            // Prepare success data outside of lock
            let pts: Vec<_> = decs
                .keys()
                .sorted()
                .map(|idx| decs.get(idx).unwrap().clone()) // unwrap is fine here, since we iterate over all keys.
                .collect();

            // Compute expensive signature OUTSIDE the lock
            let external_sig = if let Some(domain) = eip712_domain {
                compute_external_pt_signature(&sigkey, ext_handles_bytes, &pts, domain)
            } else {
                tracing::warn!("Skipping external signature computation due to missing domain");
                vec![]
            };

            // Single success update with minimal lock hold time
            let success_result = Ok((req_id, pts.clone(), external_sig));
            let (lock_acquired_time, total_lock_time) = {
                let lock_start = std::time::Instant::now();
                let mut guarded_meta_store = meta_store.write().await;
                let lock_acquired_time = lock_start.elapsed();
                let _ = guarded_meta_store.update(&req_id, success_result);
                let total_lock_time = lock_start.elapsed();
                (lock_acquired_time, total_lock_time)
            };
            // Log after lock is released
            tracing::info!(
                "MetaStore SUCCESS update - req_id={}, key_id={}, party_id={}, ciphertexts_count={}, lock_acquired_in={:?}, total_lock_held={:?}",
                req_id, key_id, party_id, pts.len(), lock_acquired_time, total_lock_time
            );
        };
        self.tracker
            .spawn(dec_sig_future().instrument(tracing::Span::current()));

        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, Status> {
        let request_id = request.into_inner().into();
        validate_request_id(&request_id)?;
        let status = {
            let guarded_meta_store = self.pub_dec_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (retrieved_req_id, plaintexts, external_signature) =
            handle_res_mapping(status, &request_id, "Decryption").await?;

        if request_id != retrieved_req_id {
            return Err(Status::not_found(format!(
                "Request ID mismatch: expected {request_id}, got {retrieved_req_id}",
            )));
        }

        let server_verf_key = self.base_kms.get_serialized_verf_key();
        let sig_payload = PublicDecryptionResponsePayload {
            plaintexts,
            verification_key: server_verf_key,
            #[allow(deprecated)] // we have to allow to fill the struct
            digest: vec![],
            external_signature: Some(external_signature),
            request_id: Some(retrieved_req_id.into()),
        };

        let sig_payload_vec = tonic_handle_potential_err(
            bc2wrap::serialize(&sig_payload),
            format!("Could not convert payload to bytes {sig_payload:?}"),
        )?;

        let sig = tonic_handle_potential_err(
            self.base_kms
                .sign(&DSEP_PUBLIC_DECRYPTION, &sig_payload_vec),
            format!("Could not sign payload {sig_payload:?}"),
        )?;
        Ok(Response::new(PublicDecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload),
        }))
    }
}
