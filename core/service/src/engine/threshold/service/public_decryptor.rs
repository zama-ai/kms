// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

// === External Crates ===
use alloy_primitives::U256;
use anyhow::anyhow;
use itertools::Itertools;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{
        self, CiphertextFormat, Empty, PublicDecryptionRequest, PublicDecryptionResponse,
        PublicDecryptionResponsePayload, TypedPlaintext,
    },
    utils::tonic_result::BoxedStatus,
    IdentifierError, RequestId,
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
    algebra::{
        base_ring::Z128,
        galois_rings::{common::ResiduePoly, degree_4::ResiduePolyF4Z128},
        structure_traits::{ErrorCorrect, Invert, Ring, Solve},
    },
    execution::{
        endpoints::decryption::{
            decrypt_using_noiseflooding, secure_decrypt_using_bitdec, DecryptionMode,
            LowLevelCiphertext, OfflineNoiseFloodSession, SecureOnlineNoiseFloodDecryption,
            SmallOfflineNoiseFloodSession,
        },
        runtime::sessions::small_session::SmallSession,
        tfhe_internals::private_keysets::PrivateKeySet,
    },
    session_id::SessionId,
    thread_handles::spawn_compute_bound,
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    consts::{DEFAULT_MPC_CONTEXT, PRSS_INIT_REQ_ID},
    cryptography::internal_crypto_types::LegacySerialization,
    engine::{
        base::{
            compute_external_pt_signature, deserialize_to_low_level, BaseKmsStruct,
            PubDecCallValues,
        },
        threshold::{service::session::ImmutableSessionMaker, traits::PublicDecryptor},
        traits::BaseKms,
        update_system_metrics,
        validation::{
            parse_proto_request_id, validate_public_decrypt_req, RequestIdParsingErr,
            DSEP_PUBLIC_DECRYPTION,
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
use super::ThresholdFheKeys;

#[tonic::async_trait]
pub trait NoiseFloodDecryptor: Send + Sync {
    type Prep: OfflineNoiseFloodSession<{ ResiduePolyF4Z128::EXTENSION_DEGREE }> + Send;

    async fn decrypt<T>(
        noiseflood_session: &mut Self::Prep,
        server_key: Arc<tfhe::integer::ServerKey>,
        ck: Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>,
        ct: LowLevelCiphertext,
        secret_key_share: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    ) -> anyhow::Result<(HashMap<String, T>, Duration)>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>: ErrorCorrect + Invert + Solve;
}

pub struct SecureNoiseFloodDecryptor;

#[tonic::async_trait]
impl NoiseFloodDecryptor for SecureNoiseFloodDecryptor {
    type Prep = SmallOfflineNoiseFloodSession<
        { ResiduePolyF4Z128::EXTENSION_DEGREE },
        threshold_fhe::execution::runtime::sessions::small_session::SmallSession<ResiduePolyF4Z128>,
    >;

    async fn decrypt<T>(
        noiseflood_session: &mut Self::Prep,
        server_key: Arc<tfhe::integer::ServerKey>,
        ck: Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>,
        ct: LowLevelCiphertext,
        secret_key_share: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
    ) -> anyhow::Result<(HashMap<String, T>, Duration)>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>: ErrorCorrect + Invert + Solve,
    {
        decrypt_using_noiseflooding::<
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            Self::Prep,
            SecureOnlineNoiseFloodDecryption,
            T,
        >(noiseflood_session, server_key, ck, ct, secret_key_share)
        .await
    }
}

pub struct RealPublicDecryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    Dec: NoiseFloodDecryptor<
            Prep = SmallOfflineNoiseFloodSession<
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                SmallSession<ResiduePolyF4Z128>,
            >,
        > + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub pub_dec_meta_store: Arc<RwLock<MetaStore<PubDecCallValues>>>,
    pub(crate) session_maker: ImmutableSessionMaker,
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub decryption_mode: DecryptionMode,
    pub(crate) _dec: PhantomData<Dec>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        Dec: NoiseFloodDecryptor<
                Prep = SmallOfflineNoiseFloodSession<
                    { ResiduePolyF4Z128::EXTENSION_DEGREE },
                    SmallSession<ResiduePolyF4Z128>,
                >,
            > + 'static,
    > RealPublicDecryptor<PubS, PrivS, Dec>
{
    /// Helper method for decryption which carries out the actual threshold decryption using noise
    /// flooding or bit-decomposition
    #[allow(clippy::too_many_arguments)]
    async fn inner_decrypt<T>(
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
        session_maker: ImmutableSessionMaker,
        ct: Vec<u8>,
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
        fhe_keys: OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>,
        dec_mode: DecryptionMode,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    {
        let my_identity = session_maker.my_identity(&context_id).await?;
        tracing::info!(
            "{:?} started inner_decrypt with mode {:?} with session ID {session_id} and context ID {context_id}",
            my_identity,
            dec_mode
        );

        let keys = fhe_keys;
        let decomp_key = keys.decompression_key.clone();
        let low_level_ct = spawn_compute_bound(move || {
            deserialize_to_low_level(fhe_type, ct_format, &ct, decomp_key.as_deref())
        })
        .await??;

        let my_role = session_maker.my_role(&context_id).await?;
        let dec = match dec_mode {
            DecryptionMode::NoiseFloodSmall => {
                let session = ok_or_tonic_abort(
                    session_maker
                        .make_small_async_session_z128(session_id, context_id, epoch_id)
                        .await,
                    "Could not prepare ddec data for noiseflood decryption".to_string(),
                )?;
                let mut noiseflood_session = SmallOfflineNoiseFloodSession::new(session);

                Dec::decrypt(
                    &mut noiseflood_session,
                    Arc::clone(&keys.integer_server_key),
                    keys.sns_key
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing sns key"))?
                        .clone(),
                    low_level_ct,
                    keys.private_keys.clone(),
                )
                .await
            }
            DecryptionMode::BitDecSmall => {
                let mut session = ok_or_tonic_abort(
                    session_maker
                        .make_small_async_session_z64(session_id, context_id, epoch_id)
                        .await,
                    "Could not prepare ddec data for bitdec decryption".to_string(),
                )?;

                secure_decrypt_using_bitdec(
                    &mut session,
                    &low_level_ct.try_get_small_ct()?,
                    &keys.private_keys,
                    keys.get_key_switching_key()?,
                    my_role,
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
                            "Public Decryption with session ID {} could not be retrived",
                            session_id.to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Public decryption in session {session_id} completed on {:?}. Inner thread took {:?} ms",
                    my_identity,
                    time.as_millis()
                );
                raw_decryption
            }
            Err(e) => return Err(anyhow!("Failed public decryption with noiseflooding: {e}")),
        };
        Ok(raw_decryption)
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        Dec: NoiseFloodDecryptor<
                Prep = SmallOfflineNoiseFloodSession<
                    { ResiduePolyF4Z128::EXTENSION_DEGREE },
                    SmallSession<ResiduePolyF4Z128>,
                >,
            > + 'static,
    > PublicDecryptor for RealPublicDecryptor<PubS, PrivS, Dec>
{
    #[tracing::instrument(skip(self, request), fields(
        request_id = ?request.get_ref().request_id,
        operation = "decrypt"
    ))]
    async fn public_decrypt(
        &self,
        request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        {
            // TODO should probably be called at regular intervals and setup with the KMS in kms_impl
            let meta_store = self.pub_dec_meta_store.read().await;
            update_system_metrics(
                &self.rate_limiter,
                &self.session_maker,
                None,
                Some(&meta_store),
            )
            .await;
        }
        let inner = Arc::new(request.into_inner());
        tracing::info!(
            request_id = ?inner.request_id,
            "Received new decryption request"
        );

        // TODO(zama-ai/kms-internal/issues/2758)
        // remove the default context when all of context is ready
        let context_id: ContextId = match &inner.context_id {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => *DEFAULT_MPC_CONTEXT,
        };
        let epoch_id: EpochId = match &inner.epoch_id {
            Some(c) => c
                .try_into()
                .map_err(|e: IdentifierError| tonic::Status::invalid_argument(e.to_string()))?,
            None => EpochId::try_from(PRSS_INIT_REQ_ID).unwrap(), // safe unwrap because PRSS_INIT_REQ_ID is valid
        };

        // Start timing and counting before any operations
        let my_role = self.session_maker.my_role(&context_id).await.map_err(|e| {
            tonic::Status::internal(format!(
                "Failed to get my role for context {context_id}: {e:?}"
            ))
        })?;
        let mut timer = metrics::METRICS
            .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
            .tag(TAG_PARTY_ID, my_role.to_string())
            .start();

        let (ciphertexts, key_id, req_id, eip712_domain) = {
            let inner_compute = Arc::clone(&inner);
            spawn_compute_bound(move || validate_public_decrypt_req(&inner_compute))
                .await
                .map_err(|_| {
                    BoxedStatus::from(tonic::Status::new(
                        tonic::Code::Internal,
                        "Error delegating validate_public_decrypt_req to rayon".to_string(),
                    ))
                })?
        }
        .inspect_err(|e| {
            tracing::error!(
                error = ?e,
                request_id = ?inner.request_id,
                "Failed to validate decrypt request"
            );
        })?;

        // Do some checks before we start modifying the database
        {
            let guarded_meta_store = self.pub_dec_meta_store.read().await;

            if guarded_meta_store.exists(&req_id) {
                return Err(Status::already_exists(format!(
                    "Public decryption request with ID {req_id} already exists"
                )));
            }
        }

        // Check for resource exhaustion once all the other checks are ok
        // because resource exhaustion can be recovered by sending the exact same request
        // but the errors above cannot be tried again.
        let permit = self.rate_limiter.start_pub_decrypt().await?;

        self.crypto_storage
            .refresh_threshold_fhe_keys(&key_id)
            .await
            .map_err(|e| {
                tracing::warn!(error=?e, key_id=?key_id, "Failed to refresh threshold FHE keys");
                Status::not_found(format!("Threshold FHE keys with key ID {key_id} not found"))
            })?;

        timer.tags([(TAG_KEY_ID, key_id.as_str())]);
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
            ok_or_tonic_abort(
                guarded_meta_store.insert(&req_id),
                "Could not insert decryption into meta store".to_string(),
            )?;
            let total_lock_time = lock_start.elapsed();
            (lock_acquired_time, total_lock_time)
        };

        // Log after lock is released
        tracing::info!(
            "MetaStore INITIAL insert - req_id={}, key_id={}, party={}, ciphertexts_count={}, lock_acquired_in={:?}, total_lock_held={:?}",
            req_id, key_id, my_role, ciphertexts.len(), lock_acquired_time, total_lock_time
        );

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
                .tags([
                    (TAG_PARTY_ID, my_role.to_string()),
                    (TAG_KEY_ID, key_id.as_str()),
                    (
                        TAG_PUBLIC_DECRYPTION_KIND,
                        dec_mode.as_str_name().to_string(),
                    ),
                ])
                .start();
            let internal_sid = ok_or_tonic_abort(
                req_id.derive_session_id_with_counter(ctr as u64),
                "failed to derive session ID from counter".to_string(),
            )?;

            let hex_req_id = hex::encode(req_id.as_bytes());
            let decimal_req_id = U256::try_from_be_slice(req_id.as_bytes())
                .unwrap_or(U256::ZERO)
                .to_string();
            tracing::info!(
                request_id = hex_req_id,
                request_id_decimal = decimal_req_id,
                "Public Decrypt Request: Decrypting ciphertext #{ctr} with internal session ID: {internal_sid}. Handle: {}",
                hex::encode(&typed_ciphertext.external_handle)
            );

            let crypto_storage = self.crypto_storage.clone();

            // we do not need to hold the handle,
            // the result of the computation is tracked by the pub_dec_meta_store
            let session_maker = self.session_maker.clone();
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
                inner_timer.tag(TAG_TFHE_TYPE, fhe_type_string);

                let ct_format = typed_ciphertext.ciphertext_format();
                let ciphertext = typed_ciphertext.ciphertext;
                let fhe_keys_rlock = crypto_storage
                    .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                    .await?;

                let res_plaintext = match fhe_type {
                    FheTypes::Uint2048 => Self::inner_decrypt::<tfhe::integer::bigint::U2048>(
                        internal_sid,
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                        context_id,
                        epoch_id,
                        session_maker,
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
                // We don't update the error counter here but rather in the signature task
                // so we only update it once even if there are multiple decryption task that fail
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
        let sigkey = self.base_kms.sig_key().map_err(|e| {
            tonic::Status::internal(format!(
                "Failed to get signing key for public decryption request {req_id}: {e:?}"
            ))
        })?;
        let dec_sig_future = move |_permit| async move {
            // Move the timer to the management task's context, so as to drop
            // it when decryptions are available
            let _timer = timer;
            // NOTE: _permit should be dropped at the end of this function
            let mut decs = HashMap::new();

            // Collect all results first, without holding any locks
            while let Some(resp) = dec_tasks.pop() {
                match resp.await {
                    Ok(Ok((idx, plaintext))) => {
                        decs.insert(idx, plaintext);
                    }
                    Ok(Err(e)) => {
                        let msg = format!("Failed decryption {req_id} with err: {e:?}");
                        tracing::error!(msg);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(&req_id, Err(msg));
                        // exit mgmt task early in case of error
                        return Err(());
                    }
                    Err(e) => {
                        let msg = format!("Failed decryption {req_id} with JoinError: {e:?}");
                        tracing::error!(msg);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(&req_id, Err(msg));
                        // exit mgmt task early in case of error
                        return Err(());
                    }
                }
            }

            // Prepare success data outside of lock
            let pts: Vec<_> = decs
                .keys()
                .sorted()
                .map(|idx| decs.get(idx).unwrap().clone()) // unwrap is fine here, since we iterate over all keys.
                .collect();

            // NOTE: extra data is not used at the moment
            let extra_data = vec![];

            // Compute expensive signature OUTSIDE the lock
            let external_sig = {
                let extra_data = extra_data.clone();
                let pts = pts.clone();
                spawn_compute_bound(move || {
                    compute_external_pt_signature(
                        &sigkey,
                        ext_handles_bytes,
                        &pts,
                        extra_data.clone(),
                        eip712_domain,
                    )
                })
                .await
            };
            let external_sig = match external_sig {
                Ok(Ok(sig)) => sig,
                Err(e) | Ok(Err(e)) => {
                    let msg = format!(
                        "Failed to compute external signature for decryption request {req_id}: {e:?}"
                    );
                    tracing::error!(msg);
                    // Update meta-store with the failure so clients are unblocked
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(&req_id, Err(msg));
                    return Err(());
                }
            };

            // Single success update with minimal lock hold time
            let pts_len = pts.len();
            let success_result = Ok((req_id, pts, external_sig, extra_data));

            let (lock_acquired_time, total_lock_time) = {
                let lock_start = std::time::Instant::now();
                let mut guarded_meta_store = meta_store.write().await;
                let lock_acquired_time = lock_start.elapsed();
                guarded_meta_store
                    .update(&req_id, success_result)
                    .map_err(|_| ())?;
                let total_lock_time = lock_start.elapsed();
                (lock_acquired_time, total_lock_time)
            };
            // Log after lock is released
            tracing::info!(
                "MetaStore SUCCESS update - req_id={}, key_id={}, party={}, ciphertexts_count={}, lock_acquired_in={:?}, total_lock_held={:?}",
                req_id, key_id, my_role, pts_len, lock_acquired_time, total_lock_time
            );
            Ok(())
        };
        // Increment the error counter if ever the task fails
        self.tracker.spawn(async move {
            let res = dec_sig_future(permit)
                .instrument(tracing::Span::current())
                .await;
            if res.is_err() {
                metrics::METRICS.increment_error_counter(
                    OP_PUBLIC_DECRYPT_REQUEST,
                    ERR_PUBLIC_DECRYPTION_FAILED,
                );
            }
        });
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, Status> {
        let request_id = parse_proto_request_id(
            &request.into_inner(),
            RequestIdParsingErr::PublicDecResponse,
        )?;
        let status = {
            let guarded_meta_store = self.pub_dec_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (retrieved_req_id, plaintexts, external_signature, extra_data) =
            handle_res_mapping(status, &request_id, "Decryption").await?;

        if request_id != retrieved_req_id {
            return Err(Status::not_found(format!(
                "Request ID mismatch: expected {request_id}, got {retrieved_req_id}",
            )));
        }

        let server_verf_key = self.base_kms.verf_key().to_legacy_bytes().map_err(|e| {
            Status::failed_precondition(format!(
                "Failed to serialize server verification key: {e:?}"
            ))
        })?;
        let sig_payload = PublicDecryptionResponsePayload {
            plaintexts,
            verification_key: server_verf_key,
            request_id: Some(retrieved_req_id.into()),
        };

        let sig_payload_vec = ok_or_tonic_abort(
            bc2wrap::serialize(&sig_payload),
            format!("Could not convert payload to bytes {sig_payload:?}"),
        )?;

        let sig = ok_or_tonic_abort(
            self.base_kms
                .sign(&DSEP_PUBLIC_DECRYPTION, &sig_payload_vec),
            format!("Could not sign payload {sig_payload:?}"),
        )?;
        Ok(Response::new(PublicDecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload),
            external_signature,
            extra_data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::TypedCiphertext,
        rpc_types::{alloy_to_protobuf_domain, KMSType},
    };
    use rand::SeedableRng;
    use threshold_fhe::execution::{
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::prss::PRSSSetup, tfhe_internals::utils::expanded_encrypt,
    };

    use crate::{
        consts::TEST_PARAM,
        cryptography::signatures::gen_sig_keys,
        dummy_domain,
        engine::{
            base::{compute_info_standard_keygen, DSEP_PUBDATA_KEY},
            threshold::service::session::SessionMaker,
        },
        vault::storage::ram,
    };

    use super::*;

    pub struct DummyNoisefloodDecryptor;

    #[tonic::async_trait]
    impl NoiseFloodDecryptor for DummyNoisefloodDecryptor {
        type Prep = SmallOfflineNoiseFloodSession<
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            threshold_fhe::execution::runtime::sessions::small_session::SmallSession<
                ResiduePolyF4Z128,
            >,
        >;

        async fn decrypt<T>(
            noiseflood_session: &mut Self::Prep,
            _server_key: Arc<tfhe::integer::ServerKey>,
            _ck: Arc<tfhe::integer::noise_squashing::NoiseSquashingKey>,
            _ct: LowLevelCiphertext,
            _secret_key_share: Arc<PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>,
        ) -> anyhow::Result<(HashMap<String, T>, Duration)>
        where
            T: tfhe::integer::block_decomposition::Recomposable
                + tfhe::core_crypto::commons::traits::CastFrom<u128>,
            ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>:
                ErrorCorrect + Invert + Solve,
        {
            let session = noiseflood_session.get_mut_base_session();
            let sid: u128 = session.session_id().into();
            let results = HashMap::from_iter([(format!("{sid}"), T::cast_from(0u128))]);
            let elapsed_time = Duration::from_secs(0);
            Ok((results, elapsed_time))
        }
    }

    impl<
            PubS: Storage + Send + Sync + 'static,
            PrivS: Storage + Send + Sync + 'static,
            Dec: NoiseFloodDecryptor<
                    Prep = SmallOfflineNoiseFloodSession<
                        { ResiduePolyF4Z128::EXTENSION_DEGREE },
                        SmallSession<ResiduePolyF4Z128>,
                    >,
                > + 'static,
        > RealPublicDecryptor<PubS, PrivS, Dec>
    {
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
                pub_dec_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                session_maker,
                tracker,
                rate_limiter,
                decryption_mode: DecryptionMode::NoiseFloodSmall,
                _dec: PhantomData,
            }
        }

        fn set_bucket_size(&mut self, bucket_size: usize) {
            let config = crate::util::rate_limiter::RateLimiterConfig {
                bucket_size,
                ..Default::default()
            };
            self.rate_limiter = RateLimiter::new(config);
        }
    }

    impl RealPublicDecryptor<ram::RamStorage, ram::RamStorage, DummyNoisefloodDecryptor> {
        async fn init_test_dummy_decryptor(
            base_kms: BaseKmsStruct,
            session_maker: ImmutableSessionMaker,
        ) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            Self::init_test(base_kms, pub_storage, priv_storage, session_maker).await
        }
    }

    async fn setup_public_decryptor(
        rng: &mut AesRng,
    ) -> (
        RequestId,
        Vec<u8>,
        RealPublicDecryptor<ram::RamStorage, ram::RamStorage, DummyNoisefloodDecryptor>,
    ) {
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk.clone()).unwrap();
        let param = TEST_PARAM;

        let prss_setup_z128 = Some(PRSSSetup::new_testing_prss(vec![], vec![]));
        let prss_setup_z64 = Some(PRSSSetup::new_testing_prss(vec![], vec![]));
        let session_maker = SessionMaker::four_party_dummy_session(
            prss_setup_z128,
            prss_setup_z64,
            base_kms.new_rng().await,
        );

        let public_decryptor = RealPublicDecryptor::init_test_dummy_decryptor(
            base_kms,
            session_maker.make_immutable(),
        )
        .await;

        let key_id = RequestId::new_random(rng);

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

        let dummy_meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
        {
            // initialize the dummy meta store
            let meta_store = dummy_meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&key_id).unwrap();
        }
        public_decryptor
            .crypto_storage
            .write_threshold_keys_with_dkg_meta_store(
                &key_id,
                threshold_fhe_keys,
                fhe_key_set,
                info,
                dummy_meta_store,
            )
            .await;

        {
            // check existance
            let _guard = public_decryptor
                .crypto_storage
                .read_guarded_threshold_fhe_keys_from_cache(&key_id)
                .await
                .unwrap();
        }

        (key_id, ct_buf, public_decryptor)
    }

    #[tokio::test]
    async fn test_resource_exhausted() {
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        let mut rng = AesRng::seed_from_u64(12);

        let (key_id, ct_buf, mut public_decryptor) = setup_public_decryptor(&mut rng).await;

        // Set bucket size to zero, so no operations are allowed
        public_decryptor.set_bucket_size(0);

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req_id = RequestId::new_random(&mut rng);
        let request = Request::new(PublicDecryptionRequest {
            request_id: Some(req_id.into()),
            ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf.clone(),
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                ciphertext_format: CiphertextFormat::SmallCompressed as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(domain),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
        });
        assert_eq!(
            public_decryptor
                .public_decrypt(request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );

        // finally reset the bucket size to a non-zero value
        public_decryptor.set_bucket_size(100);
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(12);
        let (key_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = PublicDecryptionRequest {
            request_id: Some(req_id.into()),
            ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf,
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                ciphertext_format: CiphertextFormat::SmallExpanded as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(domain),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
        };
        public_decryptor
            .public_decrypt(Request::new(request.clone()))
            .await
            .unwrap();
        assert_eq!(
            public_decryptor
                .public_decrypt(Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(1123);
        let (_key_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let bad_key_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = Request::new(PublicDecryptionRequest {
            request_id: Some(req_id.into()),
            ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf,
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                ciphertext_format: CiphertextFormat::SmallExpanded as i32,
            }],
            key_id: Some(bad_key_id.into()),
            domain: Some(domain),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
        });
        assert_eq!(
            public_decryptor
                .public_decrypt(request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );

        // try to get result for a non-existing request ID
        let another_req_id = RequestId::new_random(&mut rng);
        assert_eq!(
            public_decryptor
                .get_result(Request::new(another_req_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        {
            // Bad request ID
            let bad_req_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_request_id".to_string(),
            };
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let request = Request::new(PublicDecryptionRequest {
                request_id: Some(bad_req_id),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::SmallExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: Some(domain),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
            });
            assert_eq!(
                public_decryptor
                    .public_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // empty ciphertexts
            let req_id = RequestId::new_random(&mut rng);
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let request = Request::new(PublicDecryptionRequest {
                request_id: Some(req_id.into()),
                ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
            });
            assert_eq!(
                public_decryptor
                    .public_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // bad key ID
            let req_id = RequestId::new_random(&mut rng);
            let bad_key_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_request_id".to_string(),
            };
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let request = Request::new(PublicDecryptionRequest {
                request_id: Some(req_id.into()),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::SmallExpanded as i32,
                }],
                key_id: Some(bad_key_id),
                domain: Some(domain),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
            });
            assert_eq!(
                public_decryptor
                    .public_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // missing domain
            let req_id = RequestId::new_random(&mut rng);
            let request = Request::new(PublicDecryptionRequest {
                request_id: Some(req_id.into()),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf.clone(),
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::SmallExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: None,
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
            });
            assert_eq!(
                public_decryptor
                    .public_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // wrong domain
            let req_id = RequestId::new_random(&mut rng);
            let mut domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            domain.verifying_contract = "invalid_contract".to_string();
            let request = Request::new(PublicDecryptionRequest {
                request_id: Some(req_id.into()),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: ct_buf,
                    fhe_type: FheTypes::Uint8 as i32,
                    external_handle: vec![],
                    ciphertext_format: CiphertextFormat::SmallExpanded as i32,
                }],
                key_id: Some(key_id.into()),
                domain: Some(domain),
                extra_data: vec![],
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                epoch_id: None,
            });
            assert_eq!(
                public_decryptor
                    .public_decrypt(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // bad request ID while getting response
            assert_eq!(
                public_decryptor
                    .get_result(Request::new(kms_grpc::kms::v1::RequestId {
                        request_id: "invalid_request_id".to_string(),
                    },))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = Request::new(PublicDecryptionRequest {
            request_id: Some(req_id.into()),
            ciphertexts: vec![TypedCiphertext {
                ciphertext: ct_buf,
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: vec![],
                // NOTE: because the way [setup_public_decryptor] is implemented,
                // the ciphertext format must be SmallExpanded for the dummy decryptor to work
                ciphertext_format: CiphertextFormat::SmallExpanded as i32,
            }],
            key_id: Some(key_id.into()),
            domain: Some(domain),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: None,
        });
        public_decryptor.public_decrypt(request).await.unwrap();
        // there's no need to check the decryption result since it's a dummy protocol
        // and always produces the same response
        public_decryptor
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap();
    }
}
