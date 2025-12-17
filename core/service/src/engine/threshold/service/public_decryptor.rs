// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

// === External Crates ===
use anyhow::anyhow;
use itertools::Itertools;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{
        self, CiphertextFormat, Empty, PublicDecryptionRequest, PublicDecryptionResponse,
        PublicDecryptionResponsePayload, TypedPlaintext,
    },
    RequestId,
};
use observability::{
    metrics::{self},
    metrics_names::{
        ERR_KEY_NOT_FOUND, ERR_RATE_LIMIT_EXCEEDED, OP_PUBLIC_DECRYPT_INNER,
        OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, TAG_CONTEXT_ID, TAG_EPOCH_ID,
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
use tonic::{Request, Response};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    cryptography::internal_crypto_types::LegacySerialization,
    engine::{
        base::{
            compute_external_pt_signature, deserialize_to_low_level, BaseKmsStruct,
            PubDecCallValues,
        },
        threshold::{service::session::ImmutableSessionMaker, traits::PublicDecryptor},
        traits::BaseKms,
        utils::MetricedError,
        validation::{
            proto_request_id, validate_public_decrypt_req, RequestIdParsingErr,
            DSEP_PUBLIC_DECRYPTION,
        },
    },
    util::{
        meta_store::{
            add_req_to_meta_store, retrieve_from_meta_store, update_err_req_in_meta_store,
            update_req_in_meta_store, MetaStore,
        },
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
                let session = session_maker
                    .make_small_async_session_z128(session_id, context_id, epoch_id)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Could not prepare ddec data for noiseflood decryption: {e}",
                        )
                    })?;
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
                let mut session = session_maker
                    .make_small_async_session_z64(session_id, context_id, epoch_id)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Could not prepare ddec data for bitdec decryption: {e}",)
                    })?;

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
    ) -> Result<Response<Empty>, MetricedError> {
        // Check for resource exhaustion once all the other checks are ok
        // because resource exhaustion can be recovered by sending the exact same request
        // but the errors above cannot be tried again.
        let permit = self.rate_limiter.start_pub_decrypt().await.map_err(|e| {
            metrics::METRICS
                .increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED);
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                None,
                e,
                tonic::Code::ResourceExhausted,
            )
        })?;
        let mut timer = metrics::METRICS
            .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
            .start();

        let inner = Arc::new(request.into_inner());
        tracing::info!("{}", format_public_request(&inner));

        // Check and extract the parameters from the request in a separate thread
        let (ciphertexts, req_id, key_id, context_id, epoch_id, eip712_domain) = {
            let inner_compute = Arc::clone(&inner);
            // TODO does it make sense to spawn this as a thread? It is just parsing the parameters
            spawn_compute_bound(move || {
                validate_public_decrypt_req(&inner_compute).map_err(|e| {
                    MetricedError::new(
                        OP_PUBLIC_DECRYPT_REQUEST,
                        None,
                        e,
                        tonic::Code::InvalidArgument,
                    )
                })
            })
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_PUBLIC_DECRYPT_REQUEST,
                    None,
                    e, // Thread execution error
                    tonic::Code::Internal,
                )
            })?
        }?;
        let my_role = self.session_maker.my_role(&context_id).await.map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                Some(req_id),
                e,
                tonic::Code::InvalidArgument,
            )
        })?;
        let dec_mode = self.decryption_mode;
        let metric_tags = vec![
            (TAG_PARTY_ID, my_role.to_string()),
            (TAG_KEY_ID, key_id.as_str()),
            (TAG_CONTEXT_ID, context_id.as_str()),
            (TAG_EPOCH_ID, epoch_id.as_str()),
            (
                TAG_PUBLIC_DECRYPTION_KIND,
                dec_mode.as_str_name().to_string(),
            ),
        ];
        timer.tags(metric_tags.clone());

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
            add_req_to_meta_store(&mut guarded_meta_store, &req_id, OP_PUBLIC_DECRYPT_REQUEST)
                .await?;
            let total_lock_time = lock_start.elapsed();
            (lock_acquired_time, total_lock_time)
        };

        // TODO do we still want to log these lock times?
        // Log after lock is released
        tracing::debug!(
            "MetaStore INITIAL insert - req_id={}, key_id={}, context_id={}, epoch_id={}, party={}, ciphertexts_count={}, lock_acquired_in={:?}, total_lock_held={:?}",
            req_id, key_id, context_id, epoch_id, my_role, ciphertexts.len(), lock_acquired_time, total_lock_time
        );

        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();

        let meta_store = Arc::clone(&self.pub_dec_meta_store);
        let sigkey = self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                Some(req_id),
                e,
                tonic::Code::FailedPrecondition,
            )
        })?;
        // collect decryption results in async mgmt task so we can return from this call without waiting for the decryption(s) to finish
        let mut dec_tasks = Vec::new();

        // iterate over ciphertexts in this batch and decrypt each in their own session (so that it happens in parallel)
        for (ctr, typed_ciphertext) in ciphertexts.into_iter().enumerate() {
            let inner_timer = metrics::METRICS
                .time_operation(OP_PUBLIC_DECRYPT_INNER)
                .tags(metric_tags.clone())
                .start();
            let internal_sid = req_id
                .derive_session_id_with_counter(ctr as u64)
                .map_err(|e| {
                    MetricedError::new(
                        OP_PUBLIC_DECRYPT_INNER,
                        Some(req_id),
                        e,
                        tonic::Code::Aborted,
                    )
                })?;

            let crypto_storage = self.crypto_storage.clone();
            // we do not need to hold the handle,
            // the result of the computation is tracked by the pub_dec_meta_store
            let session_maker = self.session_maker.clone();
            let decrypt_future = || async move {
                let fhe_type_string = typed_ciphertext.fhe_type_string();
                let fhe_type = if let Ok(f) = typed_ciphertext.fhe_type() {
                    f
                } else {
                    return Err(anyhow::anyhow!(format!(
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
                    .read_guarded_threshold_fhe_keys(&key_id.into())
                    .await
                    .inspect_err(|_e| {
                        metrics::METRICS
                            .increment_error_counter(OP_PUBLIC_DECRYPT_INNER, ERR_KEY_NOT_FOUND)
                    })?;

                let res_plaintext = match fhe_type {
                    FheTypes::Uint2048 => RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<
                        tfhe::integer::bigint::U2048,
                    >(
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
                    FheTypes::Uint1024 => RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<
                        tfhe::integer::bigint::U1024,
                    >(
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
                    FheTypes::Uint512 => RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<
                        tfhe::integer::bigint::U512,
                    >(
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
                    FheTypes::Uint256 => RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<
                        tfhe::integer::U256,
                    >(
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
                    FheTypes::Uint160 => RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<
                        tfhe::integer::U256,
                    >(
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
                    FheTypes::Uint128 => {
                        RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<u128>(
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
                        .map(|x| TypedPlaintext::new(x, fhe_type))
                    }
                    FheTypes::Uint80 => {
                        RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<u128>(
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
                        .map(TypedPlaintext::from_u80)
                    }
                    FheTypes::Bool
                    | FheTypes::Uint4
                    | FheTypes::Uint8
                    | FheTypes::Uint16
                    | FheTypes::Uint32
                    | FheTypes::Uint64 => {
                        RealPublicDecryptor::<PubS, PrivS, Dec>::inner_decrypt::<u64>(
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
                        .map(|x| TypedPlaintext::new(x as u128, fhe_type))
                    }
                    unsupported_fhe_type => Err(anyhow::anyhow!(
                        "Unsupported fhe type {:?}",
                        unsupported_fhe_type
                    )),
                };
                // We don't update the error counter here but rather in the signature task
                // so we only update it once even if there are multiple decryption task that fail
                match res_plaintext {
                    Ok(plaintext) => Ok((ctr, plaintext)),
                    Result::Err(e) => Err(anyhow::anyhow!("Threshold decryption failed: {e}")),
                }
            };
            dec_tasks.push(
                self.tracker
                    .spawn(decrypt_future().instrument(tracing::Span::current())),
            );
        }
        // TODO the code below could be simplified a lot of we don't want to log individual lock time and do so many tiny threads
        let dec_sig_future = move |_permit| async move {
            // Move the timer to the management task's context, so as to drop
            // it when decryptions are available
            let _timer = timer;
            // NOTE: _permit should be dropped at the end of this function
            let mut decs = HashMap::new();

            // Collect all results first, without holding any locks
            while let Some(resp) = dec_tasks.pop() {
                let err_msg = match resp.await {
                    Ok(Ok((idx, plaintext))) => {
                        decs.insert(idx, plaintext);
                        // Everything is ok, no need to do error handling on this task
                        continue;
                    }
                    Ok(Err(e)) => {
                        format!("Failed inner decryption {req_id} with err: {e:?}")
                    }
                    Err(e) => {
                        format!("Failed join inner decryption threads on {req_id} with JoinError: {e:?}")
                    }
                };
                let _ = update_err_req_in_meta_store(
                    &mut meta_store.write().await,
                    &req_id,
                    err_msg,
                    OP_PUBLIC_DECRYPT_INNER,
                );
                return;
            }
            // All the inner decrypts succeeded ok...

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
            let pts_len = pts.len();
            let res = match external_sig {
                Ok(Ok(sig)) => Ok((req_id, pts, sig, extra_data)),
                Err(e) | Ok(Err(e)) => Err(format!(
                    "Failed to compute external signature for decryption request {req_id}: {e:?}"
                )),
            };

            // Single success update with minimal lock hold time
            let (lock_acquired_time, total_lock_time) = {
                let lock_start = std::time::Instant::now();
                let mut guarded_meta_store = meta_store.write().await;
                let lock_acquired_time = lock_start.elapsed();
                update_req_in_meta_store(
                    &mut guarded_meta_store,
                    &req_id,
                    res,
                    OP_PUBLIC_DECRYPT_REQUEST,
                );
                let total_lock_time = lock_start.elapsed();
                (lock_acquired_time, total_lock_time)
            };
            // Log after lock is released
            tracing::info!(
                "MetaStore SUCCESS update - req_id={}, key_id={}, party={}, ciphertexts_count={}, lock_acquired_in={:?}, total_lock_held={:?}",
                req_id, key_id, my_role, pts_len, lock_acquired_time, total_lock_time
            );
        };
        // Increment the error counter if ever the task fails
        self.tracker.spawn(async move {
            // Ignore the result since this is a background thread.
            let _ = dec_sig_future(permit)
                .instrument(tracing::Span::current())
                .await;
        });
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, MetricedError> {
        let request_id = proto_request_id(
            &request.into_inner(),
            RequestIdParsingErr::PublicDecResponse,
        )
        .map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_RESULT,
                None,
                e,
                tonic::Code::InvalidArgument,
            )
        })?;

        let (retrieved_req_id, plaintexts, external_signature, extra_data) =
            retrieve_from_meta_store(
                &self.pub_dec_meta_store.read().await,
                &request_id,
                OP_PUBLIC_DECRYPT_RESULT,
            )
            .await?;

        if request_id != retrieved_req_id {
            return Err(MetricedError::new(
                OP_PUBLIC_DECRYPT_RESULT,
                Some(request_id),
                anyhow!("Request ID mismatch: expected {request_id}, got {retrieved_req_id}"),
                tonic::Code::NotFound,
            ));
        }

        let server_verf_key = self.base_kms.verf_key().to_legacy_bytes().map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_RESULT,
                Some(request_id),
                anyhow!("Failed to serialize server verification key: {e:?}"),
                tonic::Code::Internal,
            )
        })?;
        let sig_payload = PublicDecryptionResponsePayload {
            plaintexts,
            verification_key: server_verf_key,
            request_id: Some(retrieved_req_id.into()),
        };

        let sig_payload_vec = bc2wrap::serialize(&sig_payload).map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_RESULT,
                Some(request_id),
                anyhow!("Could not convert payload to bytes {sig_payload:?}: {e:?}"),
                tonic::Code::Internal,
            )
        })?;

        let sig = self
            .base_kms
            .sign(&DSEP_PUBLIC_DECRYPTION, &sig_payload_vec)
            .map_err(|e| {
                MetricedError::new(
                    OP_PUBLIC_DECRYPT_RESULT,
                    Some(request_id),
                    anyhow!("Could not sign payload {sig_payload:?}: {e:?}"),
                    tonic::Code::Internal,
                )
            })?;

        Ok(Response::new(PublicDecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload),
            external_signature,
            extra_data,
        }))
    }
}

// We want most of the metadata but not the actual ciphertexts
fn format_public_request(request: &PublicDecryptionRequest) -> String {
    format!(
        "PublicDecryptionRequest {{ request_id: {:?}, key_id: {:?}, context_id: {:?}, epoch_id: {:?}, ciphertext_count: {:?} }}",
        request.request_id, request.key_id, request.context_id, request.epoch_id, request.ciphertexts.len()
    )
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
        consts::{DEFAULT_MPC_CONTEXT, TEST_PARAM},
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
                .read_guarded_threshold_fhe_keys(&key_id)
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
