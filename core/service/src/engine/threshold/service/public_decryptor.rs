// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

// === External Crates ===
use algebra::{
    base_ring::Z128,
    galois_rings::{common::ResiduePoly, degree_4::ResiduePolyF4Z128},
    structure_traits::{ErrorCorrect, Invert, Ring, Solve},
};
use anyhow::anyhow;
use itertools::Itertools;
use kms_grpc::{
    RequestId,
    identifiers::{ContextId, EpochId},
    kms::v1::{
        self, CiphertextFormat, Empty, PublicDecryptionRequest, PublicDecryptionResponse,
        PublicDecryptionResponsePayload, TypedPlaintext,
    },
};
use observability::{
    metrics::{self},
    metrics_names::{
        OP_PUBLIC_DECRYPT_INNER, OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, TAG_PARTY_ID,
        TAG_PUBLIC_DECRYPTION_KIND, TAG_TFHE_TYPE,
    },
};
use tfhe::FheTypes;
use thread_handles::spawn_compute_bound;
use threshold_execution::{
    endpoints::decryption::{
        DecryptionMode, LowLevelCiphertextAndKeys, OfflineNoiseFloodSession,
        SecureOnlineNoiseFloodDecryption, SmallOfflineNoiseFloodSession,
        decrypt_using_noiseflooding, secure_decrypt_using_bitdec,
    },
    runtime::sessions::small_session::SmallSession,
    tfhe_internals::private_keysets::PrivateKeySet,
};
use threshold_types::session_id::SessionId;
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Code, Request, Response};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    consts::DURATION_WAITING_ON_RESULT_SECONDS,
    cryptography::internal_crypto_types::LegacySerialization,
    engine::{
        base::{
            BaseKmsStruct, PubDecCallValues, deserialize_to_low_level,
            sign_public_decryption_result,
        },
        threshold::{
            service::session::{ImmutableSessionMaker, validate_context_and_epoch},
            traits::PublicDecryptor,
        },
        utils::MetricedError,
        validation::{
            RequestIdParsingErr, parse_grpc_request_id, parse_optional_grpc_request_id,
            validate_public_decrypt_req,
        },
    },
    util::{
        meta_store::{
            MetaStore, add_or_redo_failed_in_meta_store, retrieve_from_meta_store_with_timeout,
            update_err_req_in_meta_store, update_req_in_meta_store,
        },
        rate_limiter::RateLimiter,
    },
    vault::storage::{Storage, StorageExt, crypto_material::ThresholdCryptoMaterialStorage},
};

// === Current Module Imports ===
use super::ThresholdFheKeys;

#[tonic::async_trait]
pub trait NoiseFloodDecryptor: Send + Sync {
    type Prep: OfflineNoiseFloodSession<{ ResiduePolyF4Z128::EXTENSION_DEGREE }> + Send;

    async fn decrypt<T>(
        noiseflood_session: &mut Self::Prep,
        ct: LowLevelCiphertextAndKeys,
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
        threshold_execution::runtime::sessions::small_session::SmallSession<ResiduePolyF4Z128>,
    >;

    async fn decrypt<T>(
        noiseflood_session: &mut Self::Prep,
        ct: LowLevelCiphertextAndKeys,
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
        >(noiseflood_session, ct, secret_key_share)
        .await
    }
}

pub struct RealPublicDecryptor<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
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
    PrivS: StorageExt + Send + Sync + 'static,
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
    #[expect(clippy::too_many_arguments)]
    async fn inner_decrypt<T>(
        session_id: SessionId,
        context_id: ContextId,
        epoch_id: EpochId,
        session_maker: ImmutableSessionMaker,
        ct: Vec<u8>,
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
        fhe_keys: ThresholdFheKeys,
        dec_mode: DecryptionMode,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    {
        let keys = fhe_keys;
        // Only the SmallCompressed format needs the decompression key to deserialize.
        // Fetching it would lazily decompress the (multi-GiB) keyset, so avoid it for
        // the Big*/SmallExpanded formats that don't use it.
        let decomp_key = match ct_format {
            CiphertextFormat::SmallCompressed => keys.decompression_key(),
            _ => None,
        };
        let low_level_ct = spawn_compute_bound(move || {
            deserialize_to_low_level(fhe_type, ct_format, &ct, decomp_key.as_deref())
        })
        .await??;

        let dec = match dec_mode {
            DecryptionMode::NoiseFloodSmall => {
                let session = session_maker
                    .make_small_async_session_z128(session_id, context_id, epoch_id)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Could not prepare ddec data for noiseflood decryption in sid {session_id}: {e}",
                        )
                    })?;
                let mut noiseflood_session = SmallOfflineNoiseFloodSession::new(session);

                // Only `Small` ciphertexts need switch&squash; the closure (and hence the
                // lazy key decompression it triggers) does not run for the Big* variants.
                let ct = low_level_ct.with_sns_keys(|| {
                    let server_key = keys.integer_server_key();
                    let ck = keys.sns_key().ok_or(anyhow::anyhow!("Missing sns key"))?;
                    Ok((server_key, ck))
                })?;

                Dec::decrypt(&mut noiseflood_session, ct, keys.private_keys.clone()).await
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
                    &keys.key_switching_key()?,
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
                            "Public Decryption with session ID {session_id} could not be retrieved"
                        ));
                    }
                };
                tracing::info!(
                    "Public decryption in session {session_id} completed. Inner thread took {:?} ms",
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
    PrivS: StorageExt + Send + Sync + 'static,
    Dec: NoiseFloodDecryptor<
            Prep = SmallOfflineNoiseFloodSession<
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                SmallSession<ResiduePolyF4Z128>,
            >,
        > + 'static,
> PublicDecryptor for RealPublicDecryptor<PubS, PrivS, Dec>
{
    // `context_id`/`epoch_id` are only known after request validation, so they start empty and are
    // recorded below. Every event and error in this request — including the ones emitted by the
    // spawned decryption task, which inherits this span — then carries both without extra log lines.
    #[tracing::instrument(skip_all, fields(
        request_id = ?request.get_ref().request_id,
        operation = "decrypt",
        context_id = tracing::field::Empty,
        epoch_id = tracing::field::Empty
    ))]
    async fn public_decrypt(
        &self,
        request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        metrics::METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST);

        // Check for resource exhaustion once all the other checks are ok
        // because resource exhaustion can be recovered by sending the exact same request
        // but the errors above cannot be tried again.
        let permit = self.rate_limiter.start_pub_decrypt().await?;
        let mut timer = metrics::METRICS
            .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
            .start();

        let inner = Arc::new(request.into_inner());

        // Check and extract the parameters from the request in a separate thread
        let (
            ciphertexts,
            req_id,
            key_id,
            context_id,
            epoch_id,
            eip712_domain,
            extra_data,
            signing_schemes,
        ) = validate_public_decrypt_req(&inner).inspect_err(|_| {
            // The unvalidated ids are worth logging only when validation rejects the request: they
            // are then the sole record of what the caller actually sent. On success the span fields
            // recorded below carry the parsed ids, and `unpack_public_decrypt_req` has already
            // logged the request's arrival.
            tracing::warn!("Rejected {}", format_public_request(&inner));
        })?;
        // Recorded before the context/epoch check so that a rejection there is attributed too.
        let span = tracing::Span::current();
        span.record("context_id", tracing::field::display(&context_id));
        span.record("epoch_id", tracing::field::display(&epoch_id));
        let my_role = validate_context_and_epoch(
            OP_PUBLIC_DECRYPT_REQUEST,
            &self.session_maker,
            Some(req_id),
            &context_id,
            &epoch_id,
        )
        .await?;
        let dec_mode = self.decryption_mode;
        let metric_tags = vec![
            (TAG_PARTY_ID, my_role.to_string()),
            (
                TAG_PUBLIC_DECRYPTION_KIND,
                dec_mode.as_str_name().to_string(),
            ),
        ];
        timer.tags(metric_tags.clone());

        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();

        // The external handles are how the caller refers to these ciphertexts, so they are the join
        // key between a KMS log and a gateway request. Logged once per request, in batch order, so
        // the `ctr` reported by a failing inner decryption below identifies the handle.
        let ext_handles_hex = ext_handles_bytes
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>();
        tracing::debug!(
            request_id = ?req_id,
            key_id = ?key_id,
            ciphertexts_count = ciphertexts.len(),
            handles = ?ext_handles_hex,
            "Starting decryption process"
        );

        let meta_store = Arc::clone(&self.pub_dec_meta_store);
        let sigkey = self.base_kms.sig_key().map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                Some(req_id),
                e,
                tonic::Code::FailedPrecondition,
            )
        })?;
        let server_verf_key = self.base_kms.verf_key().to_legacy_bytes().map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                Some(req_id),
                anyhow!("Failed to serialize server verification key: {e:?}"),
                tonic::Code::Internal,
            )
        })?;

        let fhe_keys_rlock = self
            .crypto_storage
            .read_guarded_fhe_keys(&key_id.into(), &epoch_id)
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_PUBLIC_DECRYPT_INNER,
                    Some(req_id),
                    anyhow::anyhow!("fhe key not found due to {e:?}"),
                    tonic::Code::NotFound,
                )
            })?;

        // Below we write to the meta-store, leaving this [req_id] in the
        // "Started" (Pending) state. The management task updates it on every
        // outcome path; should the permit ever be dropped without an update, the
        // store's reaper fails the entry rather than leaving it Pending forever.
        let meta_permit = add_or_redo_failed_in_meta_store(
            &self.pub_dec_meta_store,
            &req_id,
            OP_PUBLIC_DECRYPT_REQUEST,
        )
        .await?;
        // collect decryption results in async mgmt task so we can return from this call without waiting for the decryption(s) to finish
        let mut dec_tasks = Vec::new();

        // iterate over ciphertexts in this batch and decrypt each in their own session (so that it happens in parallel)
        for (ctr, typed_ciphertext) in ciphertexts.into_iter().enumerate() {
            let inner_timer = metrics::METRICS
                .time_operation(OP_PUBLIC_DECRYPT_INNER)
                .tags(metric_tags.clone())
                .start();

            // we do not need to hold the handle,
            // the result of the computation is tracked by the pub_dec_meta_store
            let session_maker = self.session_maker.clone();

            let fhe_keys_rlock_clone = fhe_keys_rlock.clone();
            let decrypt_future = || async move {
                let internal_sid = req_id.derive_session_id_with_counter(ctr as u64)?;
                // Taken before `typed_ciphertext` is partially moved below, so that every failure
                // in this task can name the handle the caller asked about.
                let external_handle = hex::encode(&typed_ciphertext.external_handle);
                let fhe_type_string = typed_ciphertext.fhe_type_string();
                let fhe_type = if let Ok(f) = typed_ciphertext.fhe_type() {
                    f
                } else {
                    return Err(anyhow::anyhow!(format!(
                        "Threshold decryption failed for handle {external_handle} due to wrong fhe type: {}",
                        typed_ciphertext.fhe_type
                    )));
                };
                // Capture the inner_timer inside the decryption tasks, such that when the task
                // exits, the timer is dropped and thus exported
                let mut inner_timer = inner_timer;
                inner_timer.tag(TAG_TFHE_TYPE, fhe_type_string);

                let ct_format = typed_ciphertext.ciphertext_format();
                let ciphertext = typed_ciphertext.ciphertext;

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
                        fhe_keys_rlock_clone,
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
                        fhe_keys_rlock_clone,
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
                        fhe_keys_rlock_clone,
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
                        fhe_keys_rlock_clone,
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
                        fhe_keys_rlock_clone,
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
                            fhe_keys_rlock_clone,
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
                            fhe_keys_rlock_clone,
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
                            fhe_keys_rlock_clone,
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
                    Result::Err(e) => Err(anyhow::anyhow!(
                        "Threshold decryption failed for ciphertext #{ctr} (handle {external_handle}): {e}"
                    )),
                }
            };
            dec_tasks.push(
                self.tracker
                    .spawn(decrypt_future().instrument(tracing::Span::current())),
            );
        }
        let dec_sig_future = move |_permit| async move {
            // Move the timer to the management task's context, so as to drop
            // it when decryptions are available
            let _timer = timer;
            // permit should be dropped at the end of this function
            let mut meta_permit = Some(meta_permit);
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
                        format!(
                            "Failed join inner decryption threads on {req_id} with JoinError: {e:?}"
                        )
                    }
                };
                let _ = update_err_req_in_meta_store(
                    &meta_store,
                    meta_permit
                        .take() // Ensure permit gets set to `None` after updating meta store with an errror
                        .expect("permit must still be present on first error"),
                    err_msg,
                    OP_PUBLIC_DECRYPT_INNER,
                )
                .await;
                return;
            }
            // All the inner decrypts succeeded ok...

            // Prepare success data outside of lock
            let pts: Vec<_> = decs
                .keys()
                .sorted()
                .map(|idx| decs.get(idx).unwrap().clone()) // unwrap is fine here, since we iterate over all keys.
                .collect();

            // Assemble the full response payload here so it is signed once,
            // from one snapshot, rather than re-signed on every result fetch.
            let payload = PublicDecryptionResponsePayload {
                plaintexts: pts,
                verification_key: server_verf_key,
                request_id: Some(req_id.into()),
            };

            // Compute expensive signatures OUTSIDE the lock
            let signed = spawn_compute_bound(move || {
                sign_public_decryption_result(
                    &sigkey,
                    &signing_schemes,
                    payload,
                    &ext_handles_bytes,
                    extra_data,
                    &eip712_domain,
                )
            })
            .await;
            let res = match signed {
                Ok(Ok(values)) => Ok(values),
                Err(e) | Ok(Err(e)) => Err(format!(
                    "Failed to sign decryption result for request {req_id}: {e:?}"
                )),
            };

            update_req_in_meta_store(
                &meta_store,
                meta_permit
                    .take()
                    .expect("permit must still be present on success path"),
                res,
                OP_PUBLIC_DECRYPT_REQUEST,
            )
            .await;
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

    async fn public_decrypt_sync(
        &self,
        request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<PublicDecryptionResponse>, MetricedError> {
        // `public_decrypt` consumes the request, so keep the raw id for fetching the result below.
        let raw_request_id = request.get_ref().request_id.clone();

        match self.public_decrypt(request).await {
            Ok(_empty) => (),
            // Already succeeded, in flight, or tombstoned: attach to the existing entry
            Err(e) if e.code() == tonic::Code::AlreadyExists => e.defuse(),
            Err(e) => return Err(e),
        }

        // `public_decrypt` accepted the request, so its id must parse.
        let req_id: RequestId =
            parse_optional_grpc_request_id(&raw_request_id, RequestIdParsingErr::PublicDecRequest)
                .map_err(|e| {
                    MetricedError::new(OP_PUBLIC_DECRYPT_REQUEST, None, e, Code::InvalidArgument)
                })?;

        self.get_result(Request::new(req_id.into())).await
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, MetricedError> {
        metrics::METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_RESULT);

        let request_id = parse_grpc_request_id(
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

        let arc = retrieve_from_meta_store_with_timeout(
            &self.pub_dec_meta_store,
            &request_id,
            OP_PUBLIC_DECRYPT_RESULT,
            DURATION_WAITING_ON_RESULT_SECONDS,
        )
        .await?;
        let PubDecCallValues {
            payload,
            signature,
            external_signature,
            extra_data,
            signatures,
        } = (*arc).clone();

        if payload.request_id != Some(request_id.into()) {
            return Err(MetricedError::new(
                OP_PUBLIC_DECRYPT_RESULT,
                Some(request_id),
                anyhow::anyhow!(
                    "Request ID mismatch: expected {request_id}, got {:?}",
                    payload.request_id
                ),
                tonic::Code::Internal,
            ));
        }

        Ok(Response::new(PublicDecryptionResponse {
            signature,
            signatures,
            payload: Some(payload),
            external_signature,
            extra_data,
        }))
    }
}

// We want most of the metadata but not the actual ciphertexts
fn format_public_request(request: &PublicDecryptionRequest) -> String {
    format!(
        "PublicDecryptionRequest {{ request_id: {:?}, key_id: {:?}, context_id: {:?}, epoch_id: {:?}, ciphertext_count: {:?} }}",
        request.request_id,
        request.key_id,
        request.context_id,
        request.epoch_id,
        request.ciphertexts.len()
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        consts::{DEFAULT_MPC_CONTEXT, TEST_PARAM},
        cryptography::signatures::gen_sig_keys,
        dummy_domain,
        engine::threshold::service::session::SessionMaker,
        util::meta_store::EntryState,
        vault::storage::{crypto_material::PublicKeySet, ram},
    };
    use aes_prng::AesRng;
    use kms_grpc::{RequestId, kms::v1::SigningSchemeType};
    use kms_grpc::{
        kms::v1::TypedCiphertext,
        rpc_types::{KMSType, alloy_to_protobuf_domain},
    };
    use rand::SeedableRng;
    use threshold_execution::{
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::prss::PRSSSetup, tfhe_internals::utils::expanded_encrypt,
    };

    use super::*;

    pub struct DummyNoisefloodDecryptor;

    #[tonic::async_trait]
    impl NoiseFloodDecryptor for DummyNoisefloodDecryptor {
        type Prep = SmallOfflineNoiseFloodSession<
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            SmallSession<ResiduePolyF4Z128>,
        >;

        async fn decrypt<T>(
            noiseflood_session: &mut Self::Prep,
            _ct: LowLevelCiphertextAndKeys,
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
        PrivS: StorageExt + Send + Sync + 'static,
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
            );

            let tracker = Arc::new(TaskTracker::new());
            let rate_limiter = RateLimiter::default();

            Self {
                base_kms,
                crypto_storage,
                pub_dec_meta_store: MetaStore::new_unlimited(),
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

    fn make_valid_request(
        req_id: RequestId,
        key_id: RequestId,
        epoch_id: EpochId,
        ct_buf: Vec<u8>,
    ) -> PublicDecryptionRequest {
        PublicDecryptionRequest {
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
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
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            extra_data: vec![],
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            epoch_id: Some(epoch_id.into()),
        }
    }

    async fn setup_public_decryptor(
        rng: &mut AesRng,
    ) -> (
        RequestId,
        EpochId,
        Vec<u8>,
        RealPublicDecryptor<ram::RamStorage, ram::RamStorage, DummyNoisefloodDecryptor>,
    ) {
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk.clone()).unwrap();
        let param = TEST_PARAM;
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

        let key_meta_store = MetaStore::new_unlimited();
        let meta_store_permit = key_meta_store.write().await.insert(&key_id).unwrap();

        let public_decryptor = RealPublicDecryptor::init_test_dummy_decryptor(
            base_kms,
            session_maker.make_immutable(),
        )
        .await;

        public_decryptor
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
            let _guard = public_decryptor
                .crypto_storage
                .read_guarded_fhe_keys(&key_id, &epoch_id)
                .await
                .unwrap();
        }

        (key_id, epoch_id, ct_buf, public_decryptor)
    }

    #[tokio::test]
    async fn test_resource_exhausted() {
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        let mut rng = AesRng::seed_from_u64(12);

        let (key_id, epoch_id, ct_buf, mut public_decryptor) =
            setup_public_decryptor(&mut rng).await;

        // Set bucket size to zero, so no operations are allowed
        public_decryptor.set_bucket_size(0);

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);
        let err = public_decryptor
            .public_decrypt(Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // the sync endpoint is rate-limited the same way
        let err = public_decryptor
            .public_decrypt_sync(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // finally reset the bucket size to a non-zero value
        public_decryptor.set_bucket_size(100);
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(12);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);
        public_decryptor
            .public_decrypt(Request::new(request.clone()))
            .await
            .unwrap();

        // try sending the same request again
        let err = public_decryptor
            .public_decrypt(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(1123);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let valid_request = make_valid_request(req_id, key_id, epoch_id, ct_buf);

        {
            // unknown key ID
            let mut request = valid_request.clone();
            request.key_id = Some(RequestId::new_random(&mut rng).into());
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        {
            // unknown epoch ID
            let mut request = valid_request.clone();
            request.epoch_id = Some(EpochId::new_random(&mut rng).into());
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        {
            // unknown request ID on the result endpoint
            let another_req_id = RequestId::new_random(&mut rng);
            let err = public_decryptor
                .get_result(Request::new(another_req_id.into()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let valid_request = make_valid_request(req_id, key_id, epoch_id, ct_buf);
        {
            // missing request ID
            let mut request = valid_request.clone();
            request.request_id = None;
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrongly formatted request ID
            let mut request = valid_request.clone();
            request.request_id = Some(kms_grpc::kms::v1::RequestId {
                request_id: "invalid_request_id".to_string(),
            });
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // empty ciphertexts
            let mut request = valid_request.clone();
            request.ciphertexts.clear();
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrongly formatted key ID
            let mut request = valid_request.clone();
            request.key_id = Some(kms_grpc::kms::v1::RequestId {
                request_id: "invalid_request_id".to_string(),
            });
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // missing domain
            let mut request = valid_request.clone();
            request.domain = None;
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrong domain
            let mut request = valid_request.clone();
            let mut domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            domain.verifying_contract = "invalid_contract".to_string();
            request.domain = Some(domain);
            let err = public_decryptor
                .public_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decryptor
                .public_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        {
            // wrongly formatted request ID on the result endpoint
            let bad_req_id = kms_grpc::kms::v1::RequestId {
                request_id: "invalid_request_id".to_string(),
            };
            let err = public_decryptor
                .get_result(Request::new(bad_req_id))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let mut request = make_valid_request(req_id, key_id, epoch_id, ct_buf);
        // no signing scheme means ecdsa256k1 is used by default
        request.signing_schemes.clear();
        public_decryptor
            .public_decrypt(Request::new(request))
            .await
            .unwrap();
        // there's no need to check the decryption result since it's a dummy protocol
        // and always produces the same response.
        crate::testing::utils::poll_result_until_ready(|| {
            public_decryptor.get_result(Request::new(req_id.into()))
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sunshine_sync() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);

        // The sync endpoint returns the response directly, no polling needed.
        let response = public_decryptor
            .public_decrypt_sync(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let payload = response
            .payload
            .clone()
            .expect("sync response carries a payload");
        assert_eq!(payload.plaintexts.len(), 1);
        assert!(!response.signature.is_empty());

        // The request went through the meta-store, so the result stays retrievable through the
        // async result endpoint...
        let again = public_decryptor
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.payload, again.payload);

        // ...and re-sending the same sync request returns that stored result instead of failing
        // with `AlreadyExists`. Attaching is a success path, so nothing may be recorded as a
        // failure along the way.
        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let retry = public_decryptor
            .public_decrypt_sync(Request::new(request))
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
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;
        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);

        let requests_before = metrics::METRICS.request_counter_value(OP_PUBLIC_DECRYPT_REQUEST);
        let results_before = metrics::METRICS.request_counter_value(OP_PUBLIC_DECRYPT_RESULT);
        public_decryptor
            .public_decrypt_sync(Request::new(request))
            .await
            .unwrap();
        // Check global growth: the counters are shared at the process level.
        assert!(
            metrics::METRICS.request_counter_value(OP_PUBLIC_DECRYPT_REQUEST) > requests_before
        );
        assert!(metrics::METRICS.request_counter_value(OP_PUBLIC_DECRYPT_RESULT) > results_before);
    }

    #[tokio::test]
    async fn sync_attaches_to_async_request() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);

        // Start the decryption through the async endpoint...
        public_decryptor
            .public_decrypt(Request::new(request.clone()))
            .await
            .unwrap();

        // ...then a sync request with the same request ID attaches to that entry rather than
        // starting a second decryption, without reporting a failure along the way.
        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let response = public_decryptor
            .public_decrypt_sync(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response
                .payload
                .clone()
                .expect("sync response carries a payload")
                .plaintexts
                .len(),
            1
        );
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before,
            "attaching to an in-flight request must not report a failure"
        );

        // The entry the sync call waited on is the one the async request created.
        let stored = public_decryptor
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
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);

        // Leave the request ID in the state a failed attempt would leave it in.
        let permit = public_decryptor
            .pub_dec_meta_store
            .write()
            .await
            .insert(&req_id)
            .unwrap();
        crate::util::meta_store::update_err_req_in_meta_store(
            &public_decryptor.pub_dec_meta_store,
            permit,
            "forced failure".to_string(),
            OP_PUBLIC_DECRYPT_REQUEST,
        )
        .await;
        assert!(matches!(
            public_decryptor
                .pub_dec_meta_store
                .read()
                .await
                .retrieve(&req_id),
            Some(EntryState::Done(Err(_)))
        ));

        // The sync call redoes the decryption instead of returning the stored failure.
        let response = public_decryptor
            .public_decrypt_sync(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response
                .payload
                .expect("redone decryption carries a payload")
                .plaintexts
                .len(),
            1
        );
    }

    /// A failed entry that is still permit-held cannot be redone, so `public_decrypt` answers
    /// `AlreadyExists`, which the sync endpoint reads as "attach to the existing entry". That
    /// internal signal must be defused rather than dropped: dropping a `MetricedError` records
    /// an error and logs a failure for what is only a control-flow decision.
    #[tokio::test]
    async fn sync_attach_signal_is_not_recorded_as_error() {
        let mut rng = AesRng::seed_from_u64(13);
        let (key_id, epoch_id, ct_buf, public_decryptor) = setup_public_decryptor(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let request = make_valid_request(req_id, key_id, epoch_id, ct_buf);

        // Fail the entry, then hold a permit on it so that `redo_failed` reports `Locked`.
        let permit = public_decryptor
            .pub_dec_meta_store
            .write()
            .await
            .insert(&req_id)
            .unwrap();
        crate::util::meta_store::update_err_req_in_meta_store(
            &public_decryptor.pub_dec_meta_store,
            permit,
            "forced failure".to_string(),
            OP_PUBLIC_DECRYPT_REQUEST,
        )
        .await;
        let _held_permit = public_decryptor
            .pub_dec_meta_store
            .write()
            .await
            .lock_entry(&req_id)
            .unwrap();

        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let err = public_decryptor
            .public_decrypt_sync(Request::new(request))
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
