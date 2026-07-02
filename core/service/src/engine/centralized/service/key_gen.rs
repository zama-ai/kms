use crate::cryptography::signatures::PrivateSigKey;
use crate::engine::base::{DSEP_PUBDATA_KEY, KeyGenMetadata, compute_info_decompression_keygen};
use crate::engine::centralized::central_kms::{
    CentralizedKeyGenResult, CentralizedKms, async_generate_decompression_keys,
    async_generate_fhe_keys,
};
use crate::engine::keyset_configuration::InternalKeySetConfig;
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::utils::MetricedError;
use crate::engine::validation::{
    RequestIdParsingErr, parse_grpc_request_id, validate_key_gen_request,
};
use crate::util::meta_store::{
    EntryState, MetaStore, MetaStorePermit, add_req_to_meta_store, ensure_not_in_meta_store,
    retrieve_from_meta_store, try_delete_in_meta_store, update_err_req_in_meta_store,
};
use crate::vault::storage::crypto_material::{CentralizedCryptoMaterialStorage, PublicKeySet};
use crate::vault::storage::{Storage, StorageExt};
use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use itertools::Itertools;
use kms_grpc::kms::v1::{Empty, KeyDigest, KeyGenRequest, KeyGenResult};
use kms_grpc::{EpochId, RequestId};
use observability::metrics::METRICS;
use observability::metrics_names::{
    CENTRAL_TAG, OP_INSECURE_KEYGEN_REQUEST, OP_INSECURE_KEYGEN_RESULT, OP_KEYGEN_ABORT,
    OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT, TAG_PARTY_ID,
};
use std::sync::Arc;
use threshold_execution::keyset_config::KeySetConfig;
use threshold_execution::tfhe_internals::parameters::DKGParams;
use tokio_util::sync::CancellationToken;

use tokio::sync::RwLock;
use tonic::{Request, Response};
use tracing::Instrument;

/// Implementation of the key_gen endpoint
pub async fn key_gen_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<KeyGenRequest>,
    insecure: bool,
) -> Result<Response<Empty>, MetricedError> {
    // Retrieve the correct tag
    let op_tag = if insecure {
        OP_INSECURE_KEYGEN_REQUEST
    } else {
        OP_KEYGEN_REQUEST
    };
    let rate_limiter_permit = service.rate_limiter.start_keygen(op_tag).await?;
    // TODO add serial lock to have similar flow to threshold case
    // Acquire the serial lock to make sure no other keygen is running concurrently
    // let _guard = service.serial_lock.lock().await;
    let timer = METRICS
        .time_operation(op_tag)
        // Use a constant party ID since this is the central KMS
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();

    let inner = request.into_inner();
    let request_params_set = inner.params.is_some();

    let (
        req_id,
        preproc_id,
        context_id,
        epoch_id,
        dkg_params_of_request,
        internal_keyset_config,
        eip712_domain,
        extra_data,
    ) = validate_key_gen_request(inner, op_tag)?;

    tracing::info!("centralized key-gen with request id: {:?}", req_id);

    if !service
        .context_manager
        .mpc_context_exists_in_cache(&context_id)
        .await
    {
        return Err(MetricedError::new(
            op_tag,
            Some(req_id),
            anyhow::anyhow!("Context ID {context_id} not found"),
            tonic::Code::NotFound,
        ));
    }

    let preproc_id = preproc_id.ok_or_else(|| {
        MetricedError::new(
            op_tag,
            Some(req_id),
            anyhow::anyhow!("Missing preprocessing ID in key generation request"),
            tonic::Code::InvalidArgument,
        )
    })?;

    // Check for existence of request preprocessing ID
    // also check that the request ID is not used yet
    // If all is ok write the request ID to the meta store
    // All validation must be done before inserting the request ID
    //
    // Unlike the threshold KMS, the centralized KMS draws no distinction between
    // secure and insecure preprocessing: both `key_gen_preproc` and
    // `insecure_key_gen_preproc` store an identical dummy entry in the same
    // `preprocessing_meta_store`. We therefore retrieve by ID without checking
    // how the preprocessing was produced, so either a normal or an insecure
    // keygen can consume either kind of preprocessing.
    let (params, permit) = {
        let preproc =
            retrieve_from_meta_store(&service.preprocessing_meta_store, &preproc_id, op_tag)
                .await
                .map_err(|e| {
                    // Remap the error to include the correct request ID
                    MetricedError::new(
                        op_tag,
                        Some(req_id),
                        anyhow::anyhow!(e.internal_err().to_string()),
                        e.code(),
                    )
                })?;
        // Request params take precedence; otherwise use the params stored during preprocessing.
        let params = if request_params_set {
            dkg_params_of_request
        } else {
            preproc.dkg_param
        };

        // Ensure that no key already exists for a given request.
        let already_exists = service
            .crypto_storage
            .fhe_keys_exists(&req_id, &epoch_id)
            .await
            .map_err(|e| MetricedError::new(op_tag, Some(req_id), e, tonic::Code::Internal))?;
        if already_exists {
            return Err(MetricedError::new(
                op_tag,
                Some(req_id),
                anyhow::anyhow!(
                    "FHE key for request {} and epoch {} already exists in storage",
                    req_id,
                    epoch_id
                ),
                tonic::Code::AlreadyExists,
            ));
        }

        // Fail fast: reject before the remaining setup if this request id is
        // already known to the meta store.
        ensure_not_in_meta_store(&service.key_meta_map, &req_id, op_tag).await?;

        (params, rate_limiter_permit)
    };

    let meta_store = Arc::clone(&service.key_meta_map);
    let sk = service
            .base_kms
            .sig_key()
            .map_err(|e| {
        MetricedError::new(
            op_tag,
            Some(req_id),
            anyhow::anyhow!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
            tonic::Code::FailedPrecondition,
        )
    })?;

    let token = CancellationToken::new();
    {
        let mut ongoing_key_gen = service.ongoing_key_gen.lock().await;
        if ongoing_key_gen.contains_key(&preproc_id) {
            return Err(MetricedError::new(
                op_tag,
                Some(req_id),
                anyhow::anyhow!(
                    "Key generation with preprocessing ID {preproc_id} is already ongoing"
                ),
                tonic::Code::AlreadyExists,
            ));
        }
        ongoing_key_gen.insert(preproc_id, token.clone());
    }

    // check that the request ID is not used yet
    // and then insert the request ID only if it's unused
    // all validation must be done before inserting the request ID
    let meta_permit = match add_req_to_meta_store(&service.key_meta_map, &req_id, op_tag).await {
        Ok(permit) => permit,
        Err(e) => {
            service.ongoing_key_gen.lock().await.remove(&preproc_id);
            return Err(e);
        }
    };

    let ongoing = Arc::clone(&service.ongoing_key_gen);
    let crypto_storage = service.crypto_storage.clone();

    let preproc_meta_store = Arc::clone(&service.preprocessing_meta_store);

    service.tracker.spawn(
        async move {
            let _timer = timer;
            let _permit = permit;
            // "Remove" the preprocessing material by deleting its entry from the meta store
            tracing::info!("Deleting preprocessed material with ID {preproc_id} from meta store");
            let delete_res = try_delete_in_meta_store(&preproc_meta_store, &preproc_id).await;
            match delete_res {
                Ok(EntryState::Done(Ok(_))) => {
                    tracing::info!(
                        "Successfully deleted preprocessing ID {preproc_id} after keygen completion for request ID {req_id}"
                    );
                }
                Ok(EntryState::Done(Err(e))) => {
                    MetricedError::handle_unreturnable_error(
                        op_tag,
                        Some(req_id),
                        anyhow::anyhow!(
                            "Preprocessing ID {preproc_id} finished with error: {e}"
                        ),
                    );
                }
                Ok(_) => {
                    MetricedError::handle_unreturnable_error(
                        op_tag,
                        Some(req_id),
                        anyhow::anyhow!(
                            "Preprocessing ID {preproc_id} deleted but was not in Done state"
                        ),
                    );
                }
                Err(e) => {
                    MetricedError::handle_unreturnable_error(op_tag, Some(req_id), e);
                }
            }
            key_gen_background(
                meta_permit,
                token,
                &req_id,
                &preproc_id,
                &epoch_id,
                meta_store,
                crypto_storage,
                sk,
                params,
                internal_keyset_config,
                eip712_domain,
                extra_data,
                op_tag,
            )
            .await;
            // Cleanup runs on every termination (normal completion, error, or abort).
            ongoing.lock().await.remove(&preproc_id);
        }
        .instrument(tracing::Span::current()),
    );

    Ok(Response::new(Empty {}))
}

/// Implementation of the get_key_gen_result endpoint
pub async fn get_key_gen_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
    insecure: bool,
) -> Result<Response<KeyGenResult>, MetricedError> {
    // Retrieve the correct tag
    let op_tag = if insecure {
        OP_INSECURE_KEYGEN_RESULT
    } else {
        OP_KEYGEN_RESULT
    };
    let request_id =
        parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::KeyGenResponse)
            .map_err(|e| MetricedError::new(op_tag, None, e, tonic::Code::InvalidArgument))?;

    tracing::debug!("Received get key gen result request with id {}", request_id);

    let key_gen_res = retrieve_from_meta_store(&service.key_meta_map, &request_id, op_tag).await?;
    match key_gen_res.as_ref() {
        KeyGenMetadata::Current(res) => {
            if request_id != res.key_id {
                return Err(MetricedError::new(
                    op_tag,
                    Some(request_id),
                    anyhow::anyhow!(
                        "Request key ID mismatch: expected {}, got {}",
                        request_id,
                        res.key_id
                    ),
                    tonic::Code::Internal,
                ));
            }
            let key_digests = res
                .key_digest_map
                .iter()
                .sorted_by_key(|x| x.0)
                .map(|(key, digest)| KeyDigest {
                    key_type: key.to_string(),
                    digest: digest.clone(),
                })
                .collect::<Vec<_>>();

            Ok(Response::new(KeyGenResult {
                request_id: Some(request_id.into()),
                preprocessing_id: Some(res.preprocessing_id.into()),
                key_digests,
                external_signature: res.external_signature.clone(),
            }))
        }
        KeyGenMetadata::LegacyV0(_res) => {
            tracing::warn!(
                "Legacy key generation result for request ID: {}",
                request_id
            );
            // Because this is a legacy result and the call path will not reach here
            // (because a restart is needed to upgrade to the new version and the meta store is deleted from RAM),
            // we just return empty values for the fields below.
            Ok(Response::new(KeyGenResult {
                request_id: Some(request_id.into()),
                preprocessing_id: None,
                // we do not attempt to convert the legacy key digest map
                // because it does not match the format to the current one
                // since no domain separation is used
                key_digests: Vec::new(),
                external_signature: vec![],
            }))
        }
    }
}

pub async fn abort_key_gen_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<Empty>, MetricedError> {
    let preproc_id = parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::KeyGenAbort)
        .map_err(|e| MetricedError::new(OP_KEYGEN_ABORT, None, e, tonic::Code::InvalidArgument))?;
    match service.ongoing_key_gen.lock().await.remove(&preproc_id) {
        Some(cancellation_token) => {
            // The cancel arm of `tokio::select!` handles abort and clean-up.
            cancellation_token.cancel();
            tracing::info!("Aborted key generation with preprocessing {}", preproc_id);
            Ok(Response::new(Empty {}))
        }
        None => {
            // No keygen task registered for this preproc id; nothing to cancel.
            Err(MetricedError::new(
                OP_KEYGEN_ABORT,
                Some(preproc_id),
                anyhow::anyhow!(
                    "No ongoing key generation found for the supplied preprocessing ID"
                ),
                tonic::Code::NotFound,
            ))
        }
    }
}

/// Background task for key generation. Owns the meta-store permit for the
/// entire lifetime of the request.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn key_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
>(
    permit: MetaStorePermit<KeyGenMetadata>,
    cancel_token: CancellationToken,
    req_id: &RequestId,
    preproc_id: &RequestId,
    epoch_id: &EpochId,
    meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    sk: Arc<PrivateSigKey>,
    params: DKGParams,
    internal_keyset_config: InternalKeySetConfig,
    eip712_domain: Eip712Domain,
    extra_data: Vec<u8>,
    op_tag: &'static str,
) {
    let start = tokio::time::Instant::now();
    match internal_keyset_config.keyset_config() {
        KeySetConfig::Standard(standard_key_set_config) => {
            let outcome = tokio::select! {
                biased; // favor the cancel branch to reduce wasted work on cancellation
                () = cancel_token.cancelled() => Err("Key generation was aborted".to_string()),
                res = async_generate_fhe_keys(
                    &sk,
                    params,
                    standard_key_set_config.to_owned(),
                    req_id,
                    preproc_id,
                    None,
                    eip712_domain,
                    extra_data,
                ) => res.map_err(|e| format!("Failed key generation: {e}")),
            };

            let keygen_result = match outcome {
                Ok(result) => result,
                Err(msg) => {
                    // Purge any partial key material on cancellation
                    if cancel_token.is_cancelled() {
                        crypto_storage.purge_fhe_keys(req_id, epoch_id).await;
                    }
                    let _ = update_err_req_in_meta_store(&meta_store, permit, msg, op_tag).await;
                    return;
                }
            };

            let (pks, key_info) = match keygen_result {
                CentralizedKeyGenResult::Uncompressed(fhe_key_set, key_info) => {
                    (PublicKeySet::Uncompressed(Arc::new(fhe_key_set)), key_info)
                }
                CentralizedKeyGenResult::Compressed(
                    compressed_keyset,
                    compact_public_key,
                    key_info,
                ) => (
                    PublicKeySet::Compressed {
                        compact_public_key: Arc::new(compact_public_key),
                        compressed_keyset: Arc::new(compressed_keyset),
                    },
                    key_info,
                ),
            };
            if let Err(e) = crypto_storage
                .write_fhe_keys(req_id, epoch_id, key_info, pks, meta_store, permit, op_tag)
                .await
            {
                tracing::error!("Failed to write centralized keys for request {req_id}: {e}");
                return;
            }
            tracing::info!("⏱️ Core Event Time for Keygen: {:?}", start.elapsed());
        }
        KeySetConfig::DecompressionOnly => {
            let (from, to) = match internal_keyset_config.get_from_and_to() {
                Ok((from, to)) => (from, to),
                Err(e) => {
                    let _ = update_err_req_in_meta_store(
                        &meta_store,
                        permit,
                        format!("Failed to use decompression key generation parameters: {e}"),
                        op_tag,
                    )
                    .await;
                    return;
                }
            };
            let outcome = tokio::select! {
                biased; // favor the cancel branch to reduce wasted work on cancellation
                () = cancel_token.cancelled() => Err("Key generation was aborted".to_string()),
                res = async_generate_decompression_keys(
                    crypto_storage.clone(),
                    epoch_id,
                    &from,
                    &to,
                ) => res.map_err(|e| format!("Failed decompression key generation: {e}")),
            };
            let decompression_key = match outcome {
                Ok(k) => k,
                Err(msg) => {
                    if cancel_token.is_cancelled() {
                        crypto_storage.purge_fhe_keys(req_id, epoch_id).await;
                    }
                    let _ = update_err_req_in_meta_store(&meta_store, permit, msg, op_tag).await;
                    return;
                }
            };
            let info = match compute_info_decompression_keygen(
                &sk,
                &DSEP_PUBDATA_KEY,
                preproc_id,
                req_id,
                &decompression_key,
                &eip712_domain,
                extra_data,
            ) {
                Ok(info) => info,
                Err(e) => {
                    let _ = update_err_req_in_meta_store(
                        &meta_store,
                        permit,
                        format!("Failed to compute decompression key info: {e}"),
                        op_tag,
                    )
                    .await;
                    return;
                }
            };
            if let Err(e) = crypto_storage
                .inner
                .write_decompression_key(req_id, info, decompression_key, meta_store, permit)
                .await
            {
                tracing::error!(
                    "Failed to write centralized decompression key for request {req_id}: {e}"
                );
                return;
            }
            tracing::info!(
                "⏱️ Core Event Time for decompression Keygen: {:?}",
                start.elapsed()
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{FheParameter, KeyGenPreprocRequest},
        rpc_types::alloy_to_protobuf_domain,
    };
    use rand::SeedableRng;

    use crate::{
        cryptography::signatures::PublicSigKey,
        dummy_domain,
        engine::{
            base::derive_request_id,
            centralized::{
                central_kms::RealCentralizedKms,
                service::{preprocessing_impl, tests::setup_central_test_kms},
            },
        },
        vault::storage::ram::RamStorage,
    };

    use super::*;

    pub(crate) async fn setup_test_kms_with_preproc(
        rng: &mut AesRng,
        preproc_id: &RequestId,
    ) -> (RealCentralizedKms<RamStorage, RamStorage>, PublicSigKey) {
        let (kms, verf_key) = setup_central_test_kms(rng).await;

        // insert a preproc ID
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: Some((*preproc_id).into()),
            context_id: None,
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };

        // Because preprocessing does not do anything useful in the centralized KMS,
        // it is here only to make sure the API is consistent with the threshold KMS,
        // so the grpc call is fast and we do not need to check the result if the call succeeded.
        preprocessing_impl(&kms, tonic::Request::new(preproc_req))
            .await
            .unwrap();
        (kms, verf_key)
    }

    pub(crate) async fn test_standard_keygen(
        kms: &RealCentralizedKms<RamStorage, RamStorage>,
        req_id: &RequestId,
        preproc_id: Option<&RequestId>,
        insecure: bool,
    ) {
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some((*req_id).into()),
            context_id: None,
            preproc_id: preproc_id.map(|id| (*id).into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };
        let _ = key_gen_impl(kms, tonic::Request::new(request), insecure)
            .await
            .unwrap();

        // The result endpoint is non-blocking; poll until the background keygen completes.
        let _res = crate::testing::utils::poll_result_until_ready(|| {
            get_key_gen_result_impl(kms, tonic::Request::new((*req_id).into()), false)
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_sunshine_preproc").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let request_id = derive_request_id("test_keygen_sunshine").unwrap();
        test_standard_keygen(&kms, &request_id, Some(&preproc_id), false).await
    }

    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_insecure_keygen_sunshine_preproc").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let request_id = derive_request_id("test_insecure_keygen_sunshine").unwrap();
        test_standard_keygen(&kms, &request_id, Some(&preproc_id), true).await
    }

    /// The insecure keygen must fail when the preprocessing ID was never registered,
    /// just like the secure keygen.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_keygen_preproc_not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let preproc_id = derive_request_id("test_insecure_keygen_missing_preproc").unwrap();
        let request_id = derive_request_id("test_insecure_keygen_missing_preproc_key").unwrap();

        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: Some(preproc_id.into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };
        let err = key_gen_impl(&kms, tonic::Request::new(request), true)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// The insecure keygen must reject a request without a preprocessing ID.
    #[cfg(feature = "insecure")]
    #[tokio::test]
    async fn insecure_keygen_missing_preproc_id() {
        let mut rng = AesRng::seed_from_u64(42);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let request_id = derive_request_id("test_insecure_keygen_missing_preproc_id").unwrap();
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: None,
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };

        let err = key_gen_impl(&kms, tonic::Request::new(request), true)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// The secure keygen must reject a request without a preprocessing ID.
    #[tokio::test]
    async fn secure_keygen_missing_preproc_id() {
        let mut rng = AesRng::seed_from_u64(42);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let request_id = derive_request_id("test_keygen_missing_preproc_id").unwrap();

        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: None,
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };
        let err = key_gen_impl(&kms, tonic::Request::new(request), false)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_sunshine_preproc").unwrap();
        let (mut kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        kms.set_bucket_size(1);

        let request_id = derive_request_id("test_keygen_sunshine").unwrap();
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: Some(preproc_id.into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };
        let err = key_gen_impl(
            &kms,
            tonic::Request::new(request),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_invalid_arg_preproc_id").unwrap();
        let request_id = derive_request_id("test_keygen_invalid_arg_key_id").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // wrong params
        {
            let request = KeyGenRequest {
                params: Some(12), // wrong param
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                //If we set a preproc_id here, params will be ignored and thus this request wont fail
                preproc_id: None,
                domain: Some(domain.clone()),
                epoch_id: None,
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing request ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: None, // missing
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: None,
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid request ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-id".to_string(),
                }),
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: None,
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid preprocessing ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                preproc_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-preproc-id".to_string(),
                }),
                domain: Some(domain.clone()),
                epoch_id: None,
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: None, // missing
                epoch_id: None,
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid context ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-context-id".to_string(),
                }),
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: None,
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid epoch ID should fail
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-epoch-id".to_string(),
                }),
                extra_data: vec![],
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_already_exists_preproc_id").unwrap();
        let request_id = derive_request_id("test_keygen_already_exists_key_id").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // we try to generate the same key twice
        // it should fail the second time
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain.clone()),
            epoch_id: None,
            extra_data: vec![],
        };
        let _ = key_gen_impl(
            &kms,
            tonic::Request::new(request.clone()),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap();
        let _res = crate::testing::utils::poll_result_until_ready(|| {
            get_key_gen_result_impl(&kms, tonic::Request::new(request_id.into()), false)
        })
        .await
        .unwrap();

        // The first key generation consumed the preprocessing entry, tombstoning
        // it so its ID can no longer be reused. Register a *fresh* preprocessing
        // entry and point a second keygen (with the same key request ID) at it, so
        // the retry fails on the duplicate request ID and not on missing/consumed
        // preprocessing.
        let preproc_id_2 = derive_request_id("test_keygen_already_exists_preproc_id_2").unwrap();
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: Some(preproc_id_2.into()),
            context_id: None,
            domain: Some(domain.clone()),
            epoch_id: None,
            extra_data: vec![],
        };
        preprocessing_impl(&kms, tonic::Request::new(preproc_req))
            .await
            .unwrap();

        let mut duplicate_request = request.clone();
        duplicate_request.preproc_id = Some(preproc_id_2.into());
        let err = key_gen_impl(
            &kms,
            tonic::Request::new(duplicate_request),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_already_exists_preproc_id").unwrap();
        let request_id = derive_request_id("test_keygen_already_exists_key_id").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // try to generate a key twice using the same preprocessing ID
        // the second one should fail with not found because the preprocessing ID is removed after use
        {
            // Execute, emulating a secure key generation, i.e. with "emulated" preprocessing
            test_standard_keygen(&kms, &request_id, Some(&preproc_id), false).await;

            let new_request_id = derive_request_id("test_keygen_already_exists_key_id_2").unwrap();
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some((new_request_id).into()),
                context_id: None,
                preproc_id: Some((preproc_id).into()), // same preproc ID
                domain: Some(domain),
                epoch_id: None,
                extra_data: vec![],
            };
            // this time it should fail
            let err = key_gen_impl(&kms, tonic::Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        // we try to get a key that does not exist
        {
            let bad_key_id = derive_request_id("test_keygen_not_found").unwrap();
            let get_result =
                get_key_gen_result_impl(&kms, Request::new(bad_key_id.into()), false).await;
            assert_eq!(get_result.unwrap_err().code(), tonic::Code::NotFound);
        }
    }

    #[tokio::test]
    async fn abort_not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let preproc_id = derive_request_id("test_central_keygen_abort_not_found").unwrap();

        let err = abort_key_gen_impl(&kms, Request::new(preproc_id.into()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// Preprocessing alone does not register an ongoing key generation, so an abort
    /// targeting only a preproc ID must return NotFound.
    #[tokio::test]
    async fn abort_with_existing_preproc() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id =
            derive_request_id("test_central_keygen_abort_with_existing_preproc").unwrap();
        // setup_test_kms_with_preproc registers a preproc entry in the meta store
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;

        let err = abort_key_gen_impl(&kms, Request::new(preproc_id.into()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }
}
