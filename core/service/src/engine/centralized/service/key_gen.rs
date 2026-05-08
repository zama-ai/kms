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
    MetaStore, add_req_to_meta_store, handle_res, retrieve_from_meta_store,
    update_err_req_in_meta_store,
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
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use threshold_execution::keyset_config::KeySetConfig;
use threshold_execution::tfhe_internals::parameters::DKGParams;
use tokio_util::sync::CancellationToken;

use tokio::sync::{Mutex, RwLock};
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
    let permit = service.rate_limiter.start_keygen(op_tag).await?;
    // TODO add serial lock to have similar flow to threshold case
    // Acquire the serial lock to make sure no other keygen is running concurrently
    // let _guard = service.serial_lock.lock().await;
    let timer = METRICS
        .time_operation(op_tag)
        // Use a constant party ID since this is the central KMS
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();

    let inner = request.into_inner();

    let (
        req_id,
        preproc_id,
        context_id,
        epoch_id,
        dkg_params,
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

    // Check for existence of request preprocessing ID
    // also check that the request ID is not used yet
    // If all is ok write the request ID to the meta store
    // All validation must be done before inserting the request ID
    let (params, permit) = {
        // If we're in insecure mode, we skip removing preprocessed material since it may not exist
        let params = if !insecure {
            let preproc = retrieve_from_meta_store(
                service.preprocessing_meta_store.read().await,
                &preproc_id,
                op_tag,
            )
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
            preproc.dkg_param
        } else {
            dkg_params
        };

        // Ensure that no key already exists for a given request.
        let already_exists = service
            .crypto_storage
            .fhe_keys_exists(&req_id, &epoch_id)
            .await
            .map_err(|e| {
                MetricedError::new(
                    op_tag,
                    Some(req_id),
                    format!("Could not check FHE key existence in storage: {e}"),
                    tonic::Code::Internal,
                )
            })?;
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

        // check that the request ID is not used yet
        // and then insert the request ID only if it's unused
        // all validation must be done before inserting the request ID
        add_req_to_meta_store(&mut service.key_meta_map.write().await, &req_id, op_tag)?;

        (params, permit)
    };

    let meta_store = Arc::clone(&service.key_meta_map);
    let key_meta_store_cancel = Arc::clone(&service.key_meta_map);
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
        service
            .ongoing_key_gen
            .lock()
            .await
            .insert(preproc_id, token.clone());
    }
    let ongoing = Arc::clone(&service.ongoing_key_gen);
    let crypto_storage = service.crypto_storage.clone();
    let crypto_storage_cancel = service.crypto_storage.clone();

    let preproc_meta_store = Arc::clone(&service.preprocessing_meta_store);
    let keygen_background = async move {
        // "Remove" the preprocessing material by deleting its entry from the meta store
        tracing::info!("Deleting preprocessed material with ID {preproc_id} from meta store");
        let handle = {
            let mut meta_store_guard = preproc_meta_store.write().await;
            meta_store_guard.delete(&preproc_id)
        };
        match handle_res(handle, &preproc_id).await {
            Ok(_) => {
                tracing::info!(
                    "Successfully deleted preprocessing ID {preproc_id} after keygen completion for request ID {req_id}"
                );
            }
            Err(e) => {
                MetricedError::handle_unreturnable_error(op_tag, Some(req_id), e);
            }
        }
        key_gen_background(
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
    };
    service.tracker.spawn(
        async move {
            let _timer = timer;
            let _permit = permit;
            run_keygen_with_cancel(
                keygen_background,
                token,
                req_id,
                preproc_id,
                epoch_id,
                ongoing,
                key_meta_store_cancel,
                crypto_storage_cancel,
            )
            .await;
        }
        .instrument(tracing::Span::current()),
    );

    Ok(Response::new(Empty {}))
}

/// Runs the key-generation background future under a cancellation token. If the
/// token is cancelled before the future completes, the key meta store is
/// updated with an `Aborted` error and any partial key material is purged.
///
/// Extracted from `key_gen_impl` so the cancel arm can be exercised
/// deterministically in tests with a pending future.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_keygen_with_cancel<
    Fut: Future<Output = ()>,
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
>(
    keygen_background: Fut,
    token: CancellationToken,
    req_id: RequestId,
    preproc_id: RequestId,
    epoch_id: EpochId,
    ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    key_meta_store_cancel: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    crypto_storage_cancel: CentralizedCryptoMaterialStorage<PubS, PrivS>,
) {
    tokio::select! {
        () = keygen_background => {
            tracing::info!(
                "Key generation of request {} with preproc id {} exiting normally.",
                req_id, preproc_id
            );
            // Remove cancellation token since generation is now done.
            ongoing.lock().await.remove(&preproc_id);
        },
        () = token.cancelled() => {
            MetricedError::handle_unreturnable_error(
                OP_KEYGEN_REQUEST,
                Some(req_id),
                format!(
                    "Key generation background with preprocessing id {} failed since the task got aborted",
                    preproc_id
                ),
            );
            tracing::error!(
                "Key generation of request {} exiting before completion because of an abort request.",
                &req_id
            );
            let mut guarded_meta_store = key_meta_store_cancel.write().await;
            if let Err(e) = guarded_meta_store
                .update(&req_id, Result::Err("Key generation was aborted".to_string()))
            {
                tracing::warn!(
                    "Failed to mark request {req_id} as aborted in the key meta store: {e}"
                );
            }
            crypto_storage_cancel
                .purge_fhe_keys(&req_id, &epoch_id)
                .await;
        }
    }
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

    let key_gen_res =
        retrieve_from_meta_store(service.key_meta_map.read().await, &request_id, op_tag).await?;
    match key_gen_res {
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
                .into_iter()
                .sorted_by_key(|x| x.0)
                .map(|(key, digest)| KeyDigest {
                    key_type: key.to_string(),
                    digest,
                })
                .collect::<Vec<_>>();

            Ok(Response::new(KeyGenResult {
                request_id: Some(request_id.into()),
                preprocessing_id: Some(res.preprocessing_id.into()),
                key_digests,
                external_signature: res.external_signature,
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

/// Background task for key generation
#[allow(clippy::too_many_arguments)]
pub(crate) async fn key_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
>(
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
            let keygen_result = match async_generate_fhe_keys(
                &sk,
                params,
                standard_key_set_config.to_owned(),
                req_id,
                preproc_id,
                None,
                eip712_domain,
                extra_data,
            )
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    let _ = update_err_req_in_meta_store(
                        &mut meta_store.write().await,
                        req_id,
                        format!("Failed key generation: {e}"),
                        op_tag,
                    );
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
                .write_fhe_keys(req_id, epoch_id, key_info, pks, meta_store, op_tag)
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
                        &mut meta_store.write().await,
                        req_id,
                        format!("Failed to use decompression key generation parameters: {e}"),
                        op_tag,
                    );
                    return;
                }
            };
            let decompression_key = match async_generate_decompression_keys(
                crypto_storage.clone(),
                epoch_id,
                &from,
                &to,
            )
            .await
            {
                Ok(decompression_key) => decompression_key,
                Err(e) => {
                    let _ = update_err_req_in_meta_store(
                        &mut meta_store.write().await,
                        req_id,
                        format!("Failed decompression key generation: {e}"),
                        op_tag,
                    );
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
                        &mut meta_store.write().await,
                        req_id,
                        format!("Failed to compute decompression key info: {e}"),
                        op_tag,
                    );
                    return;
                }
            };
            if let Err(e) = crypto_storage
                .inner
                .write_decompression_key(req_id, info, decompression_key, meta_store)
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
        preproc_id: &RequestId,
        insecure: bool,
    ) {
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some((*req_id).into()),
            context_id: None,
            preproc_id: Some((*preproc_id).into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
            extra_data: vec![],
        };
        let _ = key_gen_impl(kms, tonic::Request::new(request), insecure)
            .await
            .unwrap();

        // no need to wait because get result is semi-blocking
        let _res = get_key_gen_result_impl(kms, tonic::Request::new((*req_id).into()), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_sunshine_preproc").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let request_id = derive_request_id("test_keygen_sunshine").unwrap();
        test_standard_keygen(&kms, &request_id, &preproc_id, false).await
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
        let _res = get_key_gen_result_impl(&kms, tonic::Request::new(request_id.into()), false)
            .await
            .unwrap();

        let err = key_gen_impl(
            &kms,
            tonic::Request::new(request.clone()),
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
            test_standard_keygen(&kms, &request_id, &preproc_id, false).await;

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

    /// Drives the cancel arm of `run_keygen_with_cancel` deterministically by
    /// passing a never-completing keygen future, then issues an abort via
    /// `abort_key_gen_impl` and checks that `get_key_gen_result_impl` returns
    /// `Aborted` rather than waiting the full timeout. Mirrors the threshold
    /// `abort_during_key_gen` test that uses `SlowOnlineDistributedKeyGen128`.
    #[tokio::test]
    async fn abort_during_key_gen() {
        use crate::consts::DEFAULT_EPOCH_ID;
        use crate::util::meta_store::add_req_to_meta_store;

        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_central_abort_during_key_gen_preproc").unwrap();
        let req_id = derive_request_id("test_central_abort_during_key_gen_reqid").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;

        // Register the request id in the key meta store so `get_key_gen_result_impl`
        // has a cell to wait on, mirroring what `key_gen_impl` does before spawning.
        add_req_to_meta_store(
            &mut kms.key_meta_map.write().await,
            &req_id,
            OP_KEYGEN_REQUEST,
        )
        .unwrap();

        // Register the cancellation token in `ongoing_key_gen` so `abort_key_gen_impl`
        // finds it, and spawn the cancel-aware task with a pending future so only the
        // cancel arm can fire.
        let token = CancellationToken::new();
        kms.ongoing_key_gen
            .lock()
            .await
            .insert(preproc_id, token.clone());

        let ongoing = Arc::clone(&kms.ongoing_key_gen);
        let key_meta = Arc::clone(&kms.key_meta_map);
        let crypto_storage = kms.crypto_storage.clone();
        let epoch_id = *DEFAULT_EPOCH_ID;
        let task = tokio::spawn(async move {
            run_keygen_with_cancel(
                std::future::pending::<()>(),
                token,
                req_id,
                preproc_id,
                epoch_id,
                ongoing,
                key_meta,
                crypto_storage,
            )
            .await;
        });

        // Abort should succeed and trigger the cancel arm.
        abort_key_gen_impl(&kms, Request::new(preproc_id.into()))
            .await
            .unwrap();
        // Second abort returns NotFound since the token was removed.
        let err = abort_key_gen_impl(&kms, Request::new(preproc_id.into()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Wait for the cancel arm to finish writing the meta store update.
        task.await.unwrap();

        // The key meta store now holds the aborted error, so `get_key_gen_result_impl`
        // returns `Aborted` immediately instead of blocking for the 60s timeout.
        let err = get_key_gen_result_impl(&kms, Request::new(req_id.into()), false)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted);
    }
}
