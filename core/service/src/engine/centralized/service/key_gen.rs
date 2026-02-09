use crate::cryptography::signatures::PrivateSigKey;
use crate::engine::base::{compute_info_decompression_keygen, KeyGenMetadata, DSEP_PUBDATA_KEY};
use crate::engine::centralized::central_kms::{
    async_generate_decompression_keys, async_generate_fhe_keys, CentralizedKms,
};
use crate::engine::keyset_configuration::InternalKeySetConfig;
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::utils::MetricedError;
use crate::engine::validation::{
    parse_grpc_request_id, validate_key_gen_request, RequestIdParsingErr,
};
use crate::util::meta_store::{
    add_req_to_meta_store, handle_res, retrieve_from_meta_store, update_err_req_in_meta_store,
    MetaStore,
};
use crate::vault::storage::crypto_material::CentralizedCryptoMaterialStorage;
use crate::vault::storage::{Storage, StorageExt};
use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use itertools::Itertools;
use kms_grpc::kms::v1::{Empty, KeyDigest, KeyGenRequest, KeyGenResult};
use kms_grpc::{EpochId, RequestId};
use observability::metrics::METRICS;
use observability::metrics_names::{
    CENTRAL_TAG, OP_INSECURE_KEYGEN_REQUEST, OP_INSECURE_KEYGEN_RESULT, OP_KEYGEN_REQUEST,
    OP_KEYGEN_RESULT, TAG_CONTEXT_ID, TAG_EPOCH_ID, TAG_KEY_ID, TAG_PARTY_ID,
};
use std::sync::Arc;
use threshold_fhe::execution::keyset_config::KeySetConfig;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
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
    let permit = service.rate_limiter.start_keygen(op_tag).await?;
    // TODO add serial lock to have similar flow to threshold case
    // Acquire the serial lock to make sure no other keygen is running concurrently
    // let _guard = service.serial_lock.lock().await;
    let mut timer = METRICS
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
    ) = validate_key_gen_request(inner, op_tag)?;
    let metric_tags = vec![
        (TAG_KEY_ID, req_id.to_string()),
        (TAG_CONTEXT_ID, context_id.to_string()),
        (TAG_EPOCH_ID, epoch_id.to_string()),
    ];
    timer.tags(metric_tags.clone());
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

    // Check for existance of request preprocessing ID
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

        // check that the request ID is not used yet
        // and then insert the request ID only if it's unused
        // all validation must be done before inserting the request ID
        add_req_to_meta_store(&mut service.key_meta_map.write().await, &req_id, op_tag)?;

        (params, permit)
    };

    let meta_store = Arc::clone(&service.key_meta_map);
    let crypto_storage = service.crypto_storage.clone();
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

    let preproc_meta_store = Arc::clone(&service.preprocessing_meta_store);
    let handle = service.tracker.spawn(
        async move {
            let _timer = timer;
            let _permit = permit;
            // "Remove" the preprocessing material by deleting its entry from the meta store
            tracing::info!("Deleting preprocessed material with ID {preproc_id} from meta store");
            let handle = {
                let mut meta_store_guard = preproc_meta_store.write().await;
                meta_store_guard.delete(&preproc_id)
            };
            match handle_res(handle, &preproc_id).await {
                Ok(_) => {
                    tracing::info!("Successfully deleted preprocessing ID {preproc_id} after keygen completion for request ID {req_id}");
                },
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
                op_tag,
            )
            .await;
        }
        .instrument(tracing::Span::current()),
    );
    service.thread_handles.write().await.add(handle);

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
    op_tag: &'static str,
) {
    let start = tokio::time::Instant::now();
    {
        // Check if the key already exists
        if crypto_storage
            .read_centralized_fhe_keys(req_id, epoch_id)
            .await
            .is_ok()
        {
            let _ = update_err_req_in_meta_store(
                &mut meta_store.write().await,
                req_id,
                format!("Failed key generation: Key with ID {req_id} already exists!"),
                op_tag,
            );
            return;
        }
    }
    match internal_keyset_config.keyset_config() {
        KeySetConfig::Standard(standard_key_set_config) => {
            let compression_id = match internal_keyset_config.get_compression_id() {
                Ok(compression_id) => compression_id,
                Err(e) => {
                    let _ = update_err_req_in_meta_store(
                        &mut meta_store.write().await,
                        req_id,
                        format!("Failed to use standard key generation parameters: {e}"),
                        op_tag,
                    );
                    return;
                }
            };

            let (fhe_key_set, key_info) = match async_generate_fhe_keys(
                &sk,
                crypto_storage.clone(),
                params,
                standard_key_set_config.to_owned(),
                compression_id,
                req_id,
                preproc_id,
                epoch_id,
                None,
                eip712_domain,
            )
            .await
            {
                Ok((fhe_key_set, key_info)) => (fhe_key_set, key_info),
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

            crypto_storage
                .write_centralized_keys_with_meta_store(
                    req_id,
                    epoch_id,
                    key_info,
                    fhe_key_set,
                    meta_store,
                )
                .await;

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
            crypto_storage
                .write_decompression_key_with_meta_store(
                    req_id,
                    decompression_key,
                    info,
                    meta_store,
                )
                .await;
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
    #[tracing_test::traced_test]
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
}
