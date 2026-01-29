use std::sync::Arc;

use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use kms_grpc::kms::v1::{CrsGenRequest, CrsGenResult, Empty};
use kms_grpc::RequestId;
use observability::metrics::METRICS;
use observability::metrics_names::{
    CENTRAL_TAG, OP_CRS_GEN_REQUEST, OP_CRS_GEN_RESULT, OP_INSECURE_CRS_GEN_REQUEST,
    TAG_CONTEXT_ID, TAG_CRS_ID, TAG_PARTY_ID,
};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::sync::RwLock;
use tonic::{Request, Response};
use tracing::Instrument;

use crate::cryptography::signatures::PrivateSigKey;
use crate::engine::base::CrsGenMetadata;
use crate::engine::centralized::central_kms::{async_generate_crs, CentralizedKms};
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::utils::MetricedError;
use crate::engine::validation::{
    parse_grpc_request_id, validate_crs_gen_request, RequestIdParsingErr,
};
use crate::util::meta_store::{
    add_req_to_meta_store, retrieve_from_meta_store, update_err_req_in_meta_store, MetaStore,
};
use crate::vault::storage::crypto_material::CentralizedCryptoMaterialStorage;
use crate::vault::storage::{Storage, StorageExt};

/// Implementation of the crs_gen endpoint
pub async fn crs_gen_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<CrsGenRequest>,
    insecure: bool,
) -> Result<Response<Empty>, MetricedError> {
    tracing::info!("Received CRS generation request");
    // Retrieve the correct tag
    let op_tag = if insecure {
        OP_INSECURE_CRS_GEN_REQUEST
    } else {
        OP_CRS_GEN_REQUEST
    };

    let permit = service
        .rate_limiter
        .start_crsgen()
        .await
        .map_err(|e| MetricedError::new(op_tag, None, e, tonic::Code::ResourceExhausted))?;
    let mut timer = METRICS
        .time_operation(op_tag)
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();
    let inner = request.into_inner();
    let (req_id, context_id, _witness_dimension, params, eip712_domain) =
        validate_crs_gen_request(inner.clone()).map_err(|e| {
            MetricedError::new(
                op_tag,
                None,
                e, // Validation error
                tonic::Code::InvalidArgument,
            )
        })?;
    let metric_tags = vec![
        (TAG_CRS_ID, req_id.to_string()),
        (TAG_CONTEXT_ID, context_id.to_string()),
    ];
    timer.tags(metric_tags.clone());

    if !service
        .context_manager
        .mpc_context_exists_in_cache(&context_id)
        .await
    {
        return Err(MetricedError::new(
            op_tag,
            Some(req_id),
            anyhow::anyhow!("context at ID {context_id} not found"),
            tonic::Code::NotFound,
        ));
    }

    // check that the request ID is not used yet
    // and then insert the request ID only if it's unused
    // all validation must be done before inserting the request ID
    add_req_to_meta_store(&mut service.crs_meta_map.write().await, &req_id, op_tag)?;

    let meta_store = Arc::clone(&service.crs_meta_map);
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

    let rng = service.base_kms.new_rng().await;

    let handle = service.tracker.spawn(
        async move {
            let _timer = timer;
            let _permit = permit;
            crs_gen_background(
                &req_id,
                rng,
                meta_store,
                crypto_storage,
                sk,
                params,
                eip712_domain,
                inner.max_num_bits,
                op_tag,
            )
            .await;
        }
        .instrument(tracing::Span::current()),
    );
    service.thread_handles.write().await.add(handle);
    Ok(Response::new(Empty {}))
}

/// Implementation of the get_crs_gen_result endpoint
pub async fn get_crs_gen_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
    insecure: bool,
) -> Result<Response<CrsGenResult>, MetricedError> {
    // Retrieve the correct tag
    let op_tag = if insecure {
        OP_INSECURE_CRS_GEN_REQUEST
    } else {
        OP_CRS_GEN_RESULT
    };
    let request_id =
        parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::CrsGenResponse)
            .map_err(|e| MetricedError::new(op_tag, None, e, tonic::Code::InvalidArgument))?;
    tracing::debug!("Received CRS gen result request with id {}", request_id);

    let crs_info =
        retrieve_from_meta_store(service.crs_meta_map.read().await, &request_id, op_tag).await?;

    match crs_info {
        CrsGenMetadata::LegacyV0(_) => {
            // This is a legacy result, we cannot return the crs_digest or external_signature
            // as they're signed using a different SolStruct and hashed using a different domain separator
            tracing::warn!(
                "Received a legacy CRS generation result,
                not returning crs_digest or external_signature"
            );
            // The old SignedPubDataHandleInternal does not store max_num_bits
            // so we have to read it from storage if we want to return it.
            // But because this is a legacy result and the call path will not reach here
            // (because a restart is needed to upgrade to the new version and the meta store is deleted from RAM)
            // it is never needed, so we just return 0 for max_num_bits.
            Ok(Response::new(CrsGenResult {
                request_id: Some(request_id.into()),
                crs_digest: vec![],
                max_num_bits: 0,
                external_signature: vec![],
            }))
        }
        CrsGenMetadata::Current(crs_info) => {
            if request_id != crs_info.crs_id {
                return Err(MetricedError::new(
                    op_tag,
                    Some(request_id),
                    anyhow::anyhow!(
                        "Request ID mismatch: expected {request_id}, got {}",
                        crs_info.crs_id
                    ),
                    tonic::Code::Internal,
                ));
            }

            Ok(Response::new(CrsGenResult {
                request_id: Some(request_id.into()),
                crs_digest: crs_info.crs_digest,
                max_num_bits: crs_info.max_num_bits,
                external_signature: crs_info.external_signature,
            }))
        }
    }
}

/// Background task for CRS generation
#[allow(clippy::too_many_arguments)]
pub(crate) async fn crs_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
>(
    req_id: &RequestId,
    rng: AesRng,
    meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
    crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    sk: Arc<PrivateSigKey>,
    params: DKGParams,
    eip712_domain: Eip712Domain,
    max_number_bits: Option<u32>,
    op_tag: &'static str,
) {
    let start = tokio::time::Instant::now();

    let (pp, crs_info) =
        match async_generate_crs(&sk, params, max_number_bits, eip712_domain, req_id, rng).await {
            Ok((pp, crs_info)) => (pp, crs_info),
            Err(e) => {
                let _ = update_err_req_in_meta_store(
                    &mut meta_store.write().await,
                    req_id,
                    e.to_string(),
                    op_tag,
                );
                return;
            }
        };

    crypto_storage
        .write_crs_with_meta_store(req_id, pp, crs_info, meta_store, op_tag)
        .await;

    tracing::info!("⏱️ Core Event Time for CRS-gen: {:?}", start.elapsed());
    tracing::info!(
        "CRS generation of request {} completed successfully.",
        req_id
    );
}

#[cfg(test)]
mod tests {
    use kms_grpc::{kms::v1::FheParameter, rpc_types::alloy_to_protobuf_domain};
    use rand::SeedableRng;

    use crate::{
        dummy_domain,
        engine::{base::derive_request_id, centralized::service::tests::setup_central_test_kms},
    };

    use super::*;

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let req_id = derive_request_id("test_crs_gen_sunshine").unwrap();
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = CrsGenRequest {
            request_id: Some(req_id.into()),
            context_id: None,
            params: FheParameter::Test.into(),
            domain: Some(domain.clone()),
            max_num_bits: Some(2048),
        };
        let _res = crs_gen_impl(&kms, Request::new(request), true)
            .await
            .unwrap();
        let _ = get_crs_gen_result_impl(&kms, Request::new(req_id.into()), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let req_id = derive_request_id("test_crs_gen_already_exists").unwrap();
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request = CrsGenRequest {
            request_id: Some(req_id.into()),
            context_id: None,
            params: FheParameter::Test.into(),
            domain: Some(domain.clone()),
            max_num_bits: Some(2048),
        };
        let _res = crs_gen_impl(&kms, Request::new(request.clone()), false)
            .await
            .unwrap();
        let err = crs_gen_impl(&kms, Request::new(request), true)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let req_id = derive_request_id("test_crs_gen_invalid_argument").unwrap();
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // wrong params
        {
            let request = CrsGenRequest {
                request_id: Some(req_id.into()),
                context_id: None,
                params: 123, // invalid params
                domain: Some(domain.clone()),
                max_num_bits: None,
            };
            let err = crs_gen_impl(&kms, Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing request ID
        {
            let request = CrsGenRequest {
                request_id: None, // missing
                context_id: None,
                params: FheParameter::Test.into(),
                domain: Some(domain.clone()),
                max_num_bits: None,
            };
            let err = crs_gen_impl(&kms, Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrong request ID format
        {
            let request = CrsGenRequest {
                request_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "not_a_valid_request_id".to_string(),
                }),
                context_id: None,
                params: FheParameter::Test.into(),
                domain: Some(domain.clone()),
                max_num_bits: None,
            };
            let err = crs_gen_impl(&kms, Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let request = CrsGenRequest {
                request_id: Some(req_id.into()),
                context_id: None,
                params: FheParameter::Test.into(),
                domain: None, // missing
                max_num_bits: None,
            };
            let err = crs_gen_impl(&kms, Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid context ID
        {
            let request = CrsGenRequest {
                request_id: Some(req_id.into()),
                context_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "not_a_valid_context_id".to_string(),
                }),
                params: FheParameter::Test.into(),
                domain: Some(domain.clone()),
                max_num_bits: None,
            };
            let err = crs_gen_impl(&kms, Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid max_num_bits
        {
            let request = CrsGenRequest {
                request_id: Some(req_id.into()),
                context_id: None,
                params: FheParameter::Test.into(),
                domain: Some(domain),
                max_num_bits: Some(123), // invalid
            };
            let err = crs_gen_impl(&kms, Request::new(request), false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let bad_req_id = derive_request_id("test_crs_gen_not_found").unwrap();
        let get_result =
            get_crs_gen_result_impl(&kms, Request::new(bad_req_id.into()), false).await;
        assert_eq!(get_result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (mut kms, _) = setup_central_test_kms(&mut rng).await;
        kms.set_bucket_size(1); // set bucket size to 1 to trigger resource exhausted error
        let req_id = derive_request_id("test_crs_gen_resource_exhausted").unwrap();
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        let request = CrsGenRequest {
            request_id: Some(req_id.into()),
            context_id: None,
            params: FheParameter::Test.into(),
            domain: Some(domain),
            max_num_bits: None,
        };
        let err = crs_gen_impl(&kms, Request::new(request), false)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }
}
