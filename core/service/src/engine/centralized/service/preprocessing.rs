use crate::{
    engine::{
        base::compute_external_signature_preprocessing,
        centralized::central_kms::{CentralizedKms, CentralizedPreprocBucket},
        traits::{BackupOperator, ContextManager},
        utils::MetricedError,
        validation::{parse_proto_request_id, validate_preproc_request, RequestIdParsingErr},
    },
    util::meta_store::{add_req_to_meta_store, retrieve_from_meta_store, update_req_in_meta_store},
    vault::storage::{Storage, StorageExt},
};
use kms_grpc::kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult};
use observability::{
    metrics::METRICS,
    metrics_names::{
        CENTRAL_TAG, OP_KEYGEN_PREPROC_REQUEST, OP_KEYGEN_PREPROC_RESULT, TAG_CONTEXT_ID,
        TAG_EPOCH_ID, TAG_PARTY_ID,
    },
};
use tonic::{Request, Response};

/// Handles preprocessing requests for centralized KMS key generation.
///
/// This is purely a dummy implementation since no initialization is needed for the centralized KMS.
/// Still, the logic here follows the same pattern as the threshold KMS for consistency.
/// That is, it checks if a preprocessing entry for the given request ID already exists. If not, it inserts the request ID and
/// computes the external signature preprocessing, updating the meta store accordingly. If the entry already exists, it returns an
/// `AlreadyExists` error.
///
/// # Arguments
/// * `service` - Reference to the centralized KMS service.
/// * `request` - gRPC request containing the `KeyGenPreprocRequest`.
///
/// # Returns
/// * `Ok(Response<Empty>)` if preprocessing is handled successfully.
/// * `Err(Status)` if the request is invalid or preprocessing already exists.
///
/// # Errors
/// Returns a gRPC `Status::InvalidArgument` if the domain or request ID is missing.
/// Returns a gRPC `Status::AlreadyExists` if preprocessing for the request ID already exists.
///
/// # Note
/// This is a dummy method for interface consistency; no actual preprocessing is performed.
pub async fn preprocessing_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<KeyGenPreprocRequest>,
) -> Result<Response<Empty>, MetricedError> {
    let _permit = service.rate_limiter.start_preproc().await.map_err(|e| {
        MetricedError::new(
            OP_KEYGEN_PREPROC_REQUEST,
            None,
            e,
            tonic::Code::ResourceExhausted,
        )
    })?;
    let mut timer = METRICS
        .time_operation(OP_KEYGEN_PREPROC_REQUEST)
        .tag(TAG_PARTY_ID, CENTRAL_TAG)
        .start();
    let inner = request.into_inner();

    let (req_id, context_id, epoch_id, dkg_param, _key_set_config, eip712_domain) =
        validate_preproc_request(inner).map_err(|e| {
            MetricedError::new(
                OP_KEYGEN_PREPROC_REQUEST,
                None,
                e, // Validation error
                tonic::Code::InvalidArgument,
            )
        })?;
    let metric_tags = vec![
        (TAG_CONTEXT_ID, context_id.as_str()),
        (TAG_EPOCH_ID, epoch_id.as_str()),
    ];
    timer.tags(metric_tags.clone());

    add_req_to_meta_store(
        &mut service.preprocessing_meta_store.write().await,
        &req_id,
        OP_KEYGEN_PREPROC_REQUEST,
    )?;

    let sk = service.base_kms.sig_key().map_err(|e| {
        MetricedError::new(
            OP_KEYGEN_PREPROC_REQUEST,
            Some(req_id),
            e,
            tonic::Code::FailedPrecondition,
        )
    })?;
    let external_signature = compute_external_signature_preprocessing(&sk, &req_id, &eip712_domain)
        .map_err(|e| e.to_string());

    let preproc_bucket = external_signature.map(|external_signature| CentralizedPreprocBucket {
        external_signature,
        dkg_param,
    });

    let _ = update_req_in_meta_store(
        &mut service.preprocessing_meta_store.write().await,
        &req_id,
        preproc_bucket,
        OP_KEYGEN_PREPROC_REQUEST,
    );
    tracing::warn!(
        "Received a preprocessing request for the central server {} - No action taken",
        req_id
    );
    Ok(Response::new(Empty {}))
}

/// Retrieves the result of key generation preprocessing for centralized KMS.
///
/// This function ensures consistency with the threshold KMS interface, but does not perform any actual retrieval.
/// It fetches the preprocessing result from the meta store using the provided request ID and returns a valid external signature.
///
/// # Arguments
/// * `service` - Reference to the centralized KMS service.
/// * `request` - gRPC request containing the `RequestId`.
///
/// # Returns
/// * `Ok(Response<KeyGenPreprocResult>)` with the preprocessing result if found.
/// * `Err(Status)` if the request is invalid or the result is not found.
///
/// # Errors
/// Returns a gRPC `Status::InvalidArgument` if the request ID is missing or invalid.
/// Returns a gRPC error if the preprocessing result cannot be retrieved.
///
/// # Note
/// This is a dummy method for interface consistency; no actual retrieval is performed.
pub async fn get_preprocessing_res_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<v1::RequestId>,
) -> Result<Response<KeyGenPreprocResult>, MetricedError> {
    tracing::warn!(
        "Get key generation preprocessing result called on centralized KMS - no action taken"
    );
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::PreprocResponse)
            .map_err(|e| {
                MetricedError::new(
                    OP_KEYGEN_PREPROC_RESULT,
                    None,
                    e,
                    tonic::Code::InvalidArgument,
                )
            })?;

    let preproc_data = retrieve_from_meta_store(
        service.preprocessing_meta_store.read().await,
        &request_id,
        OP_KEYGEN_PREPROC_RESULT,
    )
    .await?;

    Ok(Response::new(KeyGenPreprocResult {
        preprocessing_id: Some(request_id.into()),
        external_signature: preproc_data.external_signature,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cryptography::signatures::recover_address_from_ext_signature,
        dummy_domain,
        engine::{base::derive_request_id, centralized::service::tests::setup_central_test_kms},
    };
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::FheParameter, rpc_types::alloy_to_protobuf_domain,
        solidity_types::PrepKeygenVerification,
    };
    use rand::SeedableRng;

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let verf_key = kms.base_kms.verf_key();
        let preproc_req_id = derive_request_id("test_preprocessing_sunshine").unwrap();
        let domain = dummy_domain();
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: Some((preproc_req_id).into()),
            context_id: None,
            domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
            epoch_id: None,
        };
        let result = preprocessing_impl(&kms, Request::new(preproc_req)).await;
        assert!(result.is_ok());
        let get_result =
            get_preprocessing_res_impl(&kms, Request::new(preproc_req_id.into())).await;
        assert!(get_result.is_ok());
        let inner_res = get_result.unwrap().into_inner();
        let sol_struct =
            PrepKeygenVerification::new(&inner_res.preprocessing_id.unwrap().try_into().unwrap());
        assert_eq!(
            recover_address_from_ext_signature(&sol_struct, &domain, &inner_res.external_signature)
                .unwrap(),
            verf_key.address()
        );
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (mut kms, _) = setup_central_test_kms(&mut rng).await;
        kms.set_bucket_size(1);

        let preproc_req_id = derive_request_id("test_preprocessing_sunshine").unwrap();
        let domain = dummy_domain();
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: Some((preproc_req_id).into()),
            context_id: None,
            domain: Some(alloy_to_protobuf_domain(&domain).unwrap()),
            epoch_id: None,
        };
        let err = preprocessing_impl(&kms, Request::new(preproc_req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let preproc_req_id = derive_request_id("test_preprocessing_impl_already_exists").unwrap();
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: Some((preproc_req_id).into()),
            context_id: None,
            domain: Some(domain.clone()),
            epoch_id: None,
        };
        // First call should succeed
        let result1 = preprocessing_impl(&kms, Request::new(preproc_req.clone())).await;
        assert!(result1.is_ok());

        // Second call with same request_id should fail with already_exists
        let result2 = preprocessing_impl(&kms, Request::new(preproc_req))
            .await
            .err()
            .unwrap();
        assert_eq!(result2.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let preproc_req_id = derive_request_id("test_preprocessing_impl_missing_domain").unwrap();

        // Missing domain should lead to InvalidArgument
        {
            let preproc_req = KeyGenPreprocRequest {
                params: FheParameter::Test.into(),
                keyset_config: None,
                request_id: Some((preproc_req_id).into()),
                context_id: None,
                domain: None, // Missing domain
                epoch_id: None,
            };
            let result = preprocessing_impl(&kms, Request::new(preproc_req))
                .await
                .err()
                .unwrap();
            assert_eq!(result.code(), tonic::Code::InvalidArgument);
        }

        // missing request_id should lead to InvalidArgument
        {
            let preproc_req = KeyGenPreprocRequest {
                params: FheParameter::Test.into(),
                keyset_config: None,
                request_id: None,
                context_id: None,
                domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
                epoch_id: None,
            };
            let result = preprocessing_impl(&kms, Request::new(preproc_req))
                .await
                .err()
                .unwrap();
            assert_eq!(result.code(), tonic::Code::InvalidArgument);
        }

        // wrong request_id should lead to InvalidArgument
        {
            let preproc_req = KeyGenPreprocRequest {
                params: FheParameter::Test.into(),
                keyset_config: None,
                request_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "xyz".to_string(),
                }),
                context_id: None,
                domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
                epoch_id: None,
            };
            let result = preprocessing_impl(&kms, Request::new(preproc_req))
                .await
                .err()
                .unwrap();
            assert_eq!(result.code(), tonic::Code::InvalidArgument);
        }

        // wrong context ID should lead to InvalidArgument
        {
            let preproc_req = KeyGenPreprocRequest {
                params: FheParameter::Test.into(),
                keyset_config: None,
                request_id: Some(preproc_req_id.into()),
                context_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "xyz".to_string(),
                }),
                domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
                epoch_id: None,
            };
            let result = preprocessing_impl(&kms, Request::new(preproc_req))
                .await
                .err()
                .unwrap();
            assert_eq!(result.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let bad_preproc_id = derive_request_id("test_preprocessing_not_found").unwrap();
        let get_result =
            get_preprocessing_res_impl(&kms, Request::new(bad_preproc_id.into())).await;
        assert_eq!(get_result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // NOTE: it's not possible to have an unavailable error
    // for when getting the response because the preprocessing is instant
}
