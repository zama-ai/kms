use crate::{
    engine::{
        base::{compute_external_signature_preprocessing, retrieve_parameters},
        centralized::central_kms::{CentralizedKms, CentralizedPreprocBucket},
        traits::{BackupOperator, ContextManager},
        validation::{
            parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
        },
    },
    util::meta_store::handle_res_mapping,
    vault::storage::{Storage, StorageExt},
};
use kms_grpc::{
    kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult},
    rpc_types::optional_protobuf_to_alloy_domain,
    utils::tonic_result::ok_or_tonic_abort,
};
use tonic::{Request, Response, Status};

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
) -> Result<Response<Empty>, Status> {
    let inner = request.into_inner();
    let domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;
    let request_id =
        parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::PreprocRequest)?;

    // context_id is not used in the centralized KMS, but we validate it if present
    let _context_id = match &inner.context_id {
        Some(ctx) => Some(parse_proto_request_id(ctx, RequestIdParsingErr::Context)?),
        None => None,
    };

    //Ensure there's no entry in preproc buckets for that request_id
    if service
        .preprocessing_meta_store
        .read()
        .await
        .exists(&request_id)
    {
        return Err(tonic::Status::already_exists(format!(
            "Preprocessing for request ID {request_id} already exists"
        )));
    }

    let _permit = service.rate_limiter.start_preproc().await?;

    // If the entry did not exist before, start the preproc
    // NOTE: We currently consider an existing entry is NOT an error
    let mut preprocessing_meta_store = service.preprocessing_meta_store.write().await;
    ok_or_tonic_abort(
        preprocessing_meta_store.insert(&request_id),
        "Could not insert preprocessing ID into meta store".to_string(),
    )?;

    let params = retrieve_parameters(Some(inner.params))?;
    let sk = service.base_kms.sig_key().map_err(|e| {
        tonic::Status::new(
            tonic::Code::FailedPrecondition,
            format!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
        )
    })?;
    let external_signature = compute_external_signature_preprocessing(&sk, &request_id, &domain)
        .map_err(|e| e.to_string());

    let preproc_bucket = external_signature.map(|external_signature| CentralizedPreprocBucket {
        preprocessing_id: request_id,
        external_signature,
        dkg_param: params,
    });

    ok_or_tonic_abort(
        preprocessing_meta_store.update(&request_id, preproc_bucket),
        "Could not update preprocessing ID in meta store".to_string(),
    )?;
    tracing::warn!(
        "Received a preprocessing request for the central server {} - No action taken",
        request_id
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
) -> Result<Response<KeyGenPreprocResult>, Status> {
    tracing::warn!(
        "Get key generation preprocessing result called on centralized KMS - no action taken"
    );
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::PreprocResponse)?;

    let status = {
        let guarded_meta_store = service.preprocessing_meta_store.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let preproc_data = handle_res_mapping(status, &request_id, "Preprocessing").await?;
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
