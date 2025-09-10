use kms_grpc::{
    kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult},
    rpc_types::optional_protobuf_to_alloy_domain,
    utils::tonic_result::ok_or_tonic_abort,
};
use tonic::{Request, Response, Status};

use crate::{
    engine::{
        base::compute_external_signature_preprocessing,
        centralized::central_kms::RealCentralizedKms,
        validation::{
            parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
        },
    },
    util::meta_store::handle_res_mapping,
    vault::storage::Storage,
};

/// Dummy method only here to ensure consistency with the threshold KMS interface
pub async fn preprocessing_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<KeyGenPreprocRequest>,
) -> Result<Response<Empty>, Status> {
    let _permit = service.rate_limiter.start_preproc().await?;
    let inner = request.into_inner();
    let domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;
    let request_id =
        parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::PreprocRequest)?;
    //Ensure there's no entry in preproc buckets for that request_id
    let entry_exists = {
        let ids = service.prepreocessing_ids.read().await;
        ids.exists(&request_id)
    };
    // If the entry did not exist before, start the preproc
    // NOTE: We currently consider an existing entry is NOT an error
    if !entry_exists {
        let mut ids = service.prepreocessing_ids.write().await;
        ok_or_tonic_abort(
            ids.insert(&request_id),
            "Could not insert preprocessing ID into meta store".to_string(),
        )?;
        ok_or_tonic_abort(
            ids.update(
                &request_id,
                compute_external_signature_preprocessing(
                    &service.base_kms.sig_key,
                    &request_id,
                    &domain,
                )
                .map_err(|e| e.to_string()),
            ),
            "Could not update preprocessing ID in meta store".to_string(),
        )?;
        tracing::warn!(
            "Received a preprocessing request for the central server {} - No action taken",
            request_id
        );
        Ok(Response::new(Empty {}))
    } else {
        Err(tonic::Status::already_exists(format!(
            "Preprocessing for request ID {request_id} already exists"
        )))
    }
}

/// Dummy method only here to ensure consistency with the threshold KMS interface
pub async fn get_reprocessing_res_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<v1::RequestId>,
) -> Result<Response<KeyGenPreprocResult>, Status> {
    tracing::warn!(
        "Get key generation preprocessing result called on centralized KMS - no action taken"
    );
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::PreprocResponse)?;

    let status = {
        let guarded_meta_store = service.prepreocessing_ids.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let preproc_data = handle_res_mapping(status, &request_id, "Preprocessing").await?;
    Ok(Response::new(KeyGenPreprocResult {
        preprocessing_id: Some(request_id.into()),
        external_signature: preproc_data,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cryptography::internal_crypto_types::PublicSigKey,
        dummy_domain,
        engine::{
            base::{derive_request_id, tests::recover_address},
            centralized::service::tests::setup_central_test_kms,
        },
    };
    use k256::ecdsa::SigningKey;
    use kms_grpc::{
        kms::v1::FheParameter, rpc_types::alloy_to_protobuf_domain,
        solidity_types::PrepKeygenVerification,
    };
    #[tokio::test]
    async fn test_preprocessing_sunshine() {
        let tempdir = tempfile::tempdir().unwrap();
        let kms = setup_central_test_kms(Some(tempdir.path())).await;
        let verf_key =
            PublicSigKey::new(SigningKey::verifying_key(kms.base_kms.sig_key.sk()).to_owned());
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
        let get_result = get_reprocessing_res_impl(&kms, Request::new(preproc_req_id.into())).await;
        assert!(get_result.is_ok());
        let actual_address = alloy_signer::utils::public_key_to_address(verf_key.pk());
        let inner_res = get_result.unwrap().into_inner();
        let sol_struct =
            PrepKeygenVerification::new(&inner_res.preprocessing_id.unwrap().try_into().unwrap());
        assert_eq!(
            recover_address(sol_struct, &domain, &inner_res.external_signature),
            actual_address
        );
    }

    #[tokio::test]
    async fn test_preprocessing_already_exists() {
        let tempdir = tempfile::tempdir().unwrap();
        let kms = setup_central_test_kms(Some(tempdir.path())).await;
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
    async fn test_preprocessing_missing_domain() {
        let tempdir = tempfile::tempdir().unwrap();
        let kms = setup_central_test_kms(Some(tempdir.path())).await;
        let preproc_req_id = derive_request_id("test_preprocessing_impl_missing_domain").unwrap();
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

    #[tokio::test]
    async fn test_preprocessing_missing_request_id() {
        let tempdir = tempfile::tempdir().unwrap();
        let kms = setup_central_test_kms(Some(tempdir.path())).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: None, // Missing request_id
            context_id: None,
            domain: Some(domain),
            epoch_id: None,
        };
        let result = preprocessing_impl(&kms, Request::new(preproc_req))
            .await
            .err()
            .unwrap();
        assert_eq!(result.code(), tonic::Code::InvalidArgument);
    }
}
