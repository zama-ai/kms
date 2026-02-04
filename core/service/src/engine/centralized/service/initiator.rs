use crate::{
    engine::{
        centralized::central_kms::CentralizedKms,
        traits::{BackupOperator, ContextManager},
        utils::MetricedError,
        validation::validate_init_req,
    },
    util::meta_store::{add_req_to_meta_store, update_req_in_meta_store},
    vault::storage::{Storage, StorageExt},
};
use kms_grpc::kms::v1::{Empty, InitRequest};
use observability::metrics_names::OP_INIT;
use tonic::{Request, Response};

/// Initializes the centralized KMS service.
///
/// This is purely a dummy implementation since no initialization is needed for the centralized KMS.
/// Still, the logic here follows the same pattern as the threshold KMS for consistency.
/// Thus initialization is only allowed once and the request ID supplied in [`InitRequest`] must be valid.
///
/// # Arguments
/// - `service`: Reference to the `RealCentralizedKms` instance.
/// - `request`: The gRPC request containing an `InitRequest`.
///
/// # Returns
/// Returns a `Result` containing a gRPC `Response` with an empty payload on success,
/// or a gRPC `Status` error on failure.
///
/// # Errors
/// - Returns `Status::AlreadyExists` if the system is already initialized.
/// - Returns `Status::InvalidArgument` if the request ID is missing or invalid.
/// - Returns other `Status` errors if insertion or update of the init ID fails.
///
/// # Tracing
/// Logs a warning when initialization is called on a centralized KMS, indicating no action is taken.
pub async fn init_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<InitRequest>,
) -> Result<Response<Empty>, MetricedError> {
    let inner = request.into_inner();
    let (context_id, epoch_id) = validate_init_req(&inner).map_err(|e| {
        MetricedError::new(
            OP_INIT,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })?;

    if !service
        .context_manager
        .mpc_context_exists_and_consistent(&context_id)
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_INIT,
                Some(context_id.into()),
                anyhow::anyhow!("Could not validate context consistency: {e}"),
                e.code(),
            )
        })?
    {
        return Err(MetricedError::new(
            OP_INIT,
            Some(context_id.into()),
            format!("Context {context_id} not found"),
            tonic::Code::NotFound,
        ));
    }

    // Check that the system is not already initialized
    {
        if !service
            .epoch_ids
            .read()
            .await
            .get_all_request_ids()
            .is_empty()
        {
            return Err(MetricedError::new(
                OP_INIT,
                Some(context_id.into()),
                "Initialization already complete`".to_string(),
                tonic::Code::AlreadyExists,
            ));
        }
    }
    add_req_to_meta_store(
        &mut service.epoch_ids.write().await,
        &epoch_id.into(),
        OP_INIT,
    )?;
    update_req_in_meta_store::<(), anyhow::Error>(
        &mut service.epoch_ids.write().await,
        &epoch_id.into(),
        Ok(()),
        OP_INIT,
    );
    tracing::warn!(
        "Init called on centralized KMS with ID {} - no action taken",
        epoch_id
    );
    Ok(Response::new(Empty {}))
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use super::*;
    use crate::engine::{
        base::derive_request_id, centralized::service::tests::setup_central_test_kms,
    };

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let req_id = derive_request_id("test_init_sunshine").unwrap();

        let preproc_req = InitRequest {
            request_id: Some((req_id).into()),
            context_id: None,
        };
        let result = init_impl(&kms, Request::new(preproc_req)).await;
        let _ = result.unwrap();
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let req_id1 = derive_request_id("test_init_already_exists_1").unwrap();
        let req_id2 = derive_request_id("test_init_already_exists_2").unwrap();

        // First initialization should succeed
        let preproc_req1 = InitRequest {
            request_id: Some(req_id1.into()),
            context_id: None,
        };
        let result1 = init_impl(&kms, Request::new(preproc_req1)).await;
        let _ = result1.unwrap();

        // Second initialization should fail with AlreadyExists
        let preproc_req2 = InitRequest {
            request_id: Some(req_id2.into()),
            context_id: None,
        };
        let result2 = init_impl(&kms, Request::new(preproc_req2)).await;
        let status = result2.unwrap_err();
        assert_eq!(status.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let preproc_req = InitRequest {
            request_id: None,
            context_id: None,
        };
        let result = init_impl(&kms, Request::new(preproc_req)).await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
}
