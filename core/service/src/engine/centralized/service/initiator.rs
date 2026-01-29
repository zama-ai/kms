use crate::{
    consts::DEFAULT_MPC_CONTEXT,
    engine::{
        centralized::central_kms::CentralizedKms,
        traits::{BackupOperator, ContextManager},
        validation::{parse_grpc_request_id, parse_optional_grpc_request_id, RequestIdParsingErr},
    },
    vault::storage::{Storage, StorageExt},
};
use kms_grpc::{
    kms::v1::{Empty, NewMpcEpochRequest},
    utils::tonic_result::ok_or_tonic_abort,
    ContextId,
};
use tonic::{Request, Response, Status};

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
    request: Request<NewMpcEpochRequest>,
) -> Result<Response<Empty>, Status> {
    let inner = request.into_inner();
    let epoch_id = parse_optional_grpc_request_id(&inner.epoch_id, RequestIdParsingErr::Init)?;
    let context_id: ContextId = match inner.context_id {
        Some(ctx_id) => parse_grpc_request_id(&ctx_id, RequestIdParsingErr::Init)?,
        None => *DEFAULT_MPC_CONTEXT,
    };

    if !service
        .context_manager
        .mpc_context_exists_and_consistent(&context_id)
        .await?
    {
        return Err(tonic::Status::new(
            tonic::Code::NotFound,
            format!("Context {context_id} not found"),
        ));
    }

    let mut ids = service.epoch_ids.write().await;
    // Check that the system is not already initialized
    if !ids.get_all_request_ids().is_empty() {
        return Err(tonic::Status::new(
            tonic::Code::AlreadyExists,
            "Initialization already complete`".to_string(),
        ));
    }
    ok_or_tonic_abort(
        ids.insert(&epoch_id),
        "Could not insert init ID into meta store".to_string(),
    )?;
    ok_or_tonic_abort(
        ids.update(&epoch_id, Ok(())).map_err(|e| e.to_string()),
        "Could not update init ID in meta store".to_string(),
    )?;
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

        let preproc_req = NewMpcEpochRequest {
            context_id: None,
            epoch_id: Some(req_id.into()),
            previous_epoch: None,
        };
        let result = init_impl(&kms, Request::new(preproc_req)).await;
        let _ = result.unwrap();
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let req_id1 = derive_request_id("test_init_already_exists").unwrap();

        // First initialization should succeed
        let preproc_req1 = NewMpcEpochRequest {
            context_id: None,
            epoch_id: Some(req_id1.into()),
            previous_epoch: None,
        };
        let result1 = init_impl(&kms, Request::new(preproc_req1)).await;
        let _ = result1.unwrap();

        // Second initialization should fail with AlreadyExists
        let preproc_req2 = NewMpcEpochRequest {
            context_id: None,
            epoch_id: Some(req_id1.into()),
            previous_epoch: None,
        };
        let result2 = init_impl(&kms, Request::new(preproc_req2)).await;
        let status = result2.unwrap_err();
        assert_eq!(status.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let (kms, _) = setup_central_test_kms(&mut rng).await;
        let preproc_req = NewMpcEpochRequest {
            context_id: None,
            epoch_id: None,
            previous_epoch: None,
        };
        let result = init_impl(&kms, Request::new(preproc_req)).await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
}
