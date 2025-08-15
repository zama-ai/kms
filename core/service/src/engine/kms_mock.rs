use crate::engine::traits::{BackupOperator, ContextManager};
use tonic::{Request, Response, Status};

pub(crate) struct DummyContextManager;

#[tonic::async_trait]
impl ContextManager for DummyContextManager {
    async fn new_kms_context(
        &self,
        _request: Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }

    async fn destroy_kms_context(
        &self,
        _request: Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }

    async fn new_custodian_context(
        &self,
        _request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }

    async fn destroy_custodian_context(
        &self,
        _request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }
}

pub(crate) struct DummyBackupOperator;

#[tonic::async_trait]
impl BackupOperator for DummyBackupOperator {
    async fn get_operator_public_key(
        &self,
        _request: Request<kms_grpc::kms::v1::Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::OperatorPublicKey>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::OperatorPublicKey {
            public_key: vec![],
            attestation_document: vec![],
        }))
    }

    async fn custodian_backup_restore(
        &self,
        _request: Request<kms_grpc::kms::v1::Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }
}
