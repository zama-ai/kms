use kms_grpc::kms::v1::*;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
pub trait Initiator {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status>;
}

#[tonic::async_trait]
pub trait UserDecryptor {
    async fn user_decrypt(
        &self,
        request: Request<UserDecryptionRequest>,
    ) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<UserDecryptionResponse>, Status>;
}

#[tonic::async_trait]
pub trait PublicDecryptor {
    async fn public_decrypt(
        &self,
        request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, Status>;
}

#[tonic::async_trait]
pub trait KeyGenerator {
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status>;
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
pub trait InsecureKeyGenerator {
    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status>;
}

#[tonic::async_trait]
pub trait KeyGenPreprocessor {
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status>;
}

#[tonic::async_trait]
pub trait CrsGenerator {
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status>;
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
pub trait InsecureCrsGenerator {
    async fn insecure_crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status>;
}

#[tonic::async_trait]
pub trait ContextManager {
    async fn new_kms_context(
        &self,
        request: Request<NewKmsContextRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn destroy_kms_context(
        &self,
        request: Request<DestroyKmsContextRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn new_custodian_context(
        &self,
        request: Request<NewCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn destroy_custodian_context(
        &self,
        request: Request<DestroyCustodianContextRequest>,
    ) -> Result<Response<Empty>, Status>;
}

#[tonic::async_trait]
pub trait BackupOperator {
    async fn get_operator_public_key(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status>;

    async fn custodian_backup_restore(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Empty>, Status>;
}
