use kms_grpc::{kms::v1::*, rpc_types::MetricedError};
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
    ) -> Result<Response<Empty>, MetricedError>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<UserDecryptionResponse>, MetricedError>;
}

#[tonic::async_trait]
pub trait PublicDecryptor {
    async fn public_decrypt(
        &self,
        request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, MetricedError>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, MetricedError>;
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

    #[cfg(feature = "insecure")]
    async fn partial_key_gen_preproc(
        &self,
        request: Request<PartialKeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status>;
    async fn get_all_preprocessing_ids(&self) -> Result<Vec<String>, Status>;
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
pub trait Resharer {
    async fn initiate_resharing(
        &self,
        request: Request<InitiateResharingRequest>,
    ) -> Result<Response<InitiateResharingResponse>, Status>;
    async fn get_resharing_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ResharingResultResponse>, Status>;
}
