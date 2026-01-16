use crate::engine::utils::MetricedError;
use kms_grpc::kms::v1::*;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
pub trait Initiator {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, MetricedError>;
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
    async fn key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, MetricedError>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, MetricedError>;
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
pub trait InsecureKeyGenerator {
    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, MetricedError>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, MetricedError>;
}

#[tonic::async_trait]
pub trait KeyGenPreprocessor {
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    #[cfg(feature = "insecure")]
    async fn partial_key_gen_preproc(
        &self,
        request: Request<PartialKeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, MetricedError>;
    async fn get_all_preprocessing_ids(&self) -> Result<Vec<String>, MetricedError>;
}

#[tonic::async_trait]
pub trait CrsGenerator {
    async fn crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, MetricedError>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, MetricedError>;
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
pub trait InsecureCrsGenerator {
    async fn insecure_crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, MetricedError>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, MetricedError>;
}

#[tonic::async_trait]
pub trait Resharer {
    // TODO(#2868)
    async fn initiate_resharing(
        &self,
        request: Request<InitiateResharingRequest>,
    ) -> Result<Response<InitiateResharingResponse>, Status>;
    async fn get_resharing_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ResharingResultResponse>, Status>;
}
