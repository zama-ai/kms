use crate::engine::utils::MetricedError;
use kms_grpc::kms::v1::*;
use tonic::{Request, Response, Status};

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
    // Note that the Status is returned, since this call is never directly mapped to the gRPC end-point,
    // but instead used in conjunction with `abort_key_gen_preproc` in [`KeyGenPreprocessor`]
    async fn abort_key_gen(&self, preproc_id: kms_grpc::RequestId) -> Status;
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
    // Note that the Status is returned, since this call is never directly mapped to the gRPC end-point,
    // but instead used in conjunction with `abort_key_gen_preproc` in [`KeyGenPreprocessor`]
    async fn abort_key_gen(&self, preproc_id: kms_grpc::RequestId) -> Status;
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

    /// Insecure (dummy) preprocessing that only records the preprocessing ID
    /// in the meta store, to be consumed by the insecure key generation.
    #[cfg(feature = "insecure")]
    async fn insecure_key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, MetricedError>;

    /// Same as [`Self::get_result`] but for preprocessing started via
    /// [`Self::insecure_key_gen_preproc`] (only the metric tag differs).
    #[cfg(feature = "insecure")]
    async fn get_insecure_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, MetricedError>;

    async fn get_all_preprocessing_ids(&self) -> Result<Vec<String>, MetricedError>;

    async fn abort_key_gen_preproc(
        &self,
        preproc_id: kms_grpc::RequestId,
        key_gen_cancel_res: Status,
    ) -> Result<Response<Empty>, MetricedError>;
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
    async fn abort_crs_gen(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<Empty>, MetricedError>;
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
    async fn abort_crs_gen(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<Empty>, MetricedError>;
}
