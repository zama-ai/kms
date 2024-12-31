use kms_grpc::kms::*;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
pub trait Initiator {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status>;
}

#[tonic::async_trait]
pub trait Reencryptor {
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status>;
}

#[tonic::async_trait]
pub trait Decryptor {
    async fn decrypt(&self, request: Request<DecryptionRequest>)
        -> Result<Response<Empty>, Status>;
    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status>;
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
    ) -> Result<Response<KeyGenPreprocStatus>, Status>;
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
pub trait ProvenCtVerifier {
    async fn verify(
        &self,
        request: Request<VerifyProvenCtRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<VerifyProvenCtResponse>, Status>;
}
