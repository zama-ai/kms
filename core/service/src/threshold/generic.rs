use tokio::task::AbortHandle;
use tonic::{Request, Response, Status};

use crate::kms::core_service_endpoint_server::CoreServiceEndpoint;
use crate::kms::*;

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

#[tonic::async_trait]
pub trait ZkVerifier {
    async fn verify(&self, request: Request<ZkVerifyRequest>) -> Result<Response<Empty>, Status>;

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ZkVerifyResponse>, Status>;
}

pub struct GenericKms<IN, RE, DE, KG, PP, CG, ZV> {
    initiator: IN,
    reencryptor: RE,
    decryptor: DE,
    key_generator: KG,
    keygen_preprocessor: PP,
    crs_generator: CG,
    zk_verifier: ZV,
    abort_handle: AbortHandle,
}

impl<IN, RE, DE, KG, PP, CG, ZV> GenericKms<IN, RE, DE, KG, PP, CG, ZV> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: IN,
        reencryptor: RE,
        decryptor: DE,
        key_generator: KG,
        keygen_preprocessor: PP,
        crs_generator: CG,
        zk_verifier: ZV,
        abort_handle: AbortHandle,
    ) -> Self {
        Self {
            initiator,
            reencryptor,
            decryptor,
            key_generator,
            keygen_preprocessor,
            crs_generator,
            zk_verifier,
            abort_handle,
        }
    }

    pub fn abort(&self) {
        self.abort_handle.abort()
    }
}

#[tonic::async_trait]
impl<
        IN: Initiator + Sync + Send + 'static,
        RE: Reencryptor + Sync + Send + 'static,
        DE: Decryptor + Sync + Send + 'static,
        KG: KeyGenerator + Sync + Send + 'static,
        PP: KeyGenPreprocessor + Sync + Send + 'static,
        CG: CrsGenerator + Sync + Send + 'static,
        ZV: ZkVerifier + Sync + Send + 'static,
    > CoreServiceEndpoint for GenericKms<IN, RE, DE, KG, PP, CG, ZV>
{
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        self.initiator.init(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.keygen_preprocessor.key_gen_preproc(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_preproc_status(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        self.keygen_preprocessor.get_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        self.key_generator.key_gen(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        self.key_generator.get_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.reencryptor.reencrypt(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        self.reencryptor.get_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.decryptor.decrypt(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        self.decryptor.get_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        self.crs_generator.crs_gen(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        self.crs_generator.get_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn zk_verify(
        &self,
        request: Request<ZkVerifyRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.zk_verifier.verify(request).await
    }

    async fn get_zk_verify_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ZkVerifyResponse>, Status> {
        self.zk_verifier.get_result(request).await
    }
}
