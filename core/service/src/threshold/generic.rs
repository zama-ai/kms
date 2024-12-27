use crate::rpc::base::Shutdown;
use kms_grpc::kms::core_service_endpoint_server::CoreServiceEndpoint;
use kms_grpc::kms::*;
use std::{collections::HashMap, sync::Arc};
use tokio::{sync::Mutex, task::AbortHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
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

pub struct GenericKms<
    IN,
    RE,
    DE,
    KG,
    #[cfg(feature = "insecure")] IKG,
    PP,
    CG,
    #[cfg(feature = "insecure")] ICG,
    ZV,
> {
    initiator: IN,
    reencryptor: RE,
    decryptor: DE,
    key_generator: KG,
    #[cfg(feature = "insecure")]
    insecure_key_generator: IKG,
    keygen_preprocessor: PP,
    crs_generator: CG,
    #[cfg(feature = "insecure")]
    insecure_crs_generator: ICG,
    proven_ct_verifier: ZV,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    tracker: Arc<TaskTracker>,
    // List of slow events to be cancelled when requesting a shut down.
    slow_events: Arc<Mutex<HashMap<RequestId, CancellationToken>>>, // todo remove tokens when the operation is done
    ddec_abort_handle: AbortHandle,
}

#[cfg(feature = "insecure")]
impl<IN, RE, DE, KG, IKG, PP, CG, ICG, ZV> GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG, ZV> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: IN,
        reencryptor: RE,
        decryptor: DE,
        key_generator: KG,
        insecure_key_generator: IKG,
        keygen_preprocessor: PP,
        crs_generator: CG,
        insecure_crs_generator: ICG,
        proven_ct_verifier: ZV,
        tracker: Arc<TaskTracker>,
        slow_events: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
        ddec_abort_handle: AbortHandle,
    ) -> Self {
        Self {
            initiator,
            reencryptor,
            decryptor,
            key_generator,
            insecure_key_generator,
            keygen_preprocessor,
            crs_generator,
            insecure_crs_generator,
            proven_ct_verifier,
            tracker,
            slow_events,
            ddec_abort_handle,
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        IN: Sync,
        RE: Sync,
        DE: Sync,
        KG: Sync,
        IKG: Sync,
        PP: Sync,
        CG: Sync,
        ICG: Sync,
        ZV: Sync,
    > Shutdown for GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG, ZV>
{
    async fn shutdown(&self) -> anyhow::Result<()> {
        let slow_events = self.slow_events.lock().await;
        self.ddec_abort_handle.abort();
        for event in slow_events.values() {
            event.cancel();
        }
        self.tracker.close();
        self.tracker.wait().await;
        // TODO add health end points to this
        Ok(())
    }
}

#[cfg(not(feature = "insecure"))]
impl<IN, RE, DE, KG, PP, CG, ZV> GenericKms<IN, RE, DE, KG, PP, CG, ZV> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: IN,
        reencryptor: RE,
        decryptor: DE,
        key_generator: KG,
        keygen_preprocessor: PP,
        crs_generator: CG,
        proven_ct_verifier: ZV,
        tracker: Arc<TaskTracker>,
        slow_events: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
        ddec_abort_handle: AbortHandle,
    ) -> Self {
        Self {
            initiator,
            reencryptor,
            decryptor,
            key_generator,
            keygen_preprocessor,
            crs_generator,
            proven_ct_verifier,
            tracker,
            slow_events,
            ddec_abort_handle,
        }
    }
}

#[tonic::async_trait]
#[cfg(not(feature = "insecure"))]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, PP: Sync, CG: Sync, ZV: Sync> Shutdown
    for GenericKms<IN, RE, DE, KG, PP, CG, ZV>
{
    async fn shutdown(&self) -> anyhow::Result<()> {
        let slow_events = self.slow_events.lock().await;
        self.ddec_abort_handle.abort();
        for event in slow_events.values() {
            event.cancel();
        }
        self.tracker.close();
        self.tracker.wait().await;
        // TODO add health end points to this
        Ok(())
    }
}

macro_rules! impl_endpoint {
    { impl CoreServiceEndpoint $implementations:tt } => {
        #[cfg(not(feature="insecure"))]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                RE: Reencryptor + Sync + Send + 'static,
                DE: Decryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                ZV: ProvenCtVerifier + Sync + Send + 'static,
            > CoreServiceEndpoint for GenericKms<IN, RE, DE, KG, PP, CG, ZV> $implementations

        #[cfg(feature="insecure")]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                RE: Reencryptor + Sync + Send + 'static,
                DE: Decryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                IKG: InsecureKeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                ICG: InsecureCrsGenerator + Sync + Send + 'static,
                ZV: ProvenCtVerifier + Sync + Send + 'static,
            > CoreServiceEndpoint for GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG, ZV> $implementations
    }
}

impl_endpoint! {
    impl CoreServiceEndpoint {
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
        async fn verify_proven_ct(
            &self,
            request: Request<VerifyProvenCtRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.proven_ct_verifier.verify(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_verify_proven_ct_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<VerifyProvenCtResponse>, Status> {
            self.proven_ct_verifier.get_result(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            self.insecure_key_generator.insecure_key_gen(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            self.insecure_key_generator.get_result(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            self.insecure_crs_generator.insecure_crs_gen(request).await
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            self.insecure_crs_generator.get_result(request).await
        }

    }
}
