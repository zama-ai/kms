use crate::engine::threshold::traits::{
    CrsGenerator, Decryptor, Initiator, KeyGenPreprocessor, KeyGenerator, Reencryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use crate::engine::Shutdown;
use kms_common::retry_loop;
use kms_grpc::kms::v1::*;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

pub struct GenericKms<
    IN: Sync,
    RE: Sync,
    DE: Sync,
    KG: Sync,
    #[cfg(feature = "insecure")] IKG: Sync,
    PP: Sync,
    CG: Sync,
    #[cfg(feature = "insecure")] ICG: Sync,
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
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    tracker: Arc<TaskTracker>,
    health_reporter: Arc<RwLock<HealthReporter>>,
    mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
}

#[cfg(feature = "insecure")]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, IKG: Sync, PP: Sync, CG: Sync, ICG: Sync>
    GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG>
{
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
        tracker: Arc<TaskTracker>,
        health_reporter: Arc<RwLock<HealthReporter>>,
        mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
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
            tracker,
            health_reporter,
            mpc_abort_handle,
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, IKG: Sync, PP: Sync, CG: Sync, ICG: Sync> Shutdown
    for GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG>
{
    async fn shutdown(&self) -> anyhow::Result<()> {
        self.health_reporter
            .write()
            .await
            .set_not_serving::<CoreServiceEndpointServer<Self>>()
            .await;
        tracing::info!("Sat not serving");
        self.tracker.close();
        self.tracker.wait().await;
        // Abort the core service endpoint server.
        self.mpc_abort_handle.abort();
        // Wait for the MPC server to finish. But abort after a while if it doesn't finish as it could be stuck
        let res: anyhow::Result<()> = retry_loop!(
            || async move {
                if !self.mpc_abort_handle.is_finished() {
                    return Err(anyhow::anyhow!("MPC server not done"));
                }
                Ok(())
            },
            100,
            200 // 20 seconds at most
        );
        if let Err(e) = res {
            tracing::error!("Error waiting for MPC server to finish: {:?}", e);
        }
        tracing::info!("Threshold Core service endpoint server shutdown complete.");
        Ok(())
    }
}

#[cfg(feature = "insecure")]
#[allow(clippy::let_underscore_future)]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, IKG: Sync, PP: Sync, CG: Sync, ICG: Sync> Drop
    for GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG>
{
    fn drop(&mut self) {
        // Let the shutdown run in the background
        let _ = self.shutdown();
    }
}

#[cfg(not(feature = "insecure"))]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, PP: Sync, CG: Sync>
    GenericKms<IN, RE, DE, KG, PP, CG>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: IN,
        reencryptor: RE,
        decryptor: DE,
        key_generator: KG,
        keygen_preprocessor: PP,
        crs_generator: CG,
        tracker: Arc<TaskTracker>,
        health_reporter: Arc<RwLock<HealthReporter>>,
        mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
    ) -> Self {
        Self {
            initiator,
            reencryptor,
            decryptor,
            key_generator,
            keygen_preprocessor,
            crs_generator,
            tracker,
            health_reporter,
            mpc_abort_handle,
        }
    }
}

#[tonic::async_trait]
#[cfg(not(feature = "insecure"))]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, PP: Sync, CG: Sync> Shutdown
    for GenericKms<IN, RE, DE, KG, PP, CG>
{
    async fn shutdown(&self) -> anyhow::Result<()> {
        self.health_reporter
            .write()
            .await
            .set_not_serving::<CoreServiceEndpointServer<Self>>()
            .await;
        tracing::info!("Sat not serving");
        self.tracker.close();
        self.tracker.wait().await;
        // Abort the core service endpoint server.
        self.mpc_abort_handle.abort();
        // Wait for the MPC server to finish. But abort after a while if it doesn't finish as it could be stuck
        let res: anyhow::Result<()> = retry_loop!(
            || async move {
                if !self.mpc_abort_handle.is_finished() {
                    return Err(anyhow::anyhow!("MPC server not done"));
                }
                Ok(())
            },
            100,
            200 // 20 seconds at most
        );
        if let Err(e) = res {
            tracing::error!("Error waiting for MPC server to finish: {:?}", e);
        }
        tracing::info!("Threshold Core service endpoint server shutdown complete.");
        Ok(())
    }
}

#[cfg(not(feature = "insecure"))]
#[allow(clippy::let_underscore_future)]
impl<IN: Sync, RE: Sync, DE: Sync, KG: Sync, PP: Sync, CG: Sync> Drop
    for GenericKms<IN, RE, DE, KG, PP, CG>
{
    fn drop(&mut self) {
        // Let the shutdown run in the background
        let _ = self.shutdown();
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
            > CoreServiceEndpoint for GenericKms<IN, RE, DE, KG, PP, CG> $implementations

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
            > CoreServiceEndpoint for GenericKms<IN, RE, DE, KG, IKG, PP, CG, ICG> $implementations
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
