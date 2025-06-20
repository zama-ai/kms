use crate::engine::threshold::traits::{
    ContextManager, CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator, PublicDecryptor,
    UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use crate::engine::Shutdown;
use crate::retry_loop;
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
    UD: Sync,
    PD: Sync,
    KG: Sync,
    #[cfg(feature = "insecure")] IKG: Sync,
    PP: Sync,
    CG: Sync,
    #[cfg(feature = "insecure")] ICG: Sync,
    CM: Sync,
> {
    initiator: IN,
    user_decryptor: UD,
    decryptor: PD,
    key_generator: KG,
    #[cfg(feature = "insecure")]
    insecure_key_generator: IKG,
    keygen_preprocessor: PP,
    crs_generator: CG,
    #[cfg(feature = "insecure")]
    insecure_crs_generator: ICG,
    context_manager: CM,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    tracker: Arc<TaskTracker>,
    health_reporter: Arc<RwLock<HealthReporter>>,
    mpc_abort_handle: JoinHandle<anyhow::Result<()>>,
}

#[cfg(feature = "insecure")]
impl<
        IN: Sync,
        UD: Sync,
        PD: Sync,
        KG: Sync,
        IKG: Sync,
        PP: Sync,
        CG: Sync,
        ICG: Sync,
        CM: Sync,
    > GenericKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: IN,
        user_decryptor: UD,
        decryptor: PD,
        key_generator: KG,
        insecure_key_generator: IKG,
        keygen_preprocessor: PP,
        crs_generator: CG,
        insecure_crs_generator: ICG,
        context_manager: CM,
        tracker: Arc<TaskTracker>,
        health_reporter: Arc<RwLock<HealthReporter>>,
        mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
    ) -> Self {
        Self {
            initiator,
            user_decryptor,
            decryptor,
            key_generator,
            insecure_key_generator,
            keygen_preprocessor,
            crs_generator,
            insecure_crs_generator,
            context_manager,
            tracker,
            health_reporter,
            mpc_abort_handle,
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        IN: Sync,
        UD: Sync,
        PD: Sync,
        KG: Sync,
        IKG: Sync,
        PP: Sync,
        CG: Sync,
        ICG: Sync,
        CM: Sync,
    > Shutdown for GenericKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM>
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
impl<
        IN: Sync,
        UD: Sync,
        PD: Sync,
        KG: Sync,
        IKG: Sync,
        PP: Sync,
        CG: Sync,
        ICG: Sync,
        CM: Sync,
    > Drop for GenericKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM>
{
    fn drop(&mut self) {
        // Let the shutdown run in the background
        let _ = self.shutdown();
    }
}

#[cfg(not(feature = "insecure"))]
impl<IN: Sync, UD: Sync, PD: Sync, KG: Sync, PP: Sync, CG: Sync, CM: Sync>
    GenericKms<IN, UD, PD, KG, PP, CG, CM>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: IN,
        user_decryptor: UD,
        decryptor: PD,
        key_generator: KG,
        keygen_preprocessor: PP,
        crs_generator: CG,
        context_manager: CM,
        tracker: Arc<TaskTracker>,
        health_reporter: Arc<RwLock<HealthReporter>>,
        mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
    ) -> Self {
        Self {
            initiator,
            user_decryptor,
            decryptor,
            key_generator,
            keygen_preprocessor,
            crs_generator,
            context_manager,
            tracker,
            health_reporter,
            mpc_abort_handle,
        }
    }
}

#[tonic::async_trait]
#[cfg(not(feature = "insecure"))]
impl<IN: Sync, UD: Sync, PD: Sync, KG: Sync, PP: Sync, CG: Sync, CM: Sync> Shutdown
    for GenericKms<IN, UD, PD, KG, PP, CG, CM>
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
impl<IN: Sync, UD: Sync, PD: Sync, KG: Sync, PP: Sync, CG: Sync, CM: Sync> Drop
    for GenericKms<IN, UD, PD, KG, PP, CG, CM>
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
                UD: UserDecryptor + Sync + Send + 'static,
                PD: PublicDecryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                CM: ContextManager + Sync + Send + 'static,
            > CoreServiceEndpoint for GenericKms<IN, UD, PD, KG, PP, CG, CM> $implementations

        #[cfg(feature="insecure")]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                UD: UserDecryptor + Sync + Send + 'static,
                PD: PublicDecryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                IKG: InsecureKeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                ICG: InsecureCrsGenerator + Sync + Send + 'static,
                CM: ContextManager + Sync + Send + 'static,
            > CoreServiceEndpoint for GenericKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM> $implementations
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
        async fn get_key_gen_preproc_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenPreprocResult>, Status> {
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
        async fn user_decrypt(
            &self,
            request: Request<UserDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.user_decryptor.user_decrypt(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_user_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<UserDecryptionResponse>, Status> {
            self.user_decryptor.get_result(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn public_decrypt(
            &self,
            request: Request<PublicDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.decryptor.public_decrypt(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_public_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<PublicDecryptionResponse>, Status> {
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

        #[tracing::instrument(skip(self, request))]
        async fn new_kms_context(
            &self,
            request: Request<NewKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.new_kms_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_kms_context(
            &self,
            request: Request<DestroyKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.destroy_kms_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn new_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.new_custodian_context(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.destroy_custodian_context(request).await
        }
    }
}
