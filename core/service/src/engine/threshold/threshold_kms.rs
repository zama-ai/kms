use crate::engine::Shutdown;
use crate::retry_loop;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;
use tonic_health::server::HealthReporter;

pub struct ThresholdKms<
    IN: Sync,
    UD: Sync,
    PD: Sync,
    KG: Sync,
    #[cfg(feature = "insecure")] IKG: Sync,
    PP: Sync,
    CG: Sync,
    #[cfg(feature = "insecure")] ICG: Sync,
    CM: Sync,
    BO: Sync,
> {
    pub(crate) initiator: IN,
    pub(crate) user_decryptor: UD,
    pub(crate) decryptor: PD,
    pub(crate) key_generator: KG,
    #[cfg(feature = "insecure")]
    pub(crate) insecure_key_generator: IKG,
    pub(crate) keygen_preprocessor: PP,
    pub(crate) crs_generator: CG,
    #[cfg(feature = "insecure")]
    pub(crate) insecure_crs_generator: ICG,
    pub(crate) context_manager: CM,
    pub(crate) backup_operator: BO,
    tracker: Arc<TaskTracker>,
    health_reporter: HealthReporter,
    mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
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
        BO: Sync,
    > ThresholdKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM, BO>
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
        backup_operator: BO,
        tracker: Arc<TaskTracker>,
        health_reporter: HealthReporter,
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
            backup_operator,
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
        BO: Sync,
    > Shutdown for ThresholdKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM, BO>
{
    fn shutdown(&self) -> anyhow::Result<JoinHandle<()>> {
        let health_reporter = self.health_reporter.clone();
        let tracker = Arc::clone(&self.tracker);
        let mpc_abort_handle = self.mpc_abort_handle.abort_handle();
        let handle = {
            let new_handle_clone = mpc_abort_handle.clone();
            tokio::task::spawn(async move {
                health_reporter
                    .set_not_serving::<CoreServiceEndpointServer<Self>>()
                    .await;
                tracing::info!("Sat not serving");
                tracker.close();
                tracker.wait().await;
                mpc_abort_handle.abort();
                let res: anyhow::Result<()> = retry_loop!(
                    || {
                        let new_handle_clone = new_handle_clone.clone();
                        async move {
                            if !new_handle_clone.is_finished() {
                                return Err(anyhow::anyhow!("MPC server not done"));
                            }
                            Ok(())
                        }
                    },
                    100,
                    200
                );
                if let Err(e) = res {
                    tracing::error!("Error waiting for MPC server to finish: {:?}", e);
                }
                tracing::info!("Threshold Core service endpoint server shutdown complete.");
            })
        };
        Ok(handle)
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
        BO: Sync,
    > Drop for ThresholdKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM, BO>
{
    fn drop(&mut self) {
        // Start the shutdown and let it finish in the background
        let _ = self.shutdown();
    }
}

#[cfg(not(feature = "insecure"))]
impl<IN: Sync, UD: Sync, PD: Sync, KG: Sync, PP: Sync, CG: Sync, CM: Sync, BO: Sync>
    ThresholdKms<IN, UD, PD, KG, PP, CG, CM, BO>
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
        backup_operator: BO,
        tracker: Arc<TaskTracker>,
        health_reporter: HealthReporter,
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
            backup_operator,
            tracker,
            health_reporter,
            mpc_abort_handle,
        }
    }
}

#[tonic::async_trait]
#[cfg(not(feature = "insecure"))]
impl<IN: Sync, UD: Sync, PD: Sync, KG: Sync, PP: Sync, CG: Sync, CM: Sync, BO: Sync> Shutdown
    for ThresholdKms<IN, UD, PD, KG, PP, CG, CM, BO>
{
    fn shutdown(&self) -> anyhow::Result<JoinHandle<()>> {
        let health_reporter = self.health_reporter.clone();
        let tracker = Arc::clone(&self.tracker);
        let mpc_abort_handle = self.mpc_abort_handle.abort_handle();
        let handle = {
            let new_handle_clone = mpc_abort_handle.clone();
            tokio::task::spawn(async move {
                health_reporter
                    .set_not_serving::<CoreServiceEndpointServer<Self>>()
                    .await;
                tracing::info!("Sat not serving");
                tracker.close();
                tracker.wait().await;
                mpc_abort_handle.abort();
                let res: anyhow::Result<()> = retry_loop!(
                    || {
                        let new_handle_clone = new_handle_clone.clone();
                        async move {
                            if !new_handle_clone.is_finished() {
                                return Err(anyhow::anyhow!("MPC server not done"));
                            }
                            Ok(())
                        }
                    },
                    100,
                    200
                );
                if let Err(e) = res {
                    tracing::error!("Error waiting for MPC server to finish: {:?}", e);
                }
                tracing::info!("Threshold Core service endpoint server shutdown complete.");
            })
        };
        Ok(handle)
    }
}

#[cfg(not(feature = "insecure"))]
#[allow(clippy::let_underscore_future)]
impl<IN: Sync, UD: Sync, PD: Sync, KG: Sync, PP: Sync, CG: Sync, CM: Sync, BO: Sync> Drop
    for ThresholdKms<IN, UD, PD, KG, PP, CG, CM, BO>
{
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
