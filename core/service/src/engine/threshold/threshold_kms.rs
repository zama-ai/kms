use crate::conf::BandwidthBenchmarkConfig;
use crate::engine::Shutdown;
use crate::engine::backup_operator::RealBackupOperator;
use crate::engine::context_manager::ThresholdContextManager;
use crate::engine::threshold::bandwidth_bench::new_bandwidth_bench_limiter;
use crate::engine::threshold::service::crs_generator::RealCrsGenerator;
#[cfg(feature = "insecure")]
use crate::engine::threshold::service::crs_generator::RealInsecureCrsGenerator;
use crate::engine::threshold::service::epoch_manager::RealThresholdEpochManager;
#[cfg(feature = "insecure")]
use crate::engine::threshold::service::key_generator::RealInsecureKeyGenerator;
use crate::engine::threshold::service::key_generator::RealKeyGenerator;
use crate::engine::threshold::service::preprocessor::RealPreprocessor;
use crate::engine::threshold::service::public_decryptor::{
    RealPublicDecryptor, SecureNoiseFloodDecryptor,
};
use crate::engine::threshold::service::session::ImmutableSessionMaker;
use crate::engine::threshold::service::user_decryptor::{
    RealUserDecryptor, SecureNoiseFloodPartialDecryptor,
};
use crate::retry_loop;
use crate::vault::storage::{Storage, StorageExt};
use algebra::galois_rings::degree_4::ResiduePolyF4Z128;
use algebra::structure_traits::Ring;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use std::sync::Arc;
use threshold_execution::endpoints::keygen::SecureOnlineDistributedKeyGen128;
use threshold_execution::endpoints::reshare_sk::SecureReshareSecretKeys;
use threshold_execution::online::preprocessing::orchestration::producer_traits::SecureSmallProducerFactory;
use threshold_execution::small_execution::prss::RobustSecurePrssInit;
use threshold_execution::zk::ceremony::SecureCeremony;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;
use tonic_health::server::HealthReporter;

type KeyGen = SecureOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>;

/// The threshold KMS gRPC service: one party of the MPC network.
pub struct ThresholdKms<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
> {
    pub(crate) epoch_manager:
        RealThresholdEpochManager<PubS, PrivS, RobustSecurePrssInit, SecureReshareSecretKeys>,
    pub(crate) user_decryptor: RealUserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
    pub(crate) decryptor: RealPublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
    pub(crate) key_generator: RealKeyGenerator<PubS, PrivS, KeyGen>,
    #[cfg(feature = "insecure")]
    pub(crate) insecure_key_generator: RealInsecureKeyGenerator<PubS, PrivS, KeyGen>,
    pub(crate) keygen_preprocessor: RealPreprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
    pub(crate) crs_generator: RealCrsGenerator<PubS, PrivS, SecureCeremony>,
    #[cfg(feature = "insecure")]
    pub(crate) insecure_crs_generator: RealInsecureCrsGenerator<PubS, PrivS, SecureCeremony>, // doesn't matter which ceremony we use here
    pub(crate) context_manager: ThresholdContextManager<PubS, PrivS>,
    pub(crate) backup_operator: RealBackupOperator<PubS, PrivS>,
    pub(crate) session_maker: ImmutableSessionMaker,
    /// Bounds concurrent `bandwidth_benchmark` runs (the endpoint takes no rate-limiter permit).
    pub(crate) bandwidth_bench_limiter: Arc<Semaphore>,
    /// Caller-input bounds enforced by the `bandwidth_benchmark` endpoint.
    pub(crate) bandwidth_bench_config: BandwidthBenchmarkConfig,
    tracker: Arc<TaskTracker>,
    health_reporter: HealthReporter,
    mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
}

impl<PubS, PrivS> ThresholdKms<PubS, PrivS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
{
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        epoch_manager: RealThresholdEpochManager<
            PubS,
            PrivS,
            RobustSecurePrssInit,
            SecureReshareSecretKeys,
        >,
        user_decryptor: RealUserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
        decryptor: RealPublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
        key_generator: RealKeyGenerator<PubS, PrivS, KeyGen>,
        #[cfg(feature = "insecure")] insecure_key_generator: RealInsecureKeyGenerator<
            PubS,
            PrivS,
            KeyGen,
        >,
        keygen_preprocessor: RealPreprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
        crs_generator: RealCrsGenerator<PubS, PrivS, SecureCeremony>,
        #[cfg(feature = "insecure")] insecure_crs_generator: RealInsecureCrsGenerator<
            PubS,
            PrivS,
            SecureCeremony,
        >,
        context_manager: ThresholdContextManager<PubS, PrivS>,
        backup_operator: RealBackupOperator<PubS, PrivS>,
        tracker: Arc<TaskTracker>,
        session_maker: ImmutableSessionMaker,
        bandwidth_bench_config: BandwidthBenchmarkConfig,
        health_reporter: HealthReporter,
        mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
    ) -> Self {
        Self {
            epoch_manager,
            user_decryptor,
            decryptor,
            key_generator,
            #[cfg(feature = "insecure")]
            insecure_key_generator,
            keygen_preprocessor,
            crs_generator,
            #[cfg(feature = "insecure")]
            insecure_crs_generator,
            context_manager,
            backup_operator,
            tracker,
            session_maker,
            bandwidth_bench_limiter: new_bandwidth_bench_limiter(
                bandwidth_bench_config.max_concurrent_runs,
            ),
            bandwidth_bench_config,
            health_reporter,
            mpc_abort_handle,
        }
    }
}

#[tonic::async_trait]
impl<PubS, PrivS> Shutdown for ThresholdKms<PubS, PrivS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
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
                tracing::trace!("Set not serving");
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

impl<PubS, PrivS> Drop for ThresholdKms<PubS, PrivS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
{
    fn drop(&mut self) {
        // Start the shutdown and let it finish in the background
        let _ = self.shutdown();
    }
}
