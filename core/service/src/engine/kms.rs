use crate::conf::BandwidthBenchmarkConfig;
use crate::engine::Shutdown;
use crate::engine::backup_operator::BackupOperator;
use crate::engine::bandwidth_bench::new_bandwidth_bench_limiter;
use crate::engine::context_manager::ThresholdContextManager;
use crate::engine::service::crs_generator::CrsGenerator;
#[cfg(feature = "insecure")]
use crate::engine::service::crs_generator::InsecureCrsGenerator;
use crate::engine::service::epoch_manager::ThresholdEpochManager;
#[cfg(feature = "insecure")]
use crate::engine::service::key_generator::InsecureKeyGenerator;
use crate::engine::service::key_generator::KeyGenerator;
use crate::engine::service::preprocessor::Preprocessor;
use crate::engine::service::public_decryptor::{PublicDecryptor, SecureNoiseFloodDecryptor};
use crate::engine::service::session::ImmutableSessionMaker;
use crate::engine::service::user_decryptor::{SecureNoiseFloodPartialDecryptor, UserDecryptor};
use crate::retry_loop;
use crate::vault::storage::{Storage, StorageExt};
use algebra::galois_rings::degree_4::ResiduePolyF4Z128;
use algebra::structure_traits::Ring;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use observability::health::HealthState;
use std::sync::Arc;
use threshold_execution::endpoints::keygen::SecureOnlineDistributedKeyGen128;
use threshold_execution::endpoints::reshare_sk::SecureReshareSecretKeys;
use threshold_execution::online::preprocessing::orchestration::producer_traits::SecureSmallProducerFactory;
use threshold_execution::small_execution::prss::RobustSecurePrssInit;
use threshold_execution::zk::ceremony::SecureCeremony;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

type KeyGen = SecureOnlineDistributedKeyGen128<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>;

/// The threshold KMS gRPC service: one party of the MPC network.
pub struct ThresholdKms<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
> {
    pub(crate) epoch_manager:
        ThresholdEpochManager<PubS, PrivS, RobustSecurePrssInit, SecureReshareSecretKeys>,
    pub(crate) user_decryptor: UserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
    pub(crate) decryptor: PublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
    pub(crate) key_generator: KeyGenerator<PubS, PrivS, KeyGen>,
    #[cfg(feature = "insecure")]
    pub(crate) insecure_key_generator: InsecureKeyGenerator<PubS, PrivS, KeyGen>,
    pub(crate) keygen_preprocessor: Preprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
    pub(crate) crs_generator: CrsGenerator<PubS, PrivS, SecureCeremony>,
    #[cfg(feature = "insecure")]
    pub(crate) insecure_crs_generator: InsecureCrsGenerator<PubS, PrivS, SecureCeremony>, // doesn't matter which ceremony we use here
    pub(crate) context_manager: ThresholdContextManager<PubS, PrivS>,
    pub(crate) backup_operator: BackupOperator<PubS, PrivS>,
    pub(crate) session_maker: ImmutableSessionMaker,
    /// Bounds concurrent `bandwidth_benchmark` runs.
    pub(crate) bandwidth_bench_limiter: Arc<Semaphore>,
    /// Caller-input bounds enforced by the `bandwidth_benchmark` endpoint.
    pub(crate) bandwidth_bench_config: BandwidthBenchmarkConfig,
    tracker: Arc<TaskTracker>,
    health: HealthState,
    mpc_abort_handle: JoinHandle<Result<(), anyhow::Error>>,
}

impl<PubS, PrivS> ThresholdKms<PubS, PrivS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
{
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        epoch_manager: ThresholdEpochManager<
            PubS,
            PrivS,
            RobustSecurePrssInit,
            SecureReshareSecretKeys,
        >,
        user_decryptor: UserDecryptor<PubS, PrivS, SecureNoiseFloodPartialDecryptor>,
        decryptor: PublicDecryptor<PubS, PrivS, SecureNoiseFloodDecryptor>,
        key_generator: KeyGenerator<PubS, PrivS, KeyGen>,
        #[cfg(feature = "insecure")] insecure_key_generator: InsecureKeyGenerator<
            PubS,
            PrivS,
            KeyGen,
        >,
        keygen_preprocessor: Preprocessor<SecureSmallProducerFactory<ResiduePolyF4Z128>>,
        crs_generator: CrsGenerator<PubS, PrivS, SecureCeremony>,
        #[cfg(feature = "insecure")] insecure_crs_generator: InsecureCrsGenerator<
            PubS,
            PrivS,
            SecureCeremony,
        >,
        context_manager: ThresholdContextManager<PubS, PrivS>,
        backup_operator: BackupOperator<PubS, PrivS>,
        tracker: Arc<TaskTracker>,
        session_maker: ImmutableSessionMaker,
        bandwidth_bench_config: BandwidthBenchmarkConfig,
        health: HealthState,
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
            health,
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
        let health = self.health.clone();
        let tracker = Arc::clone(&self.tracker);
        let mpc_abort_handle = self.mpc_abort_handle.abort_handle();
        let handle = {
            let new_handle_clone = mpc_abort_handle.clone();
            tokio::task::spawn(async move {
                health.mark_shutting_down().await;
                health
                    .reporter()
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
