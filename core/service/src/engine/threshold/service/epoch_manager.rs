use kms_grpc::{
    kms::v1::{DestroyMpcEpochRequest, Empty, EpochResultResponse, NewMpcEpochRequest, RequestId},
    kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer,
    rpc_types::PrivDataType,
    ContextId, EpochId,
};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::{
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::prss::{PRSSInit, PRSSSetup},
    },
    networking::NetworkMode,
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

use crate::{
    consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT},
    engine::{
        base::{derive_request_id, KeyGenMetadata},
        threshold::service::{
            session::{PRSSSetupCombined, SessionMaker},
            RealThresholdKms,
        },
        traits::EpochManager,
    },
    util::{meta_store::MetaStore, rate_limiter::RateLimiter},
    vault::storage::{
        crypto_material::ThresholdCryptoMaterialStorage, delete_at_request_id,
        read_all_data_versioned, read_versioned_at_request_id, store_versioned_at_request_id,
        Storage, StorageExt,
    },
};

const PRSS_SESSION_COUNTER: u64 = 0;
const RESHARE_Z64_SESSION_COUNTER: u64 = 1;
const RESHARE_Z128_SESSION_COUNTER: u64 = 2;

// The Epoch Manager takes over the role of the Initiator and Resharer
// For now the struct is thus a union of the RealInitiator and RealResharer structs
pub struct RealThresholdEpochManager<
    PrivS: StorageExt + Send + Sync + 'static,
    PubS: Storage + Send + Sync + 'static,
    Init: PRSSInit<ResiduePolyF4Z64> + PRSSInit<ResiduePolyF4Z128>,
> {
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub(crate) session_maker: SessionMaker,
    pub health_reporter: HealthReporter,
    pub base_kms: crate::engine::base::BaseKmsStruct,
    pub reshare_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    pub rate_limiter: RateLimiter,
    pub(crate) _init: PhantomData<Init>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > RealThresholdEpochManager<PrivS, PubS, Init>
{
    /// This will load all PRSS setups from storage into session maker.
    ///
    /// It should be called after [init_legacy_prss_from_storage] so that
    /// if there is a new PRSS under the same epoch ID as a legacy one,
    /// then the legacy one is overwritten.
    pub async fn init_all_prss_from_storage(&self) -> anyhow::Result<()> {
        let all_prss = self.crypto_storage.inner.read_all_prss_info().await?;

        for (epoch_id, prss) in all_prss {
            self.session_maker.add_epoch(epoch_id.into(), prss).await;
            tracing::info!(
                "Loaded PRSS Setup from storage for request ID {}.",
                epoch_id
            );
        }
        Ok(())
    }

    // Question: When can we completely remove this depreacted function ?
    /// This assumes the default context exists.
    /// It will overwrite the PRSS in session maker if it already exists,
    /// so make sure this is called before the normal (non-legacy) initialization.
    #[expect(deprecated)]
    pub async fn init_legacy_prss_from_storage(&self) -> anyhow::Result<()> {
        // TODO(zama-ai/kms-internal#2530) set the correct context ID here.
        let epoch_id = *DEFAULT_EPOCH_ID;
        let context_id = *DEFAULT_MPC_CONTEXT;
        let threshold = self.session_maker.threshold(&context_id).await?;
        let num_parties = self.session_maker.num_parties(&context_id).await?;

        let prss_from_storage = {
            let guarded_private_storage = self.crypto_storage.inner.private_storage.lock().await;
            let prss_128 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z128>>(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z128_ID_{}_{}_{}",
                    epoch_id, num_parties, threshold,
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z128 from file with error: {e}");
            });
            let prss_64 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z64>>(
                &(*guarded_private_storage),
                &derive_request_id(&format!(
                    "PRSSSetup_Z64_ID_{}_{}_{}",
                    epoch_id, num_parties, threshold,
                ))?,
                &PrivDataType::PrssSetup.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to read PRSS Z64 from file with error: {e}");
            });

            (prss_128, prss_64)
        };

        match prss_from_storage {
            (Ok(prss_128), Ok(prss_64)) => {
                self.session_maker
                    .add_epoch(
                        epoch_id,
                        PRSSSetupCombined {
                            prss_setup_z128: prss_128,
                            prss_setup_z64: prss_64,
                            num_parties: num_parties as u8,
                            threshold,
                        },
                    )
                    .await;
            }
            (Err(e), Ok(_)) => return Err(e),
            (Ok(_), Err(e)) => return Err(e),
            (Err(_e), Err(e)) => return Err(e),
        }

        tracing::info!(
            "Loaded PRSS Setup from storage for request ID {}.",
            epoch_id
        );
        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS>>>()
                .await;
        }
        Ok(())
    }

    // NOTE: this function will overwrite the existing PRSS state
    pub async fn init_prss(
        &self,
        context_id: &ContextId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()> {
        // TODO(zama-ai/kms-internal/issues/2721),
        // we never try to store the PRSS in meta_store, so the ID is not guaranteed to be unique

        let own_identity = self
            .session_maker
            .my_identity(context_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("own identity not found in context {}", context_id))?;

        let session_id = epoch_id.derive_session_id_with_counter(PRSS_SESSION_COUNTER)?;

        // PRSS robust init requires broadcast, which is implemented with Sync network assumption
        let mut base_session = self
            .session_maker
            .make_base_session(session_id, *context_id, NetworkMode::Sync)
            .await?;

        tracing::info!("Starting PRSS for identity {}.", own_identity);
        tracing::info!(
            "Session has {} parties with threshold {}",
            base_session.parameters.num_parties(),
            base_session.parameters.threshold()
        );
        tracing::info!("Role assignments: {:?}", base_session.parameters.roles());

        // It seems we cannot do something like
        // `Init::default().init(&mut base_session).await?;`
        // as the type inference gets confused even when using the correct return type.
        let prss_setup_obj_z128: PRSSSetup<ResiduePolyF4Z128> =
            PRSSInit::<ResiduePolyF4Z128>::init(&Init::default(), &mut base_session).await?;
        let prss_setup_obj_z64: PRSSSetup<ResiduePolyF4Z64> =
            PRSSInit::<ResiduePolyF4Z64>::init(&Init::default(), &mut base_session).await?;

        let prss = PRSSSetupCombined {
            prss_setup_z128: prss_setup_obj_z128,
            prss_setup_z64: prss_setup_obj_z64,
            num_parties: base_session.parameters.num_parties() as u8,
            threshold: base_session.parameters.threshold(),
        };

        // serialize and write PRSS Setup to storage into private storage
        let private_storage = Arc::clone(&self.crypto_storage.inner.private_storage);
        let mut priv_storage = private_storage.lock().await;

        // if PRSS already exists, overwrite it
        if priv_storage
            .data_exists(
                &(*epoch_id).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?
        {
            tracing::warn!(
                "PRSS Setup epoch ID {} already exists, overwriting.",
                epoch_id
            );
            delete_at_request_id(
                &mut (*priv_storage),
                &(*epoch_id).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?;
        }

        store_versioned_at_request_id(
            &mut (*priv_storage),
            &(*epoch_id).into(),
            &prss,
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;

        self.session_maker.add_epoch(*epoch_id, prss).await;

        {
            // Notice that this is a hack to get the health reporter to report serving. The type `PrivS` has no influence on the service name.
            self.health_reporter
                .set_serving::<CoreServiceEndpointServer<RealThresholdKms<PrivS, PrivS>>>()
                .await;
        }
        tracing::info!(
            "PRSS on epoch ID {} completed successfully for identity {}.",
            epoch_id,
            own_identity
        );
        Ok(())
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: StorageExt + Send + Sync + 'static,
        Init: PRSSInit<ResiduePolyF4Z64, OutputType = PRSSSetup<ResiduePolyF4Z64>>
            + PRSSInit<ResiduePolyF4Z128, OutputType = PRSSSetup<ResiduePolyF4Z128>>
            + Default,
    > EpochManager for RealThresholdEpochManager<PrivS, PubS, Init>
{
    async fn new_mpc_epoch(
        &self,
        _request: Request<NewMpcEpochRequest>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn destroy_mpc_epoch(
        &self,
        _request: Request<DestroyMpcEpochRequest>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn get_epoch_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<EpochResultResponse>, Status> {
        todo!()
    }
}
