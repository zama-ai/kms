use std::{marker::PhantomData, sync::Arc};

use kms_grpc::kms::v1::{
    DestroyMpcEpochRequest, Empty, EpochResultResponse, NewMpcEpochRequest, RequestId,
};
use threshold_fhe::{
    algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
    execution::small_execution::prss::{PRSSInit, PRSSSetup},
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};
use tonic_health::server::HealthReporter;

use crate::{
    engine::{
        base::KeyGenMetadata, threshold::service::session::SessionMaker, traits::EpochManager,
    },
    util::{meta_store::MetaStore, rate_limiter::RateLimiter},
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage, StorageExt},
};

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
