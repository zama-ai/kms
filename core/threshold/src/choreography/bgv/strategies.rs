use std::sync::Arc;

use tonic::transport::server::Router;
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::ResiduePoly,
    structure_traits::{Derive, ErrorCorrect, Invert, Solve, Syndrome},
};
use threshold_execution::online::preprocessing::PreprocessorFactory;
use threshold_networking::grpc::GrpcNetworkingManager;
use threshold_types::role::Role;
use crate::grpc::server::ChoreoRoutingHelper;
use super::grpc::ExperimentalGrpcChoreography;

pub struct ExperimentalChoreoRoutingHelper;

impl<const EXTENSION_DEGREE: usize> ChoreoRoutingHelper<EXTENSION_DEGREE>
    for ExperimentalChoreoRoutingHelper
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
{
    fn add_to_router<L>(
        &self,
        router: Router<L>,
        my_role: Role,
        networking: Arc<GrpcNetworkingManager>,
        factory: Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>,
    ) -> Router<L> {
        router.add_service(
            ExperimentalGrpcChoreography::new(my_role, networking, factory).into_server(),
        )
    }
}
