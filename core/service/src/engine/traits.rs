use kms_grpc::ContextId;
use kms_grpc::kms::v1::*;
use tonic::Request;
use tonic::Response;

use crate::engine::base::KeyGenMetadata;
use crate::engine::utils::MetricedError;

#[tonic::async_trait]
pub trait ContextManager {
    async fn new_mpc_context(
        &self,
        request: Request<NewMpcContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn destroy_mpc_context(
        &self,
        request: Request<DestroyMpcContextRequest>,
    ) -> Result<(), MetricedError>; // Observe that this needs to be linked to a call to destroy associated epochs, hence the method does not return a Response type

    async fn new_custodian_context(
        &self,
        request: Request<NewCustodianContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn destroy_custodian_context(
        &self,
        request: Request<DestroyCustodianContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    async fn mpc_context_exists_and_consistent(
        &self,
        context_id: &ContextId,
    ) -> anyhow::Result<bool>;

    async fn mpc_context_exists_in_cache(&self, context_id: &ContextId) -> bool;
}

pub trait PrivateKeyMaterialMetadata {
    fn get_metadata(&self) -> &KeyGenMetadata;
}
