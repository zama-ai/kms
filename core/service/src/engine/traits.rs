use kms_grpc::ContextId;
use kms_grpc::kms::v1::*;
use tonic::Request;
use tonic::Response;

use crate::engine::base::KeyGenMetadata;
use crate::engine::utils::MetricedError;
use crate::engine::validation::VerifiedDestroyMpcContext;

#[tonic::async_trait]
pub trait ContextManager {
    async fn new_mpc_context(
        &self,
        request: Request<NewMpcContextRequest>,
    ) -> Result<Response<Empty>, MetricedError>;

    /// Check a destroy request without changing anything: parse it, resolve the signing schemes and
    /// domain, check the node can sign them, and check that destroying the context would not remove
    /// the last context or the last epoch. A context that does not exist passes, so that its absence
    /// can be confirmed.
    async fn validate_destroy_mpc_context(
        &self,
        request: &DestroyMpcContextRequest,
    ) -> Result<VerifiedDestroyMpcContext, MetricedError>;

    /// Delete an MPC context, if it still exists, and return a signed confirmation that it no
    /// longer exists. The caller must have destroyed the context's epochs first.
    ///
    /// Before any destruction happens the request is validated using [`Self::validate_destroy_mpc_context`].
    async fn destroy_mpc_context(
        &self,
        verified: VerifiedDestroyMpcContext,
    ) -> Result<Response<DestroyMpcContextResponse>, MetricedError>;

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
