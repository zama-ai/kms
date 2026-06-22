use crate::{client::client_wasm::Client, engine::context::ContextInfo};
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{DestroyMpcContextRequest, MpcContext, NewMpcContextRequest},
};

impl Client {
    pub fn new_mpc_context_request(
        &mut self,
        new_context: ContextInfo,
    ) -> anyhow::Result<NewMpcContextRequest> {
        Ok(NewMpcContextRequest {
            new_context: Some(MpcContext::try_from(new_context)?),
        })
    }

    /// Build a [`DestroyMpcContextRequest`] for `context_id` together with the epochs to destroy
    /// alongside it.
    ///
    /// `epoch_ids` must be the full set of epochs belonging to the context: destroying a context
    /// without its epochs leaves their secret key shares behind (see the `DestroyMpcContext` RPC
    /// docs). In production the kms-connector is the source of truth for this set; pass `&[]` only
    /// for a context that genuinely has no associated epochs.
    pub fn destroy_mpc_context_request(
        &mut self,
        context_id: &ContextId,
        epoch_ids: &[EpochId],
    ) -> anyhow::Result<DestroyMpcContextRequest> {
        Ok(DestroyMpcContextRequest {
            context_id: Some((*context_id).into()),
            epoch_ids: epoch_ids.iter().map(|id| (*id).into()).collect(),
        })
    }
}
