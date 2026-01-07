use crate::{client::client_wasm::Client, engine::context::ContextInfo};
use kms_grpc::{
    identifiers::ContextId,
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

    pub fn destroy_mpc_context_request(
        &mut self,
        context_id: &ContextId,
    ) -> anyhow::Result<DestroyMpcContextRequest> {
        Ok(DestroyMpcContextRequest {
            context_id: Some((*context_id).into()),
        })
    }
}
