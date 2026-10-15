use crate::{client::client_wasm::Client, engine::context::ContextInfo};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{DestroyMpcContextRequest, MpcContext, NewMpcContextRequest},
    rpc_types::alloy_to_protobuf_domain,
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

    /// Build a [`DestroyMpcContextRequest`] for `context_id`, asking for the confirmation to be
    /// signed under `eip712_domain` and every scheme this client requests.
    pub fn destroy_mpc_context_request(
        &mut self,
        context_id: &ContextId,
        eip712_domain: &Eip712Domain,
    ) -> anyhow::Result<DestroyMpcContextRequest> {
        Ok(DestroyMpcContextRequest {
            context_id: Some((*context_id).into()),
            domain: Some(alloy_to_protobuf_domain(eip712_domain)?),
            extra_data: Vec::new(),
            signing_schemes: self.signing_schemes_proto(),
        })
    }
}
