use crate::{client::client_wasm::Client, engine::context::ContextInfo};
use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{DestroyKmsContextRequest, KmsContext, NewKmsContextRequest},
};

impl Client {
    pub fn new_kms_context_request(
        &mut self,
        previous_context_id: Option<&ContextId>,
        new_context: ContextInfo,
    ) -> anyhow::Result<NewKmsContextRequest> {
        Ok(NewKmsContextRequest {
            active_context: previous_context_id.map(|c| (*c).into()),
            new_context: Some(KmsContext::try_from(new_context)?),
        })
    }

    pub fn destroy_kms_context_request(
        &mut self,
        context_id: &ContextId,
    ) -> anyhow::Result<DestroyKmsContextRequest> {
        Ok(DestroyKmsContextRequest {
            context_id: Some((*context_id).into()),
        })
    }
}
