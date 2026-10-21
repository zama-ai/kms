use crate::{
    client::client_wasm::Client,
    engine::{
        base::{DSEP_NEW_CONTEXT, NewMpcContextSignedPayload},
        context::ContextInfo,
    },
};
use alloy_dyn_abi::Eip712Domain;
use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{DestroyMpcContextRequest, MpcContext, NewMpcContextRequest, NewMpcContextResponse},
    rpc_types::alloy_to_protobuf_domain,
    solidity_types::ContextCreationConfirmation,
};

impl Client {
    pub fn new_mpc_context_request(
        &mut self,
        previous_context_id: &ContextId,
        new_context: ContextInfo,
        node_config_hash: [u8; 32],
        domain: &Eip712Domain,
        extra_data: Vec<u8>,
    ) -> anyhow::Result<NewMpcContextRequest> {
        Ok(NewMpcContextRequest {
            new_context: Some(MpcContext::try_from(new_context)?),
            previous_context_id: Some((*previous_context_id).into()),
            node_config_hash: node_config_hash.to_vec(),
            domain: Some(alloy_to_protobuf_domain(domain)?),
            extra_data,
            signing_schemes: self.signing_schemes_proto(),
        })
    }

    /// Check that `response` confirms the construction of the new context signed
    /// under every scheme this client requests.
    ///
    /// Returns the party that produced the response.
    pub fn process_new_mpc_context_response(
        &self,
        response: &NewMpcContextResponse,
        previous_context_id: &ContextId,
        new_context_id: &ContextId,
        node_config_hash: &[u8; 32],
        extra_data: &[u8],
        domain: &Eip712Domain,
    ) -> anyhow::Result<u32> {
        // The signatures are checked against what was requested rather than what came back, so a
        // party cannot confirm the construction of some other context.
        let expected = NewMpcContextSignedPayload {
            previous_context_id: *previous_context_id,
            new_context_id: *new_context_id,
            node_config_hash: node_config_hash.clone(), // TODO can we do anything regarding validating this
            extra_data: extra_data.to_vec(),
        };
        let received: NewMpcContextSignedPayload = response
            .payload
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the context destruction response carries no payload"))?
            .try_into()?;
        anyhow::ensure!(
            received == expected,
            "the context destruction response confirms {received:?}, but {expected:?} was requested"
        );
        let (party_id, _address) = self.verify_result_signatures(
            &response.signatures,
            // A context destruction response has no deprecated `external_signature`.
            &[],
            &ContextCreationConfirmation::new(
                previous_context_id,
                new_context_id,
                node_config_hash.into(),
                extra_data.to_vec(),
            ),
            domain,
            &DSEP_NEW_CONTEXT,
            &expected,
        )?;
        tracing::info!(
            "Contruction of context {new_context_id} verified as done by party {party_id}"
        );
        Ok(party_id)
    }

    /// Build a [`DestroyMpcContextRequest`] for `context_id` together with the epochs to destroy
    /// alongside it.
    pub fn destroy_mpc_context_request(
        &mut self,
        context_id: &ContextId,
    ) -> anyhow::Result<DestroyMpcContextRequest> {
        Ok(DestroyMpcContextRequest {
            context_id: Some((*context_id).into()),
        })
    }
}
