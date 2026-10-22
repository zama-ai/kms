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
    kms::v1::{
        DestroyMpcContextRequest, MpcContext, NewMpcContextPayload, NewMpcContextRequest,
        NewMpcContextResponse,
    },
    rpc_types::{alloy_to_protobuf_domain, optional_protobuf_to_alloy_domain},
    solidity_types::ContextCreationConfirmation,
};

impl Client {
    /// Build a [`NewMpcContextRequest`] for `new_context`, asking for its `ContextCreationConfirmation`
    /// to be signed under `domain` and every scheme this client requests.
    pub fn new_mpc_context_request(
        &self,
        new_context: ContextInfo,
        previous_context_id: &ContextId,
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

    /// Check that `response` confirms the creation of the context in `request`, with the previous
    /// context ID, node config hash and extra data of `request`, signed under its domain and every
    /// scheme this client requests.
    ///
    /// Returns the party that produced the response.
    pub fn process_new_mpc_context_response(
        &self,
        response: &NewMpcContextResponse,
        request: &NewMpcContextRequest,
    ) -> anyhow::Result<u32> {
        // The signatures are checked against what was requested rather than what came back, so a
        // party cannot confirm the creation of some other context.
        let expected = NewMpcContextSignedPayload::try_from(NewMpcContextPayload {
            previous_context_id: request.previous_context_id.clone(),
            new_context_id: request
                .new_context
                .as_ref()
                .and_then(|new_context| new_context.context_id.clone()),
            node_config_hash: request.node_config_hash.clone(),
            extra_data: request.extra_data.clone(),
        })?;
        let domain = optional_protobuf_to_alloy_domain(request.domain.as_ref())?;
        let received: NewMpcContextSignedPayload = response
            .payload
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the context creation response carries no payload"))?
            .try_into()?;
        anyhow::ensure!(
            received == expected,
            "the context creation response confirms {received:?}, but {expected:?} was requested"
        );
        let (party_id, _address) = self.verify_result_signatures(
            &response.signatures,
            // A context creation response has no deprecated `external_signature`.
            &[],
            &ContextCreationConfirmation::new(
                &expected.previous_context_id,
                &expected.new_context_id,
                expected.node_config_hash.into(),
                expected.extra_data.clone(),
            ),
            &domain,
            &DSEP_NEW_CONTEXT,
            &expected,
        )?;
        tracing::info!(
            "Creation of context {} verified as done by party {party_id}",
            expected.new_context_id
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
