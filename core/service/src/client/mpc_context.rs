use crate::{
    client::client_wasm::Client,
    engine::{
        base::{DSEP_NEW_CONTEXT, NewMpcContextSignedPayload, context_creation_sol_type},
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
            &context_creation_sol_type(&expected),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::{
        NodeSigningIdentity,
        test_support::{ECDSA_AND_MLDSA65, seeded_identity},
    };
    use crate::cryptography::signing::composite::sign_result_entries;
    use crate::dummy_domain;
    use crate::engine::context::SoftwareVersion;
    use crate::testing::helpers::client_knowing;
    use alloy_sol_types::SolStruct;
    use kms_grpc::kms::v1::TypedSignature;
    use rand::SeedableRng;
    use threshold_types::rng::AesRng;

    /// A response confirming `payload`, signed by `identity` the way a node signs it.
    fn response(
        identity: &NodeSigningIdentity,
        payload: &NewMpcContextSignedPayload,
    ) -> NewMpcContextResponse {
        let eip712_hash = context_creation_sol_type(payload).eip712_signing_hash(&dummy_domain());
        let signatures = sign_result_entries(
            identity,
            &ECDSA_AND_MLDSA65,
            &DSEP_NEW_CONTEXT,
            &eip712_hash,
            payload,
        )
        .unwrap();
        NewMpcContextResponse {
            payload: Some(payload.into()),
            signatures: signatures.iter().map(TypedSignature::from).collect(),
        }
    }

    #[test]
    fn new_context_response_matches_the_request() {
        let mut rng = AesRng::seed_from_u64(0xC0DE);
        let identity = seeded_identity(&mut rng);
        let client = client_knowing(&identity, &ECDSA_AND_MLDSA65);
        let new_context = ContextInfo {
            mpc_nodes: vec![],
            context_id: ContextId::from_bytes([1u8; 32]),
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
            pcr_values: vec![],
        };
        let requested = NewMpcContextSignedPayload {
            previous_context_id: ContextId::from_bytes([2u8; 32]),
            new_context_id: new_context.context_id,
            node_config_hash: [3u8; 32],
            extra_data: vec![7u8; 3],
        };
        let request = client
            .new_mpc_context_request(
                new_context,
                &requested.previous_context_id,
                requested.node_config_hash,
                &dummy_domain(),
                requested.extra_data.clone(),
            )
            .unwrap();

        let valid = response(&identity, &requested);
        assert_eq!(
            client
                .process_new_mpc_context_response(&valid, &request)
                .unwrap(),
            1
        );

        // A correctly signed confirmation of anything else is not a confirmation of the request.
        let others = [
            NewMpcContextSignedPayload {
                new_context_id: ContextId::from_bytes([4u8; 32]),
                ..requested.clone()
            },
            NewMpcContextSignedPayload {
                previous_context_id: ContextId::from_bytes([5u8; 32]),
                ..requested.clone()
            },
            NewMpcContextSignedPayload {
                node_config_hash: [6u8; 32],
                ..requested.clone()
            },
            NewMpcContextSignedPayload {
                extra_data: vec![],
                ..requested.clone()
            },
        ];
        for other in &others {
            assert!(
                client
                    .process_new_mpc_context_response(&response(&identity, other), &request)
                    .is_err()
            );
        }

        let without_payload = NewMpcContextResponse {
            payload: None,
            ..valid
        };
        assert!(
            client
                .process_new_mpc_context_response(&without_payload, &request)
                .is_err()
        );
    }
}
