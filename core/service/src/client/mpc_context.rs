use crate::{
    client::client_wasm::Client,
    engine::{
        base::{DSEP_DESTROY_CONTEXT, DestroyMpcContextSignedPayload},
        context::ContextInfo,
    },
};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{
        DestroyMpcContextRequest, DestroyMpcContextResponse, MpcContext, NewMpcContextRequest,
    },
    rpc_types::alloy_to_protobuf_domain,
    solidity_types::ContextDestructionVerification,
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
        &self,
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

    /// Check that `response` confirms the destruction of `context_id` with `extra_data`, signed
    /// under every scheme this client requests.
    ///
    /// Returns the party that produced the response.
    pub fn process_destroy_mpc_context_response(
        &self,
        response: &DestroyMpcContextResponse,
        context_id: &ContextId,
        extra_data: &[u8],
        domain: &Eip712Domain,
    ) -> anyhow::Result<u32> {
        // The signatures are checked against what was requested rather than what came back, so a
        // party cannot confirm the destruction of some other context.
        let expected = DestroyMpcContextSignedPayload {
            context_id: *context_id,
            extra_data: extra_data.to_vec(),
        };
        let received: DestroyMpcContextSignedPayload = response
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
            &ContextDestructionVerification::new(context_id, extra_data.to_vec()),
            domain,
            &DSEP_DESTROY_CONTEXT,
            &expected,
        )?;
        tracing::info!("Destruction of context {context_id} verified as done by party {party_id}");
        Ok(party_id)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::consts::TEST_PARAM;
    use crate::cryptography::signatures::{
        NodeSigningIdentity, SigningSchemeType, VerfKeySet, test_support::seeded_identity,
    };
    use crate::cryptography::signing::composite::sign_result_entries;
    use crate::dummy_domain;
    use alloy_sol_types::SolStruct;
    use kms_grpc::kms::v1::TypedSignature;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use threshold_types::rng::AesRng;

    /// The schemes the client requests: ECDSA and a post-quantum scheme, so both kinds of
    /// verification are exercised.
    pub(crate) const SCHEMES: [SigningSchemeType; 2] =
        [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65];

    /// A client that knows `identity` as party 1, holds its key for every scheme in [`SCHEMES`],
    /// and requests them all.
    pub(crate) fn client_knowing(identity: &NodeSigningIdentity) -> Client {
        let pk = identity.verf_key();
        let mut client = Client::new(
            HashMap::from([(1, pk.clone())]),
            HashMap::from([(1, VerfKeySet::from_identity(identity, &SCHEMES).unwrap())]),
            pk.address(),
            None,
            TEST_PARAM,
            None,
        );
        client.set_signing_schemes(&SCHEMES).unwrap();
        client
    }

    /// A response confirming `context_id` with `extra_data`, signed by `identity` the way a node
    /// signs it.
    fn response(
        identity: &NodeSigningIdentity,
        context_id: &ContextId,
        extra_data: &[u8],
    ) -> DestroyMpcContextResponse {
        let eip712_hash = ContextDestructionVerification::new(context_id, extra_data.to_vec())
            .eip712_signing_hash(&dummy_domain());
        let payload = DestroyMpcContextSignedPayload {
            context_id: *context_id,
            extra_data: extra_data.to_vec(),
        };
        let signatures = sign_result_entries(
            identity,
            &SCHEMES,
            &DSEP_DESTROY_CONTEXT,
            &eip712_hash,
            &payload,
        )
        .unwrap();
        DestroyMpcContextResponse {
            payload: Some((&payload).into()),
            signatures: signatures.iter().map(TypedSignature::from).collect(),
        }
    }

    /// A confirmation only counts for the context and extra data that were requested.
    #[test]
    fn destroy_context_response_matches_the_request() {
        let mut rng = AesRng::seed_from_u64(0xC0DE);
        let identity = seeded_identity(&mut rng);
        let client = client_knowing(&identity);
        let context_id = ContextId::from_bytes([1u8; 32]);
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();

        let valid = response(&identity, &context_id, &extra_data);
        assert_eq!(
            client
                .process_destroy_mpc_context_response(&valid, &context_id, &extra_data, &domain)
                .unwrap(),
            1
        );

        // A correctly signed confirmation of another context is not a confirmation of ours.
        let other = response(&identity, &ContextId::from_bytes([2u8; 32]), &extra_data);
        assert!(
            client
                .process_destroy_mpc_context_response(&other, &context_id, &extra_data, &domain)
                .is_err()
        );

        // The extra data has to match too.
        assert!(
            client
                .process_destroy_mpc_context_response(&valid, &context_id, &[], &domain)
                .is_err()
        );
    }
}
