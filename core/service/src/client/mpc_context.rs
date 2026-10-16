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
        let received: DestroyMpcContextSignedPayload = response
            .payload
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the context destruction response carries no payload"))?
            .try_into()?;
        anyhow::ensure!(
            received.context_id == *context_id,
            "the context destruction response confirms context {}, but {context_id} was requested",
            received.context_id
        );
        anyhow::ensure!(
            received.extra_data == extra_data,
            "the context destruction response carries other extra data than was requested"
        );
        let (party_id, _address) = self.verify_result_signatures(
            &response.signatures,
            // A context destruction response has no deprecated `external_signature`.
            &[],
            &ContextDestructionVerification::new(context_id, extra_data.to_vec()),
            domain,
            &DSEP_DESTROY_CONTEXT,
            &received,
        )?;
        tracing::info!("Destruction of context {context_id} verified as done by party {party_id}");
        Ok(party_id)
    }
}

#[cfg(test)]
mod tests {
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
    const SCHEMES: [SigningSchemeType; 2] =
        [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65];

    /// A client that knows `identity` as party 1, holds its key for every scheme in [`SCHEMES`],
    /// and requests them all.
    fn client_knowing(identity: &NodeSigningIdentity) -> Client {
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

    /// A response confirming `confirmed`, signed by `identity` under `schemes` over `signed`, with
    /// the same signing function a node uses.
    fn response(
        identity: &NodeSigningIdentity,
        schemes: &[SigningSchemeType],
        confirmed: &ContextId,
        signed: &ContextId,
        extra_data: &[u8],
    ) -> DestroyMpcContextResponse {
        let eip712_hash = ContextDestructionVerification::new(signed, extra_data.to_vec())
            .eip712_signing_hash(&dummy_domain());
        let signed_payload = DestroyMpcContextSignedPayload {
            context_id: *signed,
            extra_data: extra_data.to_vec(),
        };
        let signatures = sign_result_entries(
            identity,
            schemes,
            &DSEP_DESTROY_CONTEXT,
            &eip712_hash,
            &signed_payload,
        )
        .unwrap();
        let payload = DestroyMpcContextSignedPayload {
            context_id: *confirmed,
            extra_data: extra_data.to_vec(),
        };
        DestroyMpcContextResponse {
            payload: Some((&payload).into()),
            signatures: signatures.iter().map(TypedSignature::from).collect(),
        }
    }

    /// The rejections a correct node never provokes, so they cannot be reached with real servers.
    #[test]
    fn destroy_context_response_signatures() {
        let mut rng = AesRng::seed_from_u64(0xC0DE);
        let identity = seeded_identity(&mut rng);
        let client = client_knowing(&identity);
        let context_id = ContextId::from_bytes([1u8; 32]);
        let other_context_id = ContextId::from_bytes([2u8; 32]);
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();
        let check = |client: &Client, response: &DestroyMpcContextResponse, extra_data: &[u8]| {
            client.process_destroy_mpc_context_response(response, &context_id, extra_data, &domain)
        };

        let valid = response(&identity, &SCHEMES, &context_id, &context_id, &extra_data);
        assert_eq!(check(&client, &valid, &extra_data).unwrap(), 1);

        // A correctly signed confirmation of another context is not a confirmation of ours.
        let other = response(
            &identity,
            &SCHEMES,
            &other_context_id,
            &other_context_id,
            &extra_data,
        );
        assert!(check(&client, &other, &extra_data).is_err());

        // A payload naming our context does not help if the signatures cover another one.
        let mismatched = response(
            &identity,
            &SCHEMES,
            &context_id,
            &other_context_id,
            &extra_data,
        );
        assert!(check(&client, &mismatched, &extra_data).is_err());

        // The extra data is bound into the signatures too.
        assert!(check(&client, &valid, &[]).is_err());

        // Every requested scheme has to be present: an ECDSA signature alone is not enough.
        let ecdsa_only = response(
            &identity,
            &[SigningSchemeType::Ecdsa256k1],
            &context_id,
            &context_id,
            &extra_data,
        );
        assert!(check(&client, &ecdsa_only, &extra_data).is_err());

        // The post-quantum signature is checked in its own right, not carried by the ECDSA one.
        let mut tampered = valid.clone();
        // Flip a bit of the ML-DSA-65 signature of `signatures`, leaving the others intact.
        let entry = tampered
            .signatures
            .iter_mut()
            .find(|entry| entry.scheme == SigningSchemeType::MlDsa65.as_wire())
            .unwrap();
        entry.signature[0] ^= 0x01;
        assert!(check(&client, &tampered, &extra_data).is_err());

        // A client that does not know the signer rejects the response.
        let stranger = client_knowing(&seeded_identity(&mut rng));
        assert!(check(&stranger, &valid, &extra_data).is_err());
    }
}
