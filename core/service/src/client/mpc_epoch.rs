use crate::{
    client::client_wasm::Client,
    engine::base::{DSEP_DESTROY_EPOCH, DestroyMpcEpochSignedPayload},
};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    identifiers::EpochId, kms::v1::DestroyMpcEpochResponse,
    solidity_types::EpochDestructionVerification,
};

impl Client {
    /// Check that `response` confirms the destruction of `epoch_id` with `extra_data`, signed under
    /// every scheme this client requests.
    ///
    /// Returns the party that produced the response.
    pub fn process_destroy_mpc_epoch_response(
        &self,
        response: &DestroyMpcEpochResponse,
        epoch_id: &EpochId,
        extra_data: &[u8],
        domain: &Eip712Domain,
    ) -> anyhow::Result<u32> {
        // The signatures are checked against what was requested rather than what came back, so a
        // party cannot confirm the destruction of some other epoch.
        let expected = DestroyMpcEpochSignedPayload {
            epoch_id: *epoch_id,
            extra_data: extra_data.to_vec(),
        };
        let received: DestroyMpcEpochSignedPayload = response
            .payload
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the epoch destruction response carries no payload"))?
            .try_into()?;
        anyhow::ensure!(
            received == expected,
            "the epoch destruction response confirms {received:?}, but {expected:?} was requested"
        );
        let (party_id, _address) = self.verify_result_signatures(
            &response.signatures,
            // An epoch destruction response has no deprecated `external_signature`.
            &[],
            &EpochDestructionVerification::new(epoch_id, extra_data.to_vec()),
            domain,
            &DSEP_DESTROY_EPOCH,
            &expected,
        )?;
        tracing::info!("Destruction of epoch {epoch_id} verified as done by party {party_id}");
        Ok(party_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mpc_context::tests::{SCHEMES, client_knowing};
    use crate::cryptography::signatures::{
        NodeSigningIdentity, SigningSchemeType, test_support::seeded_identity,
    };
    use crate::cryptography::signing::composite::sign_result_entries;
    use crate::dummy_domain;
    use alloy_sol_types::SolStruct;
    use kms_grpc::kms::v1::TypedSignature;
    use rand::SeedableRng;
    use threshold_types::rng::AesRng;

    /// A response confirming `confirmed`, signed by `identity` under `schemes` over `signed`, with
    /// the same signing function a node uses.
    fn response(
        identity: &NodeSigningIdentity,
        schemes: &[SigningSchemeType],
        confirmed: &EpochId,
        signed: &EpochId,
        extra_data: &[u8],
    ) -> DestroyMpcEpochResponse {
        let eip712_hash = EpochDestructionVerification::new(signed, extra_data.to_vec())
            .eip712_signing_hash(&dummy_domain());
        let signed_payload = DestroyMpcEpochSignedPayload {
            epoch_id: *signed,
            extra_data: extra_data.to_vec(),
        };
        let signatures = sign_result_entries(
            identity,
            schemes,
            &DSEP_DESTROY_EPOCH,
            &eip712_hash,
            &signed_payload,
        )
        .unwrap();
        let payload = DestroyMpcEpochSignedPayload {
            epoch_id: *confirmed,
            extra_data: extra_data.to_vec(),
        };
        DestroyMpcEpochResponse {
            payload: Some((&payload).into()),
            signatures: signatures.iter().map(TypedSignature::from).collect(),
        }
    }

    /// The rejections a correct node never provokes, so they cannot be reached with real servers.
    #[test]
    fn destroy_epoch_response_signatures() {
        let mut rng = AesRng::seed_from_u64(0xDE57);
        let identity = seeded_identity(&mut rng);
        let client = client_knowing(&identity);
        let epoch_id = EpochId::from_bytes([1u8; 32]);
        let other_epoch_id = EpochId::from_bytes([2u8; 32]);
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();
        let check = |client: &Client, response: &DestroyMpcEpochResponse, extra_data: &[u8]| {
            client.process_destroy_mpc_epoch_response(response, &epoch_id, extra_data, &domain)
        };

        let valid = response(&identity, &SCHEMES, &epoch_id, &epoch_id, &extra_data);
        assert_eq!(check(&client, &valid, &extra_data).unwrap(), 1);

        // A correctly signed confirmation of another epoch is not a confirmation of ours.
        let other = response(
            &identity,
            &SCHEMES,
            &other_epoch_id,
            &other_epoch_id,
            &extra_data,
        );
        assert!(check(&client, &other, &extra_data).is_err());

        // A payload naming our epoch does not help if the signatures cover another one.
        let mismatched = response(&identity, &SCHEMES, &epoch_id, &other_epoch_id, &extra_data);
        assert!(check(&client, &mismatched, &extra_data).is_err());

        // The extra data is bound into the signatures too.
        assert!(check(&client, &valid, &[]).is_err());

        // Every requested scheme has to be present: an ECDSA signature alone is not enough.
        let ecdsa_only = response(
            &identity,
            &[SigningSchemeType::Ecdsa256k1],
            &epoch_id,
            &epoch_id,
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
