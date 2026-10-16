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
    use crate::client::mpc_context::tests::SCHEMES;
    use crate::cryptography::signatures::{NodeSigningIdentity, test_support::seeded_identity};
    use crate::cryptography::signing::composite::sign_result_entries;
    use crate::dummy_domain;
    use crate::testing::helpers::client_knowing;
    use alloy_sol_types::SolStruct;
    use kms_grpc::kms::v1::TypedSignature;
    use rand::SeedableRng;
    use threshold_types::rng::AesRng;

    /// A response confirming `epoch_id` with `extra_data`, signed by `identity` the way a node
    /// signs it.
    fn response(
        identity: &NodeSigningIdentity,
        epoch_id: &EpochId,
        extra_data: &[u8],
    ) -> DestroyMpcEpochResponse {
        let eip712_hash = EpochDestructionVerification::new(epoch_id, extra_data.to_vec())
            .eip712_signing_hash(&dummy_domain());
        let payload = DestroyMpcEpochSignedPayload {
            epoch_id: *epoch_id,
            extra_data: extra_data.to_vec(),
        };
        let signatures = sign_result_entries(
            identity,
            &SCHEMES,
            &DSEP_DESTROY_EPOCH,
            &eip712_hash,
            &payload,
        )
        .unwrap();
        DestroyMpcEpochResponse {
            payload: Some((&payload).into()),
            signatures: signatures.iter().map(TypedSignature::from).collect(),
        }
    }

    /// A confirmation only counts for the epoch and extra data that were requested.
    #[test]
    fn destroy_epoch_response_matches_the_request() {
        let mut rng = AesRng::seed_from_u64(0xDE57);
        let identity = seeded_identity(&mut rng);
        let client = client_knowing(&identity, &SCHEMES);
        let epoch_id = EpochId::from_bytes([1u8; 32]);
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();

        let valid = response(&identity, &epoch_id, &extra_data);
        assert_eq!(
            client
                .process_destroy_mpc_epoch_response(&valid, &epoch_id, &extra_data, &domain)
                .unwrap(),
            1
        );

        // A correctly signed confirmation of another epoch is not a confirmation of ours.
        let other = response(&identity, &EpochId::from_bytes([2u8; 32]), &extra_data);
        assert!(
            client
                .process_destroy_mpc_epoch_response(&other, &epoch_id, &extra_data, &domain)
                .is_err()
        );

        // The extra data has to match too.
        assert!(
            client
                .process_destroy_mpc_epoch_response(&valid, &epoch_id, &[], &domain)
                .is_err()
        );
    }
}
