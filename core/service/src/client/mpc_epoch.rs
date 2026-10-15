use crate::{
    client::client_wasm::Client,
    engine::base::{DSEP_DESTROY_EPOCH, DestroyMpcEpochPayload},
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
        let expected = DestroyMpcEpochPayload {
            destroyed_epoch_id: *epoch_id,
            extra_data: extra_data.to_vec(),
        };
        let received: DestroyMpcEpochPayload = response
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
    use crate::consts::TEST_PARAM;
    use crate::cryptography::signatures::{
        PrivateSigKey, compute_eip712_signature, gen_sig_keys,
    };
    use crate::dummy_domain;
    use kms_grpc::rpc_types::ecdsa_signatures;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use threshold_types::rng::AesRng;

    /// A response confirming `confirmed`, ECDSA-signed by `sk` over `signed`.
    fn response(
        sk: &PrivateSigKey,
        confirmed: &EpochId,
        signed: &EpochId,
        extra_data: &[u8],
    ) -> DestroyMpcEpochResponse {
        let signature = compute_eip712_signature(
            sk,
            &EpochDestructionVerification::new(signed, extra_data.to_vec()),
            &dummy_domain(),
        )
        .unwrap();
        let payload = DestroyMpcEpochPayload {
            destroyed_epoch_id: *confirmed,
            extra_data: extra_data.to_vec(),
        };
        DestroyMpcEpochResponse {
            payload: Some((&payload).into()),
            signatures: ecdsa_signatures(signature),
        }
    }

    #[test]
    fn destroy_epoch_response_signatures() {
        let mut rng = AesRng::seed_from_u64(0xDE57);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let client = Client::new(
            HashMap::from([(1, pk.clone())]),
            HashMap::new(),
            pk.address(),
            None,
            TEST_PARAM,
            None,
        );
        let epoch_id = EpochId::from_bytes([1u8; 32]);
        let other_epoch_id = EpochId::from_bytes([2u8; 32]);
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();
        let check = |client: &Client, response: &DestroyMpcEpochResponse, extra_data: &[u8]| {
            client.process_destroy_mpc_epoch_response(response, &epoch_id, extra_data, &domain)
        };

        let valid = response(&sk, &epoch_id, &epoch_id, &extra_data);
        assert_eq!(check(&client, &valid, &extra_data).unwrap(), 1);

        // A correctly signed confirmation of another epoch is not a confirmation of ours.
        let other = response(&sk, &other_epoch_id, &other_epoch_id, &extra_data);
        assert!(check(&client, &other, &extra_data).is_err());

        // A payload naming our epoch does not help if the signature covers another one.
        let mismatched = response(&sk, &epoch_id, &other_epoch_id, &extra_data);
        assert!(check(&client, &mismatched, &extra_data).is_err());

        // The extra data is bound into the signature too.
        assert!(check(&client, &valid, &[]).is_err());

        // A client that does not know the signer rejects the response.
        let pk = gen_sig_keys(&mut rng).0;
        let address = pk.address();
        let stranger = Client::new(
            HashMap::from([(1, pk)]),
            HashMap::new(),
            address,
            None,
            TEST_PARAM,
            None,
        );
        assert!(check(&stranger, &valid, &extra_data).is_err());
    }
}
