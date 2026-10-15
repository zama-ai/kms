use crate::{
    client::client_wasm::Client,
    engine::{
        base::{DSEP_DESTROY_CONTEXT, DestroyMpcContextPayload},
        context::ContextInfo,
    },
};
use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
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
    /// Returns the party that produced the response, and the epochs it reports as destroyed.
    pub fn process_destroy_mpc_context_response(
        &self,
        response: &DestroyMpcContextResponse,
        context_id: &ContextId,
        extra_data: &[u8],
        domain: &Eip712Domain,
    ) -> anyhow::Result<(u32, Vec<EpochId>)> {
        let received: DestroyMpcContextPayload = response
            .payload
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the context destruction response carries no payload"))?
            .try_into()?;
        anyhow::ensure!(
            received.destroyed_context_id == *context_id,
            "the context destruction response confirms context {}, but {context_id} was requested",
            received.destroyed_context_id
        );
        anyhow::ensure!(
            received.extra_data == extra_data,
            "the context destruction response carries other extra data than was requested"
        );
        let (party_id, _address) = self.verify_result_signatures(
            &response.signatures,
            // A context destruction response has no deprecated `external_signature`.
            &[],
            &ContextDestructionVerification::new(
                context_id,
                &received.destroyed_epoch_ids,
                extra_data.to_vec(),
            ),
            domain,
            &DSEP_DESTROY_CONTEXT,
            &received,
        )?;
        tracing::info!(
            "Destruction of context {context_id} verified as done by party {party_id}, \
             together with epochs {:?}",
            received.destroyed_epoch_ids
        );
        Ok((party_id, received.destroyed_epoch_ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
        use kms_grpc::rpc_types::ecdsa_signatures;
    use kms_lib::consts::TEST_PARAM;
    use kms_lib::cryptography::signatures::{
        PrivateSigKey, PublicSigKey, compute_eip712_signature, gen_sig_keys,
    };
    use crate::dummy_domain;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use threshold_types::rng::AesRng;

    /// A client that knows `pk` as party 1 and requests ECDSA only.
    fn client_knowing(pk: PublicSigKey) -> Client {
        let address = pk.address();
        Client::new(
            HashMap::from([(1, pk)]),
            HashMap::new(),
            address,
            None,
            TEST_PARAM,
            None,
        )
    }

    /// A response confirming `confirmed` with `confirmed_epochs`, ECDSA-signed by `sk` over
    /// `signed` with `signed_epochs`.
    fn response(
        sk: &PrivateSigKey,
        (confirmed, confirmed_epochs): (&ContextId, &[EpochId]),
        (signed, signed_epochs): (&ContextId, &[EpochId]),
        extra_data: &[u8],
    ) -> DestroyMpcContextResponse {
        let signature = compute_eip712_signature(
            sk,
            &ContextDestructionVerification::new(signed, signed_epochs, extra_data.to_vec()),
            &dummy_domain(),
        )
        .unwrap();
        let payload = DestroyMpcContextPayload {
            destroyed_context_id: *confirmed,
            destroyed_epoch_ids: confirmed_epochs.to_vec(),
            extra_data: extra_data.to_vec(),
        };
        DestroyMpcContextResponse {
            payload: Some((&payload).into()),
            signatures: ecdsa_signatures(signature),
        }
    }

    #[test]
    fn destroy_context_response_signatures() {
        let mut rng = AesRng::seed_from_u64(0xC0DE);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let client = client_knowing(pk);
        let context_id = ContextId::from_bytes([1u8; 32]);
        let other_context_id = ContextId::from_bytes([2u8; 32]);
        let epochs = [EpochId::from_bytes([3u8; 32]), EpochId::from_bytes([4u8; 32])];
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();
        let check = |client: &Client, response: &DestroyMpcContextResponse, extra_data: &[u8]| {
            client.process_destroy_mpc_context_response(response, &context_id, extra_data, &domain)
        };

        let valid = response(
            &sk,
            (&context_id, &epochs),
            (&context_id, &epochs),
            &extra_data,
        );
        assert_eq!(
            check(&client, &valid, &extra_data).unwrap(),
            (1, epochs.to_vec())
        );

        // A context without epochs, or whose epochs an earlier attempt removed, lists none.
        let no_epochs = response(&sk, (&context_id, &[]), (&context_id, &[]), &extra_data);
        assert_eq!(
            check(&client, &no_epochs, &extra_data).unwrap(),
            (1, Vec::new())
        );

        // A correctly signed confirmation of another context is not a confirmation of ours.
        let other = response(
            &sk,
            (&other_context_id, &epochs),
            (&other_context_id, &epochs),
            &extra_data,
        );
        assert!(check(&client, &other, &extra_data).is_err());

        // The epoch list in the payload must be the one the signature covers.
        let altered_epochs = response(
            &sk,
            (&context_id, &epochs[..1]),
            (&context_id, &epochs),
            &extra_data,
        );
        assert!(check(&client, &altered_epochs, &extra_data).is_err());

        // The extra data is bound into the signature too.
        assert!(check(&client, &valid, &[]).is_err());

        // A client that does not know the signer rejects the response.
        let stranger = client_knowing(gen_sig_keys(&mut rng).0);
        assert!(check(&stranger, &valid, &extra_data).is_err());
    }
}
