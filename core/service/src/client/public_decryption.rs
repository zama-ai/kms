use crate::client::client_wasm::Client;
use crate::cryptography::signatures::{internal_verify_sig, PublicSigKey, Signature};
use crate::engine::validation::validate_public_decrypt_responses_against_request;
use crate::engine::validation::DSEP_PUBLIC_DECRYPTION;
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use kms_grpc::identifiers::ContextId;
use kms_grpc::kms::v1::TypedPlaintext;
use kms_grpc::kms::v1::{PublicDecryptionRequest, PublicDecryptionResponse, TypedCiphertext};
use kms_grpc::rpc_types::alloy_to_protobuf_domain;
use kms_grpc::RequestId;

impl Client {
    /// Creates a decryption request to send to the KMS servers.
    ///
    /// The key_id should be the request ID of the key generation
    /// request that generated the key which should be used for public decryption
    pub fn public_decryption_request(
        &mut self,
        ciphertexts: Vec<TypedCiphertext>,
        domain: &Eip712Domain,
        request_id: &RequestId,
        context_id: Option<&ContextId>,
        key_id: &RequestId,
    ) -> anyhow::Result<PublicDecryptionRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let req = PublicDecryptionRequest {
            ciphertexts,
            key_id: Some((*key_id).into()),
            domain: Some(domain_msg),
            request_id: Some((*request_id).into()),
            extra_data: vec![],
            context_id: context_id.map(|c| (*c).into()),
            epoch_id: None,
        };
        Ok(req)
    }

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid and at least [min_agree_count] agree on the result.
    /// Returns `None` if validation fails.
    ///
    /// __NOTE__: If the original request is not provided, we can __not__ check
    /// that the response correctly contains the digest of the request.
    pub fn process_decryption_resp(
        &self,
        request: Option<PublicDecryptionRequest>,
        agg_resp: &[PublicDecryptionResponse],
        min_agree_count: u32,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        use crate::engine::validation::select_most_common_public_dec;

        validate_public_decrypt_responses_against_request(
            self.get_server_pks()?,
            request,
            agg_resp,
            min_agree_count,
        )?;

        let pivot_payload = some_or_err(
            select_most_common_public_dec(min_agree_count as usize, agg_resp),
            "No elements in public decryption response".to_string(),
        )?;

        for cur_resp in agg_resp {
            let cur_payload = some_or_err(
                cur_resp.payload.to_owned(),
                "No payload in current response!".to_string(),
            )?;
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };

            // Observe that it has already been verified in [self.validate_meta_data] that server
            // verification key is in the set of permissible keys
            let cur_verf_key: PublicSigKey =
                bc2wrap::deserialize_safe(&cur_payload.verification_key)?;
            internal_verify_sig(
                &DSEP_PUBLIC_DECRYPTION,
                &bc2wrap::serialize(&cur_payload)?,
                &sig,
                &cur_verf_key,
            )
            .inspect_err(|e| {
                tracing::warn!("Signature on received response is not valid! {}", e);
            })?;
        }
        Ok(pivot_payload.plaintexts)
    }
}
