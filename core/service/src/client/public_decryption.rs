use crate::anyhow_error_and_log;
use crate::client::client_wasm::Client;
use crate::engine::validation::PublicDecTrustedValidationContext;
use crate::engine::validation::validate_public_decrypt_responses_against_request;
use alloy_sol_types::Eip712Domain;
use kms_grpc::identifiers::ContextId;
use kms_grpc::kms::v1::{PublicDecryptionRequest, PublicDecryptionResponse, TypedCiphertext};
use kms_grpc::kms::v1::{SigningSchemeType, TypedPlaintext};
use kms_grpc::rpc_types::{alloy_to_protobuf_domain, optional_protobuf_to_alloy_domain};
use kms_grpc::{EpochId, RequestId};

impl Client {
    /// Creates a decryption request to send to the KMS servers.
    ///
    /// The key_id should be the request ID of the key generation
    /// request that generated the key which should be used for public decryption
    #[expect(clippy::too_many_arguments)]
    pub fn public_decryption_request(
        &mut self,
        ciphertexts: Vec<TypedCiphertext>,
        domain: &Eip712Domain,
        request_id: &RequestId,
        context_id: Option<&ContextId>,
        key_id: &RequestId,
        epoch_id: Option<&EpochId>,
        extra_data: &[u8],
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
            extra_data: extra_data.to_vec(),
            context_id: context_id.map(|c| (*c).into()),
            epoch_id: epoch_id.map(|e| (*e).into()),
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
        };
        Ok(req)
    }

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid and at least `min_agree_count` agree on the result.
    ///
    /// __NOTE__: If the original request is not provided, we can __not__ check
    /// that the response correctly contains the digest of the request.
    ///
    /// # Arguments
    ///
    /// All arguments except `agg_resp` are **trusted** (client-side state):
    ///
    /// * `request` — The original public decryption request constructed by this
    ///   client. Used to verify that the server responses match the request
    ///   (digest, ciphertext handles, domain). Pass `None` to skip request-level
    ///   checks (not recommended in production).
    /// * `min_agree_count` — Minimum number of server responses that must agree
    ///   on the same plaintext for the result to be accepted.
    ///
    /// The following argument is **untrusted** (received from the network):
    ///
    /// * `agg_resp` — The aggregated server responses. These are validated
    ///   (signatures, digest matching, majority agreement) before use.
    pub fn process_decryption_resp(
        &self,
        request: Option<PublicDecryptionRequest>,
        min_agree_count: u32,
        agg_resp: &[PublicDecryptionResponse],
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let eip712_domain = match &request {
            Some(req) => Some(optional_protobuf_to_alloy_domain(req.domain.as_ref())?),
            None => None,
        };
        let ext_handles_bytes: Vec<Vec<u8>> = match &request {
            Some(req) => req
                .ciphertexts
                .iter()
                .map(|c| c.external_handle.clone())
                .collect(),
            None => vec![],
        };
        let extra_data = request.as_ref().map(|req| req.extra_data.as_slice());
        let trusted_ctx = PublicDecTrustedValidationContext::new(
            self.get_server_pks()?,
            eip712_domain.as_ref(),
            &ext_handles_bytes,
            extra_data,
            request.as_ref(),
        )?;

        // Partition the untrusted responses and enforce the majority threshold. Partitioning is
        // infallible w.r.t. any individual response's content — a Byzantine party can only land
        // itself in `rejected` — so a single malformed signature or verification key can not
        // abort the whole decryption.
        // The plaintext result is a consensus value read from the established
        // invariants, never from one contribution.
        let partitioned = validate_public_decrypt_responses_against_request(
            &trusted_ctx,
            min_agree_count,
            agg_resp,
        )?;

        Ok(partitioned.invariants.plaintexts)
    }
}
