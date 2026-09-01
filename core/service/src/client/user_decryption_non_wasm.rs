use crate::client::client_wasm::Client;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use kms_grpc::RequestId;
use kms_grpc::kms::v1::SigningSchemeType;
use kms_grpc::kms::v1::{SigningMetadata, TypedCiphertext, UserDecryptionRequest};
use kms_grpc::rpc_types::alloy_to_protobuf_domain;
use kms_grpc::{ContextId, EpochId};

impl Client {
    /// Creates a user decryption request to send to the KMS servers.
    /// Returns the full [UserDecryptionRequest] containing
    /// the payload to send to the servers, along with the generated
    /// user decryption key pair.
    /// The private key is used to decrypt the responses from the servers,
    /// and must be kept to process the responses.
    ///
    /// Note that we only support MlKem512 in the latest version and not other variants of MlKem.
    #[allow(unknown_lints)]
    // We allow modifying the internal rng before return
    #[allow(non_local_effect_before_error_return, clippy::too_many_arguments)]
    pub fn user_decryption_request(
        &mut self,
        domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
        context_id: Option<&ContextId>,
        epoch_id: Option<&EpochId>,
        extra_data: &[u8],
    ) -> anyhow::Result<(
        UserDecryptionRequest,
        UnifiedPublicEncKey,
        UnifiedPrivateEncKey,
    )> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }
        let _client_sk = some_or_err(
            self.client_sk.clone(),
            "missing client signing key".to_string(),
        )?;

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut self.rng);
        let (enc_sk, enc_pk) = encryption.keygen()?;

        Ok((
            UserDecryptionRequest {
                request_id: Some((*request_id).into()),
                enc_key: {
                    let mut buf = Vec::new();
                    tfhe::safe_serialization::safe_serialize(
                        &enc_pk,
                        &mut buf,
                        SAFE_SER_SIZE_LIMIT,
                    )
                    .expect("Failed to serialize ephemeral encryption key");
                    buf
                },
                client_address: self.client_address.to_checksum(None),
                typed_ciphertexts,
                key_id: Some((*key_id).into()),
                domain: Some(domain_msg),
                extra_data: extra_data.to_vec(),
                context_id: context_id.map(|c| (*c).into()),
                epoch_id: epoch_id.map(|e| (*e).into()),
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                // This builder is the EVM shape; a Solana request is built by
                // [`Self::solana_user_decryption_request`] instead.
                signing_metadata: vec![],
            },
            enc_pk,
            enc_sk,
        ))
    }

    /// Like [`Self::user_decryption_request`], for a Solana-settled request: the identity is the
    /// user's 32-byte ed25519 key inside the request's one [`SigningMetadata`] entry, together
    /// with the host deployment's verifying program id, and `client_address` stays empty — the
    /// exact shape the KMS Connector produces, so a reference client sending this exercises the
    /// same server path.
    ///
    /// `response_domain` is the EIP-712 domain the KMS nodes sign the response under (the gateway
    /// domain in production); it plays no part in who can open the result.
    #[allow(unknown_lints)]
    // We allow modifying the internal rng before return
    #[allow(non_local_effect_before_error_return, clippy::too_many_arguments)]
    pub fn solana_user_decryption_request(
        &mut self,
        response_domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
        context_id: Option<&ContextId>,
        epoch_id: Option<&EpochId>,
        extra_data: &[u8],
        user_pubkey: [u8; 32],
        verifying_program_id: [u8; 32],
    ) -> anyhow::Result<(
        UserDecryptionRequest,
        UnifiedPublicEncKey,
        UnifiedPrivateEncKey,
    )> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain_msg = alloy_to_protobuf_domain(response_domain)?;

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut self.rng);
        let (enc_sk, enc_pk) = encryption.keygen()?;

        Ok((
            UserDecryptionRequest {
                request_id: Some((*request_id).into()),
                enc_key: {
                    let mut buf = Vec::new();
                    tfhe::safe_serialization::safe_serialize(
                        &enc_pk,
                        &mut buf,
                        SAFE_SER_SIZE_LIMIT,
                    )
                    .expect("Failed to serialize ephemeral encryption key");
                    buf
                },
                // Empty by rule: the Solana identity travels in the envelope below, and the
                // server rejects a request carrying both.
                client_address: String::new(),
                typed_ciphertexts,
                key_id: Some((*key_id).into()),
                domain: Some(domain_msg),
                extra_data: extra_data.to_vec(),
                context_id: context_id.map(|c| (*c).into()),
                epoch_id: epoch_id.map(|e| (*e).into()),
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                signing_metadata: vec![SigningMetadata::solana(
                    user_pubkey.to_vec(),
                    verifying_program_id.to_vec(),
                )],
            },
            enc_pk,
            enc_sk,
        ))
    }
}
