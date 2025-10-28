use crate::client::client_wasm::Client;
use crate::cryptography::encryption::{
    Encryption, EncryptionScheme, EncryptionSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::internal_crypto_types::LegacySerialization;
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use kms_grpc::kms::v1::{TypedCiphertext, UserDecryptionRequest};
use kms_grpc::rpc_types::alloy_to_protobuf_domain;
use kms_grpc::RequestId;

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
    #[allow(non_local_effect_before_error_return)]
    pub fn user_decryption_request(
        &mut self,
        domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
        encryption_scheme: EncryptionSchemeType,
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

        // NOTE: we only support MlKem512 in the latest version
        let mut encryption = Encryption::new(encryption_scheme, &mut self.rng);
        let (enc_sk, enc_pk) = encryption.keygen()?;

        Ok((
            UserDecryptionRequest {
                request_id: Some((*request_id).into()),
                enc_key: enc_pk
                    .to_legacy_bytes()
                    .expect("Failed to serialize ephemeral encryption key"),
                client_address: self.client_address.to_checksum(None),
                typed_ciphertexts,
                key_id: Some((*key_id).into()),
                domain: Some(domain_msg),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            },
            enc_pk,
            enc_sk,
        ))
    }
}
