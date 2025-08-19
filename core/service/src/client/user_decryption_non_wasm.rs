use crate::client::client_wasm::Client;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::internal_crypto_types::UnifiedPrivateEncKey;
use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;
use crate::cryptography::signcryption::ephemeral_encryption_key_generation;
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
    pub fn user_decryption_request(
        &mut self,
        domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
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
        let (enc_pk, enc_sk) =
            ephemeral_encryption_key_generation::<ml_kem::MlKem512>(&mut self.rng);

        let mut enc_key_buf = Vec::new();
        // The key is freshly generated, so we can safely unwrap the serialization
        tfhe::safe_serialization::safe_serialize(
            &UnifiedPublicEncKey::MlKem512(enc_pk.clone()),
            &mut enc_key_buf,
            SAFE_SER_SIZE_LIMIT,
        )
        .expect("Failed to serialize ephemeral encryption key");

        Ok((
            UserDecryptionRequest {
                request_id: Some((*request_id).into()),
                enc_key: enc_key_buf,
                client_address: self.client_address.to_checksum(None),
                typed_ciphertexts,
                key_id: Some((*key_id).into()),
                domain: Some(domain_msg),
                extra_data: vec![],
            },
            UnifiedPublicEncKey::MlKem512(enc_pk),
            UnifiedPrivateEncKey::MlKem512(enc_sk),
        ))
    }

    /// This is the legacy version of the user decryption request
    /// where the encryption key is MlKem1024 serialized using bincode2.
    /// The normal version [Self::user_decryption_request] uses MlKem512 uses safe serialization.
    #[cfg(test)]
    pub(crate) fn user_decryption_request_legacy(
        &mut self,
        domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
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

        let (enc_pk, enc_sk) =
            ephemeral_encryption_key_generation::<ml_kem::MlKem1024>(&mut self.rng);

        Ok((
            UserDecryptionRequest {
                request_id: Some((*request_id).into()),
                // The key is freshly generated, so we can safely unwrap the serialization
                // NOTE: in the legacy version we do not serialize the unified version
                enc_key: bc2wrap::serialize(&enc_pk)
                    .expect("Failed to serialize ephemeral encryption key"),
                client_address: self.client_address.to_checksum(None),
                typed_ciphertexts,
                key_id: Some((*key_id).into()),
                domain: Some(domain_msg),
                extra_data: vec![],
            },
            UnifiedPublicEncKey::MlKem1024(enc_pk),
            UnifiedPrivateEncKey::MlKem1024(enc_sk),
        ))
    }
}
