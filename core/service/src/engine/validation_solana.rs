use crate::cryptography::encryption::UnifiedPublicEncKey;
use alloy_primitives::Address;
use kms_grpc::{
    kms::v1::UserDecryptionRequest,
    rpc_types::{SolanaUserDecryptBinding, optional_protobuf_to_alloy_domain},
};

type SolanaUserDecryptValidation = (Vec<u8>, Address, alloy_sol_types::Eip712Domain);

/// Validates the Solana-owned fields of a user-decryption request.
///
/// An unset Solana pubkey leaves the request on the unchanged EVM path. Solana authorization is
/// enforced by the connector before this call; this validation binds the KMS response to the
/// typed pubkey, encryption key, ciphertext handles, and response-signing domain.
pub(super) fn validate_user_decrypt_req(
    req: &UserDecryptionRequest,
) -> Result<Option<SolanaUserDecryptValidation>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pubkey) = req.solana_pubkey.as_deref() else {
        return Ok(None);
    };
    let pubkey = <[u8; 32]>::try_from(pubkey).map_err(|_| {
        anyhow::anyhow!(
            "Solana client identity must be a 32-byte pubkey, got {} bytes",
            pubkey.len()
        )
    })?;
    if !req.client_address.is_empty() {
        return Err(
            anyhow::anyhow!("Solana user decryption request must not set client_address").into(),
        );
    }

    let binding = SolanaUserDecryptBinding::try_from_handle_bytes(
        req.typed_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.external_handle.as_slice()),
    )?;
    let link = binding.compute_link(&req.enc_key, &pubkey);
    let client_id = solana_user_decrypt_client_id(&pubkey);

    UnifiedPublicEncKey::deserialize_and_validate(&req.enc_key).map_err(|error| {
        anyhow::anyhow!(
            "Error deserializing UnifiedPublicEncKey from Solana UserDecryptionRequest: {error}"
        )
    })?;
    let response_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    Ok(Some((link, client_id, response_domain)))
}

/// Derives the 20-byte signcryption client ID as `keccak256(pubkey)[12..]`, mirroring EVM
/// address derivation. It is a deterministic response label, not an authorization input.
fn solana_user_decrypt_client_id(pubkey: &[u8; 32]) -> Address {
    Address::from_slice(&alloy_primitives::keccak256(pubkey)[12..])
}

#[cfg(test)]
mod tests {
    use super::solana_user_decrypt_client_id;

    #[test]
    fn client_id_is_keccak_derived_and_deterministic() {
        let pubkey = [0x22u8; 32];
        let id = solana_user_decrypt_client_id(&pubkey);
        assert_eq!(id, solana_user_decrypt_client_id(&pubkey));
        assert_eq!(id.as_slice(), &alloy_primitives::keccak256(pubkey)[12..]);

        let mut other = pubkey;
        other[0] ^= 0xff;
        assert_ne!(id, solana_user_decrypt_client_id(&other));
    }
}
