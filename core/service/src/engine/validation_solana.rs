use crate::cryptography::encryption::UnifiedPublicEncKey;
use kms_grpc::{
    kms::v1::UserDecryptionRequest,
    rpc_types::{SigncryptionReceiver, optional_protobuf_to_alloy_domain},
    solana_binding::{SOLANA_IDENTITY_LEN, SolanaUserDecryptBinding},
};

/// What the adapter hands to the shared engine: the request's link, the recipient the result is
/// sealed to, and the domain the response signature is produced under.
type SolanaValidation = (Vec<u8>, SigncryptionReceiver, alloy_sol_types::Eip712Domain);

/// Builds the canonical binding for a Solana user-decryption request, or returns `Ok(None)` for a
/// request that carries no Solana identity — that request belongs to the EVM path.
///
/// The adapter is where host knowledge ends: it reads the typed Solana fields, hands them to the
/// checked binding, and returns bytes. Wallet signatures, PDAs, ACL/MMR evidence and delegation
/// are all settled upstream, by the connector that verified the signed request; `extra_data` is
/// the host-side metadata of that settled request, bound verbatim by the linker and never parsed
/// here.
pub(super) fn validate_solana_request(
    req: &UserDecryptionRequest,
) -> Result<Option<SolanaValidation>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pubkey) = req.solana_pubkey.as_deref() else {
        // The other Solana field without the identity is a contradictory request, not an EVM one.
        if req.solana_verifying_program_id.is_some() {
            return Err(anyhow::anyhow!(
                "user decryption request sets solana_verifying_program_id without solana_pubkey"
            )
            .into());
        }
        return Ok(None);
    };
    let pubkey = <[u8; SOLANA_IDENTITY_LEN]>::try_from(pubkey).map_err(|_| {
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

    let verifying_program_id = req.solana_verifying_program_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "Solana user decryption request must set solana_verifying_program_id, half of the \
             deployment domain the response is bound to"
        )
    })?;

    let transport_key =
        UnifiedPublicEncKey::deserialize_and_validate(&req.enc_key).map_err(|error| {
            anyhow::anyhow!(
                "Error deserializing UnifiedPublicEncKey from Solana UserDecryptionRequest: {error}"
            )
        })?;
    require_mlkem512_transport_key(&transport_key)?;

    // The one construction, given the request's own bytes.
    let binding = SolanaUserDecryptBinding::new(
        verifying_program_id,
        &pubkey,
        req.typed_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.external_handle.as_slice()),
        &req.enc_key,
        &req.extra_data,
    )?;

    let response_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    // Read back off the binding, not the request: a value that failed validation has no path to
    // signcryption.
    Ok(Some((
        binding.compute_link(),
        SigncryptionReceiver::Solana(*binding.receiver_id()),
        response_domain,
    )))
}

/// An allow-list of one: the Solana path pins its transport key to ML-KEM-512. Deserialization
/// already rejects everything else today; a future variant must be admitted here explicitly.
fn require_mlkem512_transport_key(
    transport_key: &UnifiedPublicEncKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !matches!(transport_key, UnifiedPublicEncKey::MlKem512(_)) {
        return Err(
            anyhow::anyhow!("Solana user decryption requires an ML-KEM-512 transport key").into(),
        );
    }
    Ok(())
}
