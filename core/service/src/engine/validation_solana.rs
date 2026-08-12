use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
use crate::cryptography::encryption::UnifiedPublicEncKey;
use kms_grpc::identifiers::{ContextId, EpochId};
use kms_grpc::{
    kms::v1::UserDecryptionRequest,
    rpc_types::{SigncryptionReceiver, optional_protobuf_to_alloy_domain},
    solana_binding::{SOLANA_IDENTITY_LEN, SolanaUserDecryptBinding},
};

/// What the adapter hands to the shared engine: the request's link, the recipient the result is
/// sealed to, and the domain the response signature is produced under.
type SolanaValidation = (Vec<u8>, SigncryptionReceiver, alloy_sol_types::Eip712Domain);

/// Builds the canonical binding for a Solana user-decryption request.
///
/// Returns `Ok(None)` for a request that carries no Solana identity: that request belongs to the
/// EVM path, which this function must leave exactly as it found it.
///
/// The adapter is where host knowledge ends. It reads the typed Solana fields, hands them to the
/// checked binding, and returns bytes — it does not parse relayer payloads, wallet signatures,
/// PDAs, ACL or MMR evidence, or delegation policy, all of which are settled before a request
/// reaches any KMS party. It also does not parse `extra_data`: the KMS is agnostic to its content
/// by design, and the values the linker commits to arrive as typed fields, parsed by the connector
/// that verified the signature over them.
pub(super) fn validate_solana_request(
    req: &UserDecryptionRequest,
) -> Result<Option<SolanaValidation>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pubkey) = req.solana_pubkey.as_deref() else {
        // A request that carries the other Solana field without the identity is contradictory, not
        // EVM: reinterpreting it silently would surface a connector bug as a client-side link
        // mismatch instead of an error that names the field.
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

    // The KMS binds the same context and epoch it selects keys by, taken from the typed fields the
    // connector parsed out of the signed request. The defaults mirror the shared request path, so a
    // request that omits them is bound to the values the KMS actually used.
    let context_id: ContextId = match &req.context_id {
        Some(context_id) => context_id.try_into()?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId = match &req.epoch_id {
        Some(epoch_id) => epoch_id.try_into()?,
        None => *DEFAULT_EPOCH_ID,
    };

    let transport_key =
        UnifiedPublicEncKey::deserialize_and_validate(&req.enc_key).map_err(|error| {
            anyhow::anyhow!(
                "Error deserializing UnifiedPublicEncKey from Solana UserDecryptionRequest: {error}"
            )
        })?;
    require_mlkem512_transport_key(&transport_key)?;

    // The one construction, given the request's own bytes: the transport key exactly as the request
    // carries it, and the handles in request order with duplicates preserved.
    let binding = SolanaUserDecryptBinding::new(
        verifying_program_id,
        &pubkey,
        context_id.as_bytes(),
        epoch_id.as_bytes(),
        req.typed_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.external_handle.as_slice()),
        &req.enc_key,
    )?;

    let response_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    // Read back off the binding rather than from the request: a value that failed validation has no
    // path to signcryption.
    Ok(Some((
        binding.compute_link(),
        SigncryptionReceiver::Solana(*binding.receiver_id()),
        response_domain,
    )))
}

/// An allow-list of one: the Solana path pins its transport key to ML-KEM-512. Deserialization
/// already rejects ML-KEM-1024 on every path, so today this cannot fire — it is defense-in-depth
/// for the day deserialization admits another variant again. Deliberately not a match on the other
/// variants: a future variant should have to be admitted here explicitly rather than inherited.
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
