use crate::cryptography::encryption::UnifiedPublicEncKey;
use kms_grpc::{
    kms::v1::{SolanaMetadata, UserDecryptionRequest, signing_metadata::Metadata},
    rpc_types::{PlaintextReceiver, optional_protobuf_to_alloy_domain},
    solana_binding::{SOLANA_IDENTITY_LEN, SolanaUserDecryptBinding},
};

/// What the adapter hands to the shared engine: the request's link, the recipient the result is
/// sealed to, and the domain the response signature is produced under.
type SolanaValidation = (Vec<u8>, PlaintextReceiver, alloy_sol_types::Eip712Domain);

/// Builds the canonical binding for a Solana user-decryption request, or returns `Ok(None)` for a
/// request that carries no signing metadata — that request belongs to the EVM path.
///
/// The adapter is where host knowledge ends: it reads the request's Solana envelope, hands it to
/// the checked binding, and returns bytes. Wallet signatures, PDAs, ACL/MMR evidence and
/// delegation are all settled upstream, by the connector that verified the signed request;
/// `extra_data` is the host-side metadata of that settled request, bound verbatim by the linker
/// and never parsed here.
pub(super) fn validate_solana_request(
    req: &UserDecryptionRequest,
) -> Result<Option<SolanaValidation>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(solana) = require_solana_metadata(req)? else {
        return Ok(None);
    };
    let pubkey = <[u8; SOLANA_IDENTITY_LEN]>::try_from(solana.pubkey.as_slice()).map_err(|_| {
        anyhow::anyhow!(
            "Solana client identity must be a 32-byte pubkey, got {} bytes",
            solana.pubkey.len()
        )
    })?;
    if !req.client_address.is_empty() {
        return Err(
            anyhow::anyhow!("Solana user decryption request must not set client_address").into(),
        );
    }

    let verifying_program_id = solana.verifying_program_id.as_slice();

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
        PlaintextReceiver::Solana(*binding.receiver_id()),
        response_domain,
    )))
}

/// The one Solana envelope of a request, `Ok(None)` for an EVM request (empty list), or the
/// reason the metadata list cannot be dispatched.
///
/// One entry is a rule of this version, not of the wire: the field is repeated so that a future
/// batch of host requests is a validation change, not a schema change. The Ethereum variant is
/// declared empty and is not how an EVM request travels today — those leave the list empty — so
/// carrying it is a mistake to surface, never a silent EVM fallback.
fn require_solana_metadata(
    req: &UserDecryptionRequest,
) -> Result<Option<&SolanaMetadata>, Box<dyn std::error::Error + Send + Sync>> {
    let entry = match req.signing_metadata.as_slice() {
        [] => return Ok(None),
        [entry] => entry,
        more => {
            return Err(anyhow::anyhow!(
                "user decryption request carries {} signing_metadata entries; this version \
                 accepts exactly one",
                more.len()
            )
            .into());
        }
    };

    match &entry.metadata {
        Some(Metadata::Solana(solana)) => Ok(Some(solana)),
        Some(Metadata::Ethereum(_)) => Err(anyhow::anyhow!(
            "signing_metadata carries the ethereum variant, which is declared empty and carries \
             nothing to verify against; an EVM request leaves signing_metadata empty"
        )
        .into()),
        None => Err(anyhow::anyhow!(
            "signing_metadata entry names no host variant; a party that cannot dispatch a \
             request must refuse it rather than guess"
        )
        .into()),
    }
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
