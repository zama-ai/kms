#[cfg(feature = "non-wasm")]
pub mod attestation;
pub mod decompression;
pub mod error;
pub mod hybrid_ml_kem;
pub mod internal_crypto_types;
pub mod signatures;
// Allow our deprecated modules for now as we need to be backwards compatible
#[allow(deprecated)]
pub mod encryption;
#[allow(deprecated)]
pub mod signcryption;

use crate::cryptography::encryption::UnifiedPublicEncKey;
use crate::cryptography::internal_crypto_types::LegacySerialization;
#[cfg(any(feature = "non-wasm", test))]
use crate::cryptography::signatures::compute_eip712_signature;
#[cfg(any(feature = "non-wasm", test))]
use crate::cryptography::signatures::PrivateSigKey;
#[cfg(any(feature = "non-wasm", test))]
use alloy_dyn_abi::Eip712Domain;
use kms_grpc::{
    kms::v1::UserDecryptionResponsePayload, solidity_types::UserDecryptResponseVerification,
};

#[cfg(any(feature = "non-wasm", test))]
pub(crate) fn compute_external_user_decrypt_signature(
    server_sk: &PrivateSigKey,
    payload: &UserDecryptionResponsePayload,
    eip712_domain: &Eip712Domain,
    user_pk: &UnifiedPublicEncKey,
    extra_data: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let message = compute_user_decrypt_message(payload, user_pk, extra_data)?;
    tracing::debug!("Computing signature for UserDecryptResponseVerification");
    compute_eip712_signature(server_sk, &message, eip712_domain)
}

pub(crate) fn compute_user_decrypt_message(
    payload: &UserDecryptionResponsePayload,
    user_pk: &UnifiedPublicEncKey,
    extra_data: Vec<u8>,
) -> anyhow::Result<UserDecryptResponseVerification> {
    let external_handles: Vec<_> = payload
        .signcrypted_ciphertexts
        .iter()
        .enumerate()
        .map(|(idx, c)| {
            if c.external_handle.len() > 32 {
                anyhow::bail!(
                    "external_handle at index {idx} too long: {} bytes (max 32)",
                    c.external_handle.len()
                );
            } else {
                Ok(alloy_primitives::FixedBytes::<32>::left_padding_from(
                    c.external_handle.as_slice(),
                ))
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let user_decrypted_share_buf = bc2wrap::serialize(payload)?;

    // LEGACY CODE: we used to only support ML-KEM1024 encoded with bincode
    // the solidity structure to sign with EIP-712
    // note that the JS client must also use the same encoding to verify the result
    let user_pk_buf = user_pk
        .to_legacy_bytes()
        .map_err(|e| anyhow::anyhow!("serialization error: {e}"))?;

    tracing::info!(
        "Computed UserDecryptResponseVerification for handles {:?} and extra data {}.",
        external_handles,
        hex::encode(&extra_data)
    );

    Ok(UserDecryptResponseVerification {
        publicKey: user_pk_buf.into(),
        ctHandles: external_handles,
        userDecryptedShare: user_decrypted_share_buf.into(),
        extraData: extra_data.into(),
    })
}
