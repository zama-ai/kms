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

#[cfg(any(feature = "non-wasm", test))]
use crate::cryptography::signatures::PrivateSigKey;
#[cfg(any(feature = "non-wasm", test))]
use crate::cryptography::signatures::compute_eip712_signature;
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
    user_pk_buf: &[u8],
    extra_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let message = compute_user_decrypt_message(payload, user_pk_buf, extra_data)?;
    tracing::debug!("Computing signature for UserDecryptResponseVerification");
    compute_eip712_signature(server_sk, &message, eip712_domain)
}

pub(crate) fn compute_user_decrypt_message(
    payload: &UserDecryptionResponsePayload,
    user_pk_buf: &[u8],
    extra_data: &[u8],
) -> anyhow::Result<UserDecryptResponseVerification> {
    // convert external_handles back to 256-bit bytes32 to be signed
    let external_handles_bytes32: Vec<_> = payload
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

    tracing::info!(
        "Computed UserDecryptResponseVerification for handles {:?} and extra data \"{}\".",
        external_handles_bytes32,
        hex::encode(extra_data)
    );

    Ok(UserDecryptResponseVerification {
        publicKey: user_pk_buf.to_vec().into(),
        ctHandles: external_handles_bytes32,
        userDecryptedShare: user_decrypted_share_buf.into(),
        extraData: extra_data.to_vec().into(),
    })
}
