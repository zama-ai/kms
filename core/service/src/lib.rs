use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::B256;
use anyhow::anyhow;
use kms_grpc::{
    kms::v1::UserDecryptionResponsePayload, rpc_types::UserDecryptResponseVerification,
};
use std::{fmt, panic::Location};

pub mod client;
pub mod consts;

#[cfg(feature = "non-wasm")]
pub mod util {
    pub mod file_handling;
    pub mod key_setup;
    pub mod meta_store;
    #[cfg(any(test, feature = "testing", feature = "insecure"))]
    pub mod random_free_port;
    pub mod rate_limiter;
    pub mod retry;
}
pub mod cryptography {
    #[cfg(feature = "non-wasm")]
    pub mod attestation;
    pub mod backup_pke;
    pub mod decompression;
    pub mod error;
    pub mod hybrid_ml_kem;
    pub mod internal_crypto_types;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod backup;
#[cfg(feature = "non-wasm")]
pub mod conf;
pub mod engine;
#[cfg(feature = "non-wasm")]
pub mod grpc;
#[cfg(feature = "non-wasm")]
pub mod vault;

#[cfg(feature = "non-wasm")]
pub use kms_grpc::utils::tonic_result::{
    box_tonic_err, tonic_handle_potential_err, tonic_some_or_err, tonic_some_or_err_ref,
    tonic_some_ref_or_err, BoxedStatus, TonicResult,
};

/// Truncate s to a maximum of 128 chars.
pub(crate) fn top_n_chars(mut s: String) -> String {
    s.truncate(128);
    s
}

/// Helper method for returning the optional value of `input` if it exists, otherwise
/// returning a custom anyhow error.
pub fn some_or_err<T>(input: Option<T>, error: String) -> anyhow::Result<T> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        anyhow!("Missing value: {}", top_n_chars(error.to_string()))
    })
}

// NOTE: the below is copied from core/threshold
// since the calling tracing from another crate
// does not generate correct logs in tracing_test::traced_test
#[track_caller]
pub(crate) fn anyhow_error_and_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    anyhow_tracked(msg)
}

#[track_caller]
pub(crate) fn anyhow_tracked<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    anyhow!("Error in {}: {}", Location::caller(), msg)
}

#[cfg(feature = "non-wasm")]
#[track_caller]
pub(crate) fn anyhow_error_and_warn_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::warn!("Warning in {}: {}", Location::caller(), msg);
    anyhow!("Warning in {}: {}", Location::caller(), msg)
}

pub fn compute_user_decrypt_message_hash(
    payload: &UserDecryptionResponsePayload,
    eip712_domain: &Eip712Domain,
    user_pk: &UnifiedPublicEncKey,
    extra_data: Vec<u8>,
) -> anyhow::Result<B256> {
    use alloy_sol_types::SolStruct;
    // convert external_handles back to bytes32 to be signed
    let external_handles: Vec<_> = payload
        .signcrypted_ciphertexts
        .iter()
        .map(|e| {
            alloy_primitives::FixedBytes::<32>::left_padding_from(e.external_handle.as_slice())
        })
        .collect();

    let user_decrypted_share_buf = bc2wrap::serialize(payload)?;

    // the solidity structure to sign with EIP-712
    // note that the JS client must also use the same encoding to verify the result
    let user_pk_buf = user_pk.bytes_for_hashing()?;
    let message = UserDecryptResponseVerification {
        publicKey: user_pk_buf.into(),
        ctHandles: external_handles,
        userDecryptedShare: user_decrypted_share_buf.into(),
        extraData: extra_data.into(),
    };

    let message_hash = message.eip712_signing_hash(eip712_domain);
    tracing::info!(
        "UserDecryptResponseVerification EIP-712 Message hash: {:?}",
        message_hash
    );
    Ok(message_hash)
}

/// Create a dummy domain for testing
#[cfg(any(test, all(feature = "non-wasm", feature = "testing")))]
pub(crate) fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
    )
}

// re-export DecryptionMode
pub use threshold_fhe::execution::endpoints::decryption::DecryptionMode;

use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;
