use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::B256;
use anyhow::anyhow;
use cryptography::internal_crypto_types::PublicEncKey;
use kms_grpc::{
    kms::v1::UserDecryptionResponsePayload, rpc_types::UserDecryptResponseVerification,
};
#[cfg(feature = "non-wasm")]
use std::collections::HashMap;
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
    pub mod decompression;
    pub mod internal_crypto_types;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod backup;
#[cfg(feature = "non-wasm")]
pub mod conf;
pub mod engine;
#[cfg(feature = "non-wasm")]
pub mod vault;

/// Check that the hashmap has exactly one element and return it.
#[cfg(feature = "non-wasm")]
pub(crate) fn get_exactly_one<K, V>(mut hm: HashMap<K, V>) -> anyhow::Result<V>
where
    K: Clone + fmt::Debug + Eq + std::hash::Hash,
{
    if hm.values().len() != 1 {
        return Err(anyhow_error_and_log(format!(
            "Hashmap map should contain exactly one entry, but contained {} entries",
            hm.values().len(),
        )));
    }

    let req_id = some_or_err(
        hm.keys().last(),
        "impossible error: hashmap is empty".to_string(),
    )?
    .clone();

    // cannot use `some_or_err` because the derived type
    // e.g., XXXVersionedDispatchOwned does not have Debug
    hm.remove(&req_id)
        .ok_or_else(|| anyhow!("client pk hashmap is empty"))
}

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
    anyhow!("Error in {}: {}", Location::caller(), msg)
}

#[track_caller]
pub(crate) fn anyhow_error_and_warn_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::warn!("Warning in {}: {}", Location::caller(), msg);
    anyhow!("Warning in {}: {}", Location::caller(), msg)
}

#[cfg(feature = "non-wasm")]
pub fn tonic_some_or_err<T>(input: Option<T>, error: String) -> Result<T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

#[cfg(feature = "non-wasm")]
pub fn tonic_some_or_err_ref<T>(input: &Option<T>, error: String) -> Result<&T, tonic::Status> {
    input.as_ref().ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

#[cfg(feature = "non-wasm")]
pub fn tonic_some_ref_or_err<T>(input: Option<&T>, error: String) -> Result<&T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

#[cfg(feature = "non-wasm")]
pub fn tonic_handle_potential_err<T, E: ToString>(
    resp: Result<T, E>,
    error: String,
) -> Result<T, tonic::Status> {
    resp.map_err(|e| {
        let msg = format!("{}: {}", error, e.to_string());
        tracing::warn!(msg);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(msg))
    })
}

pub fn compute_user_decrypt_message_hash(
    payload: &UserDecryptionResponsePayload,
    eip712_domain: &Eip712Domain,
    user_pk: &PublicEncKey,
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

    let user_decrypted_share_buf = bincode::serialize(payload)?;

    // the solidity structure to sign with EIP-712
    // note that the JS client must also use the same encoding to verify the result
    let user_pk = bincode::serialize(user_pk)?;
    let message = UserDecryptResponseVerification {
        publicKey: user_pk.into(),
        ctHandles: external_handles,
        userDecryptedShare: user_decrypted_share_buf.into(),
    };

    let message_hash = message.eip712_signing_hash(eip712_domain);
    tracing::info!(
        "UserDecryptResponseVerification EIP-712 Message hash: {:?}",
        message_hash
    );
    Ok(message_hash)
}

// ree-export DecryptionMode
pub use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
