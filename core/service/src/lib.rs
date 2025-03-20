use anyhow::anyhow;
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
pub mod conf;
#[cfg(feature = "non-wasm")]
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
        .ok_or(anyhow!("client pk hashmap is empty"))
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

// ree-export DecryptionMode
pub use distributed_decryption::execution::endpoints::decryption::DecryptionMode;
