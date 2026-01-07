use anyhow::anyhow;
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
#[cfg(feature = "non-wasm")]
pub mod backup;
#[cfg(feature = "non-wasm")]
pub mod conf;
pub mod cryptography;
pub mod engine;
#[cfg(feature = "non-wasm")]
pub mod grpc;
#[cfg(feature = "non-wasm")]
pub mod vault;

#[cfg(feature = "non-wasm")]
pub use kms_grpc::utils::tonic_result::{
    box_tonic_err, ok_or_tonic_abort, some_or_tonic_abort, BoxedStatus, TonicResult,
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
