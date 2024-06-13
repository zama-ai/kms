use anyhow::anyhow;
use std::fmt;
use std::panic::Location;

// copied from tonic since we're cannot pull in tonic for wasm
macro_rules! my_include_proto {
    ($package: tt) => {
        include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
    };
}
pub mod kms {
    my_include_proto!("kms"); // The string specified here must match the proto package name
}
pub mod client;
pub mod consts;
#[cfg(feature = "non-wasm")]
pub mod util {
    pub mod aws;
    pub mod file_handling;
    pub mod key_setup;
}
pub mod cryptography {
    #[cfg(feature = "non-wasm")]
    pub mod central_kms;
    pub mod der_types;
    pub mod nitro_enclave;
    #[cfg(feature = "non-wasm")]
    pub mod request;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod threshold {
    pub mod meta_store;
    #[cfg(any(test, feature = "testing"))]
    pub mod mock_threshold_kms;
    pub mod threshold_kms;
}
#[cfg(feature = "non-wasm")]
pub mod storage;
pub mod rpc {
    #[cfg(feature = "non-wasm")]
    pub mod central_rpc;
    #[cfg(feature = "non-wasm")]
    pub mod central_rpc_proxy;
    pub mod rpc_types;
}
#[cfg(feature = "non-wasm")]
pub mod conf;

/// Take the max(20, s.len()) characters of s.
pub(crate) fn top_n_chars(mut s: String) -> String {
    let n = std::cmp::max(s.len(), 20);
    _ = s.split_off(n);
    s
}

/// Helper method for returning the optional value of `input` if it exists, otherwise
/// returning a custom anyhow error.
pub fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> anyhow::Result<T> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        anyhow!("Invalid request: {}", top_n_chars(error.to_string()))
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
