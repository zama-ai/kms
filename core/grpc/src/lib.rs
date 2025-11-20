// copied from tonic since we're cannot pull in tonic for wasm
macro_rules! my_include_proto {
    ($package: tt) => {
        include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
    };
}
pub mod kms {
    pub mod v1 {
        my_include_proto!("kms.v1");
    }
}

#[cfg(feature = "non-wasm")]
pub mod kms_service {
    pub mod v1 {
        my_include_proto!("kms_service.v1");
    }
}

#[cfg(feature = "non-wasm")]
pub mod metastore_status {
    pub mod v1 {
        my_include_proto!("metastore_status.v1");
    }
}

pub mod identifiers;
// PRSSSetup variant of PrivDataType is deprecated.
#[expect(deprecated)]
pub mod rpc_types;
pub mod solidity_types;
pub mod utils;

// Re-export identifier types for easier access
pub use identifiers::{ContextId, IdentifierError, KeyId, RequestId};

#[cfg(feature = "non-wasm")]
use anyhow::anyhow;
#[cfg(feature = "non-wasm")]
use std::{fmt, panic::Location};

// NOTE: the below is copied from core/threshold
// since the calling tracing from another crate
// does not generate correct logs in tracing_test::traced_test
#[cfg(feature = "non-wasm")]
#[track_caller]
pub(crate) fn anyhow_error_and_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    anyhow_tracked(msg)
}

#[cfg(feature = "non-wasm")]
#[track_caller]
pub(crate) fn anyhow_tracked<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    anyhow!("Error in {}: {}", Location::caller(), msg)
}
