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
pub mod rpc_types;
pub mod solidity_types;
pub mod utils;

// Re-export identifier types for easier access
pub use identifiers::{IdentifierError, KeyId, RequestId};
