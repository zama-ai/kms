use std::panic::Location;

use anyhow::anyhow;

pub mod kms {
    tonic::include_proto!("kms"); // The string specified here must match the proto package name
}
pub mod core {
    pub mod der_types;
    pub mod kms_core;
    pub mod request;
    pub mod signcryption;
}
pub mod file_handling;
pub mod rpc{
    pub mod kms_rpc;
    pub mod rpc_types;
}


#[track_caller]
pub fn anyhow_error_and_log(msg: String) -> anyhow::Error {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    anyhow!("Error in {}: {}", Location::caller(), msg)
}
#[track_caller]
pub fn anyhow_error_and_warn_log(msg: String) -> anyhow::Error {
    tracing::warn!("Warning in {}: {}", Location::caller(), msg);
    anyhow!("Warning in {}: {}", Location::caller(), msg)
}
