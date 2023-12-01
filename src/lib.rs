use std::panic::Location;

use anyhow::anyhow;

pub mod encryption;
pub mod file_handling;

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
