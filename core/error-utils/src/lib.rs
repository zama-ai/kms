use core::fmt;
use std::panic::Location;

use anyhow::anyhow;

#[track_caller]
pub fn anyhow_error_and_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    anyhow!("Error in {}: {}", Location::caller(), msg)
}

#[track_caller]
pub fn anyhow_error_and_warn_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::warn!("Warning in {}: {}", Location::caller(), msg);
    anyhow!("Warning in {}: {}", Location::caller(), msg)
}

pub fn log_error_wrapper<S: AsRef<str> + fmt::Display>(msg: S) -> S {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    msg
}
