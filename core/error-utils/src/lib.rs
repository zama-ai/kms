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

#[cfg(feature = "non-wasm")]
pub fn log_error_wrapper<S: AsRef<str> + fmt::Display>(msg: S) -> S {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    msg
}

#[cfg(test)]
mod tests {
    use super::{anyhow_error_and_log, anyhow_error_and_warn_log};

    #[test]
    #[tracing_test::traced_test]
    fn test_log() {
        let _ = anyhow_error_and_log("(test_log), msg");
        assert!(logs_contain("src/lib.rs"));
        assert!(logs_contain("(test_log), msg"));
        assert!(logs_contain("Error in"));
    }

    #[tracing_test::traced_test]
    #[test]
    fn test_warn_log() {
        let _ = anyhow_error_and_warn_log("(test_warn_log), msg");
        assert!(logs_contain("src/lib.rs"));
        assert!(logs_contain("(test_warn_log), msg"));
        assert!(logs_contain("Warning in"));
    }
}
