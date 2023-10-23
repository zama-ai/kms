use std::panic::Location;

use anyhow::anyhow;

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

mod tests {
    #[cfg(test)]
    #[tracing_test::traced_test]
    #[test]
    #[allow(clippy::unnecessary_literal_unwrap, clippy::useless_format)]
    fn test_log() {
        use crate::error::error_handler::anyhow_error_and_log;

        let _err = Err::<(), anyhow::Error>(anyhow_error_and_log(format!("(test_log), msg",)));
        assert!(logs_contain("src/error/error_handler.rs"));
        assert!(logs_contain("(test_log), msg"));
        assert!(logs_contain("Error in"));
    }

    #[cfg(test)]
    #[tracing_test::traced_test]
    #[test]
    #[allow(clippy::unnecessary_literal_unwrap, clippy::useless_format)]
    fn test_warn_log() {
        use crate::error::error_handler::anyhow_error_and_warn_log;

        let _err =
            Err::<(), anyhow::Error>(anyhow_error_and_warn_log(format!("(test_warn_log), msg",)));
        assert!(logs_contain("src/error/error_handler.rs"));
        assert!(logs_contain("(test_warn_log), msg"));
        assert!(logs_contain("Warning in"));
    }
}
