//! Utilities for working with tonic::Status errors in Results

// This module is structured to be available in both wasm and non-wasm builds.
// The tonic-related code is gated behind the non-wasm feature flag.

#[cfg(feature = "non-wasm")]
mod non_wasm {
    use tracing;

    /// Truncates a string to a maximum of 1024 chars to limit error message size.
    pub(crate) fn top_1k_chars(mut s: String) -> String {
        s.truncate(1024);
        s
    }

    /// A memory-efficient wrapper around Box<tonic::Status>
    ///
    /// Reduces the size of Result variants by boxing tonic::Status (176+ bytes),
    /// addressing the clippy::result_large_err warning.
    #[derive(Debug)]
    pub struct BoxedStatus(Box<tonic::Status>);

    impl std::fmt::Display for BoxedStatus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for BoxedStatus {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }

    impl From<BoxedStatus> for tonic::Status {
        fn from(boxed: BoxedStatus) -> Self {
            *boxed.0
        }
    }

    impl From<tonic::Status> for BoxedStatus {
        fn from(status: tonic::Status) -> Self {
            BoxedStatus(Box::new(status))
        }
    }

    /// Type alias for Result with boxed tonic::Status
    pub type TonicResult<T> = Result<T, BoxedStatus>;

    /// Converts a Result<T, tonic::Status> to a TonicResult<T>
    pub fn box_tonic_err<T>(result: Result<T, tonic::Status>) -> TonicResult<T> {
        result.map_err(BoxedStatus::from)
    }

    /// Converts an Option<T> to a TonicResult<T>, an aborted status is used if None.
    ///
    /// If None, returns a BoxedStatus error with the provided error message
    pub fn some_or_tonic_abort<T>(input: Option<T>, error: String) -> TonicResult<T> {
        input.ok_or_else(|| {
            tracing::error!(error);
            BoxedStatus::from(tonic::Status::new(
                tonic::Code::Aborted,
                top_1k_chars(error),
            ))
        })
    }

    /// Converts a Result<T, E> to a TonicResult<T>, an aborted status is used if there is an error.
    ///
    /// Formats the error message by combining the provided context with the error's string representation
    pub fn ok_or_tonic_abort<T, E: ToString>(resp: Result<T, E>, error: String) -> TonicResult<T> {
        resp.map_err(|e| {
            let msg = format!("{}: {}", error, e.to_string());
            tracing::error!(msg);
            BoxedStatus::from(tonic::Status::new(tonic::Code::Aborted, top_1k_chars(msg)))
        })
    }
}

// Re-export the non-wasm module contents when the non-wasm feature is enabled
#[cfg(feature = "non-wasm")]
pub use non_wasm::*;
