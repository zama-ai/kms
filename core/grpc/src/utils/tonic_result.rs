//! Utilities for working with tonic::Status errors in Results

// This module is structured to be available in both wasm and non-wasm builds.
// The tonic-related code is gated behind the non-wasm feature flag.

#[cfg(feature = "non-wasm")]
mod non_wasm {
    use tracing;

    /// Truncates a string to a maximum of 128 chars to limit error message size.
    pub(crate) fn top_n_chars(mut s: String) -> String {
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

    /// Converts an Option<T> to a TonicResult<T>
    ///
    /// If None, returns a BoxedStatus error with the provided error message
    pub fn tonic_some_or_err<T>(input: Option<T>, error: String) -> TonicResult<T> {
        input.ok_or_else(|| {
            tracing::warn!(error);
            BoxedStatus::from(tonic::Status::new(tonic::Code::Aborted, top_n_chars(error)))
        })
    }

    /// Converts a reference to an Option<T> to a TonicResult<&T>
    pub fn tonic_some_or_err_ref<T>(input: &Option<T>, error: String) -> TonicResult<&T> {
        input.as_ref().ok_or_else(|| {
            tracing::warn!(error);
            BoxedStatus::from(tonic::Status::new(tonic::Code::Aborted, top_n_chars(error)))
        })
    }

    /// Converts an Option<&T> to a TonicResult<&T>
    pub fn tonic_some_ref_or_err<T>(input: Option<&T>, error: String) -> TonicResult<&T> {
        input.ok_or_else(|| {
            tracing::warn!(error);
            BoxedStatus::from(tonic::Status::new(tonic::Code::Aborted, error))
        })
    }

    /// Converts a Result<T, E> to a TonicResult<T>
    ///
    /// Formats the error message by combining the provided context with the error's string representation
    pub fn tonic_handle_potential_err<T, E: ToString>(
        resp: Result<T, E>,
        error: String,
    ) -> TonicResult<T> {
        resp.map_err(|e| {
            let msg = format!("{}: {}", error, e.to_string());
            tracing::warn!(msg);
            BoxedStatus::from(tonic::Status::new(tonic::Code::Aborted, msg))
        })
    }
}

// Re-export the non-wasm module contents when the non-wasm feature is enabled
#[cfg(feature = "non-wasm")]
pub use non_wasm::*;
