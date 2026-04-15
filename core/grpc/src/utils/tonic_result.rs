//! Utilities for working with tonic::Status errors in Results

// This module is structured to be available in both wasm and non-wasm builds.
// The tonic-related code is gated behind the non-wasm feature flag.

#[cfg(feature = "non-wasm")]
mod non_wasm {

    /// Truncates a string to a maximum of 1024 chars to limit error message size.
    pub fn top_1k_chars(mut s: String) -> String {
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
}

// Re-export the non-wasm module contents when the non-wasm feature is enabled
#[cfg(feature = "non-wasm")]
pub use non_wasm::*;
