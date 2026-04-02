//! Test tracing harness for this workspace.
//!
//! Two usage modes:
//!
//! - `#[traced_test]` — captured-log assertions via `logs_contain` / `logs_assert`.
//! - `init_logging()` / `try_init_test_stderr_subscriber()` — stderr/file output
//!   for integration tests and runtime diagnostics.
//!
//! Both modes install a global tracing subscriber. In a single test process,
//! whichever initializer runs first becomes the active subscriber.
//!
//! Filter precedence, workflow examples, and env var reference are documented in
//! [`docs/developer/observability.md`](../../docs/developer/observability.md)
//! (section "Testing").

use std::sync::Once;

pub mod config;
pub mod internal;

pub use kms_test_tracing_macro::traced_test;

/// Enables test-mode env defaults and initializes stderr test logging once.
///
/// This is intended as the shared entry point for integration-style tests to
/// avoid repeating ad-hoc `Once` guards across crates.
///
/// Use this for tests that only need stderr output. For tests that assert on
/// captured logs (`logs_contain(...)` / `logs_assert(...)`), use
/// `kms_test_tracing::traced_test` instead.
///
/// Important: tracing subscriber installation is process-global. If another
/// initializer already installed a subscriber, this function becomes a no-op.
pub fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("KMS_TEST_MODE", "1");
        config::try_init_test_stderr_subscriber();
    });
}
