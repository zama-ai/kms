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

pub mod config;
pub mod internal;

pub use tracing_test_macro::traced_test;
