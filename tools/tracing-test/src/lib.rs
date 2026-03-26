//! Test tracing harness split into two usage modes:
//!
//! - Use [`traced_test`] when tests need captured-log assertions via
//!   `logs_contain(...)` / `logs_assert(...)`.
//! - Use `observability::telemetry::init_test_logging_once()` for integration
//!   tests that only need stderr output and shared filter presets.
//!
//! Important: both modes install a global tracing subscriber. In a single test
//! process, whichever initializer runs first becomes the active subscriber.

pub mod config;
pub mod internal;

pub use tracing_test_macro::traced_test;
