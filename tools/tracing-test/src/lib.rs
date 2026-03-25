// Keep the runtime half of the tracing test harness in-repo because this
// workspace needs test-log capture semantics that differ from the console sink.
// CI often runs with quiet or even `RUST_LOG=error` filters, but test helpers
// like `logs_contain(...)` still need access to captured `info!` events.
// This crate owns that subscriber setup and capture buffer; the attribute macro
// stays in the sibling proc-macro crate.
pub mod internal;

pub use tracing_test_macro::traced_test;
