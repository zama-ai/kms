//! Shared test-logging configuration used by both the `#[traced_test]` capture
//! harness and the `observability` crate's test-mode subscriber.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriter;

pub const DEFAULT_TEST_CONSOLE_FILTER: &str = "warn,tonic=error,h2=error,hyper=error,tower=error,opentelemetry_sdk=error,reqwest=error,rustls=error";

pub const DEFAULT_TEST_VERBOSE_FILTER: &str =
    "info,tonic=info,h2=warn,hyper=warn,tower=warn,opentelemetry_sdk=warn,reqwest=warn,rustls=warn";

// File-filter preset used only by the persistent trace sink in observability.
pub const DEFAULT_TEST_FILE_FILTER: &str = "warn,observability=info,kms_core_client=info,kms_lib=info,kms_server=info,kms_init=info,kms_gen_keys=info,kms_custodian=info,tonic=warn,h2=error,hyper=error,tower=error,opentelemetry_sdk=error,reqwest=error,rustls=error";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestLogMode {
    Quiet,
    Console,
    Verbose,
}

pub fn parse_test_log_mode(value: Option<&str>) -> TestLogMode {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "verbose" | "debug" | "trace" => TestLogMode::Verbose,
        "console" => TestLogMode::Console,
        _ => TestLogMode::Quiet,
    }
}

pub fn parse_boolish_env(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes")
    )
}

pub fn test_log_mode() -> TestLogMode {
    let mode = std::env::var("KMS_TEST_LOG_MODE").ok();
    parse_test_log_mode(mode.as_deref())
}

/// Whether a console (stderr) layer should be attached to the subscriber.
///
/// Note: the env var is called `KMS_TEST_LOG_STDOUT` for historical reasons;
/// actual output goes to **stderr**.
pub fn test_console_enabled() -> bool {
    let stdout = std::env::var("KMS_TEST_LOG_STDOUT").ok();
    matches!(test_log_mode(), TestLogMode::Console | TestLogMode::Verbose)
        || parse_boolish_env(stdout.as_deref())
}

pub fn test_logging_enabled() -> bool {
    parse_boolish_env(std::env::var("KMS_TEST_MODE").ok().as_deref())
        || matches!(std::env::var("RUN_MODE").as_deref(), Ok("integration"))
        || std::env::var("TRACE_PERSISTENCE").unwrap_or_default() == "enabled"
}

/// Build an `EnvFilter` for a test output (console or file).
///
/// First match wins:
/// 1. Output-specific: `KMS_TEST_LOG_CONSOLE_FILTER` / `KMS_TEST_LOG_FILE_FILTER`
/// 2. Shared: `KMS_TEST_LOG_FILTER`
/// 3. `RUST_LOG`
/// 4. `KMS_TEST_LOG_MODE` preset (`verbose` → info, otherwise warn)
///
/// Levels 1–3 use `tracing` directive syntax. Level 4 is a keyword.
/// See `docs/developer/observability.md` ("Testing") for full details.
pub fn test_log_filter(override_var: &str, quiet_default: &str) -> EnvFilter {
    if let Ok(filter) = std::env::var(override_var) {
        return EnvFilter::new(filter);
    }
    if let Ok(filter) = std::env::var("KMS_TEST_LOG_FILTER") {
        return EnvFilter::new(filter);
    }
    if let Ok(filter) = std::env::var("RUST_LOG") {
        return EnvFilter::new(filter);
    }
    if matches!(test_log_mode(), TestLogMode::Verbose) {
        return EnvFilter::new(DEFAULT_TEST_VERBOSE_FILTER);
    }
    EnvFilter::new(quiet_default)
}

pub fn test_console_env_filter() -> EnvFilter {
    test_log_filter("KMS_TEST_LOG_CONSOLE_FILTER", DEFAULT_TEST_CONSOLE_FILTER)
}

pub fn test_persistent_env_filter() -> EnvFilter {
    test_log_filter("KMS_TEST_LOG_FILE_FILTER", DEFAULT_TEST_FILE_FILTER)
}

/// Used by the persistent trace file sink in `init_tracing()` to bound artifact
/// size while still emitting an explicit truncation marker.
pub fn test_log_max_bytes() -> usize {
    std::env::var("KMS_TEST_LOG_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4 * 1024 * 1024)
}

#[derive(Clone)]
pub struct TruncatingMakeWriter<W> {
    inner: W,
    state: Arc<TruncatingWriterState>,
}

struct TruncatingWriterState {
    max_bytes: usize,
    written_bytes: AtomicUsize,
    truncated: AtomicBool,
}

pub struct TruncatingWriter<W> {
    inner: W,
    state: Arc<TruncatingWriterState>,
}

const TRACE_TRUNCATION_MARKER: &[u8] = b"\n[truncated test trace output]\n";

impl<W> TruncatingMakeWriter<W> {
    /// Creates a truncating writer wrapper.
    ///
    /// `max_bytes = 0` disables truncation (no size limit).
    pub fn new(inner: W, max_bytes: usize) -> Self {
        Self {
            inner,
            state: Arc::new(TruncatingWriterState {
                max_bytes,
                written_bytes: AtomicUsize::new(0),
                truncated: AtomicBool::new(false),
            }),
        }
    }
}

impl<'a, W> MakeWriter<'a> for TruncatingMakeWriter<W>
where
    W: MakeWriter<'a> + Clone,
{
    type Writer = TruncatingWriter<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        TruncatingWriter {
            inner: self.inner.make_writer(),
            state: self.state.clone(),
        }
    }
}

impl<W> io::Write for TruncatingWriter<W>
where
    W: io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.state.max_bytes == 0 {
            return self.inner.write(buf);
        }

        // Reserve budget with CAS so concurrent `make_writer()` instances cannot
        // each observe the same remaining space and collectively exceed `max_bytes`.
        let mut written = self.state.written_bytes.load(Ordering::Relaxed);
        let mut remaining = self.state.max_bytes.saturating_sub(written);
        let (to_write, remaining_before) = loop {
            if remaining == 0 {
                break (0, remaining);
            }
            let desired = remaining.min(buf.len());
            let new_written = written.saturating_add(desired);
            match self.state.written_bytes.compare_exchange(
                written,
                new_written,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break (desired, remaining),
                Err(actual) => {
                    written = actual;
                    remaining = self.state.max_bytes.saturating_sub(written);
                }
            }
        };

        // One `write_all` so `non_local_effect_before_error_return` is satisfied: a failed
        // marker write must not follow a successful payload write to the same sink.
        let mut out =
            Vec::with_capacity(to_write.saturating_add(if remaining_before < buf.len() {
                TRACE_TRUNCATION_MARKER.len()
            } else {
                0
            }));
        if to_write > 0 {
            out.extend_from_slice(&buf[..to_write]);
        }
        if remaining_before < buf.len() && !self.state.truncated.swap(true, Ordering::Relaxed) {
            out.extend_from_slice(TRACE_TRUNCATION_MARKER);
        }
        if !out.is_empty() {
            self.inner.write_all(&out)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Install a minimal **stderr-only** subscriber using [`test_console_env_filter`].
///
/// This does **not** register the in-memory capture layer that powers
/// `logs_contain` / `logs_assert` on `#[traced_test]`; for that stack use
/// [`crate::internal::try_init_traced_test_subscriber`] (or rely on the macro,
/// which calls [`crate::internal::init_subscriber`] directly).
///
/// Workspace convention: integration tests usually call [`crate::init_logging`]
/// or import [`try_init_test_stderr_subscriber`] from `kms_test_tracing::config`.
///
/// Safe to call multiple times: if a global subscriber is already installed,
/// the underlying `try_init` returns `Err` and that error is ignored.
pub fn try_init_test_stderr_subscriber() {
    if let Err(err) = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(test_console_env_filter())
        .try_init()
    {
        if parse_boolish_env(std::env::var("KMS_TEST_LOG_INIT_DEBUG").ok().as_deref()) {
            eprintln!("[tracing-test] skipped stderr-only subscriber init: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_test_log_mode_supports_tri_state_values() {
        assert_eq!(parse_test_log_mode(None), TestLogMode::Quiet);
        assert_eq!(parse_test_log_mode(Some("quiet")), TestLogMode::Quiet);
        assert_eq!(parse_test_log_mode(Some("console")), TestLogMode::Console);
        assert_eq!(parse_test_log_mode(Some("verbose")), TestLogMode::Verbose);
        assert_eq!(parse_test_log_mode(Some("debug")), TestLogMode::Verbose);
        assert_eq!(parse_test_log_mode(Some("trace")), TestLogMode::Verbose);
    }

    #[test]
    fn parse_boolish_env_accepts_common_truthy_values() {
        assert!(parse_boolish_env(Some("1")));
        assert!(parse_boolish_env(Some("true")));
        assert!(parse_boolish_env(Some("YES")));
        assert!(!parse_boolish_env(Some("0")));
        assert!(!parse_boolish_env(Some("false")));
        assert!(!parse_boolish_env(None));
    }
}
