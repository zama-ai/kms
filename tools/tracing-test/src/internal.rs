// Runtime internals for the in-repo `#[traced_test]` harness.
//
// Owns the global subscriber setup, per-test captured-log buffer, and the
// capture-specific filter logic. The key invariant is that the capture path
// never inherits ambient `RUST_LOG`, so `logs_contain(...)` assertions keep
// working even when CI forces a quiet global filter.
//
// Shared configuration lives in `crate::config`.

use std::collections::VecDeque;
use std::fmt::{self as std_fmt, Write as _};
use std::sync::{Mutex, MutexGuard, Once, OnceLock};

use crate::config::{parse_boolish_env, test_console_enabled, test_console_env_filter};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter, Layer};

pub static INITIALIZED: Once = Once::new();

const DEFAULT_CAPTURE_MAX_BYTES: usize = 4 * 1024 * 1024;
const TRUNCATED_LINE_SUFFIX: &str = " [truncated]";

#[derive(Default)]
struct EventFieldVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

#[derive(Default)]
struct CaptureLayer;

struct CapturedLine {
    scopes: Vec<String>,
    line: String,
    size_bytes: usize,
}

struct CaptureBuffer {
    lines: VecDeque<CapturedLine>,
    total_bytes: usize,
    max_bytes: usize,
}

impl CaptureBuffer {
    fn new(max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            total_bytes: 0,
            max_bytes,
        }
    }

    fn matching_lines(&self, scope: &str) -> Vec<String> {
        self.lines
            .iter()
            .filter(|line| has_scope(&line.scopes, scope))
            .map(|line| line.line.clone())
            .collect()
    }

    fn push(&mut self, scopes: Vec<String>, line: String) {
        let scope_bytes = scopes.iter().map(|scope| scope.len()).sum::<usize>();
        let line_budget = self.max_bytes.saturating_sub(scope_bytes);
        let line = truncate_line(line, line_budget);
        let size_bytes = estimate_size_bytes(&scopes, &line);

        if size_bytes == 0 {
            return;
        }

        while self.total_bytes.saturating_add(size_bytes) > self.max_bytes {
            let Some(removed) = self.lines.pop_front() else {
                return;
            };
            self.total_bytes = self.total_bytes.saturating_sub(removed.size_bytes);
        }

        self.total_bytes = self.total_bytes.saturating_add(size_bytes);
        self.lines.push_back(CapturedLine {
            scopes,
            line,
            size_bytes,
        });
    }
}

impl Visit for EventFieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std_fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }
}

impl EventFieldVisitor {
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let Some(scopes) = current_scope_names(&ctx) else {
            return;
        };

        let rendered = render_event(event, &scopes);
        lock_ignore_poison(global_buf()).push(scopes, rendered);
    }
}

/// Install the **capture-layer** subscriber stack for `#[traced_test]`: an in-memory
/// buffer (for `logs_contain` / `logs_assert`) plus an optional stderr mirror when
/// [`crate::config::test_console_enabled`] is true.
///
/// The attribute macro invokes [`init_subscriber`] once via [`INITIALIZED`]; call
/// this function only when you need the same stack without using `#[traced_test]`.
///
/// Safe to call multiple times — [`INITIALIZED`] runs [`init_subscriber`] at most once.
/// For stderr-only output (no capture), use [`crate::config::try_init_test_stderr_subscriber`]
/// (`observability::telemetry::try_init_test_stderr_subscriber` in this repo).
pub fn try_init_traced_test_subscriber() {
    INITIALIZED.call_once(init_subscriber);
}

pub fn init_subscriber() {
    // Both sinks use per-layer filters so that capture and console filtering
    // stay independent.  A global filter would cap both sinks at the most
    // restrictive level, which breaks `logs_contain(...)` when the console
    // filter is quieter than the capture filter.
    let subscriber =
        tracing_subscriber::registry().with(CaptureLayer.with_filter(test_capture_env_filter()));

    // Use `let _ =` instead of `.expect()` so this doesn't panic when another
    // macro (e.g. `#[integration_test]`) already installed a global subscriber
    // in the same test binary. The `INITIALIZED` Once-guard still prevents
    // redundant work within traced_test itself.
    if test_console_enabled() {
        if let Err(err) = subscriber
            .with(
                tracing_fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_span_events(FmtSpan::NONE)
                    .with_ansi(false)
                    .with_writer(std::io::stderr)
                    .with_filter(test_console_env_filter()),
            )
            .try_init()
        {
            if parse_boolish_env(std::env::var("KMS_TEST_LOG_INIT_DEBUG").ok().as_deref()) {
                eprintln!("[tracing-test] skipped global subscriber init (console+capture): {err}");
            }
        }
    } else {
        if let Err(err) = subscriber.try_init() {
            if parse_boolish_env(std::env::var("KMS_TEST_LOG_INIT_DEBUG").ok().as_deref()) {
                eprintln!("[tracing-test] skipped global subscriber init (capture): {err}");
            }
        }
    }
}

pub fn logs_with_scope_contain(scope: &str, value: &str) -> bool {
    let buffer = lock_ignore_poison(global_buf());
    buffer
        .lines
        .iter()
        .any(|line| has_scope(&line.scopes, scope) && line.line.contains(value))
}

pub fn logs_assert<F>(scope: &str, f: F) -> Result<(), String>
where
    F: Fn(&[&str]) -> Result<(), String>,
{
    let lines = lock_ignore_poison(global_buf()).matching_lines(scope);
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    f(&refs)
}

fn global_buf() -> &'static Mutex<CaptureBuffer> {
    static GLOBAL_BUF: OnceLock<Mutex<CaptureBuffer>> = OnceLock::new();
    GLOBAL_BUF.get_or_init(|| Mutex::new(CaptureBuffer::new(capture_max_bytes())))
}

fn current_scope_names<S>(ctx: &Context<'_, S>) -> Option<Vec<String>>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    let current = ctx.lookup_current()?;
    Some(
        current
            .scope()
            .from_root()
            .map(|span| span.metadata().name().to_string())
            .collect(),
    )
}

fn render_event(event: &Event<'_>, scopes: &[String]) -> String {
    let mut rendered = format!("{} {}", event.metadata().level(), event.metadata().target());

    if let Some(file) = event.metadata().file() {
        rendered.push(' ');
        rendered.push_str(file);
        if let Some(line) = event.metadata().line() {
            let _ = write!(rendered, ":{line}");
        }
    }

    if !scopes.is_empty() {
        rendered.push(' ');
        rendered.push('[');
        rendered.push_str(&scopes.join("::"));
        rendered.push(']');
    }

    let mut visitor = EventFieldVisitor::default();
    event.record(&mut visitor);

    if let Some(message) = visitor.message {
        rendered.push(' ');
        rendered.push_str(&message);
    }

    for field in visitor.fields {
        rendered.push(' ');
        rendered.push_str(&field);
    }

    rendered
}

fn estimate_size_bytes(scopes: &[String], line: &str) -> usize {
    line.len() + scopes.iter().map(|scope| scope.len()).sum::<usize>()
}

fn has_scope(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|current| current == scope)
}

fn truncate_line(mut line: String, max_bytes: usize) -> String {
    if max_bytes == 0 {
        return String::new();
    }

    if line.len() <= max_bytes {
        return line;
    }

    let suffix_bytes = TRUNCATED_LINE_SUFFIX.len();
    let keep_bytes = max_bytes.saturating_sub(suffix_bytes);
    let suffix = if max_bytes >= suffix_bytes {
        TRUNCATED_LINE_SUFFIX
    } else {
        let suffix_boundary = truncate_to_char_boundary(TRUNCATED_LINE_SUFFIX, max_bytes);
        &TRUNCATED_LINE_SUFFIX[..suffix_boundary]
    };
    let truncated = truncate_to_char_boundary(&line, keep_bytes);
    line.truncate(truncated);
    line.push_str(suffix);
    line
}

fn truncate_to_char_boundary(value: &str, max_bytes: usize) -> usize {
    let mut boundary = max_bytes.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn capture_max_bytes() -> usize {
    std::env::var("KMS_TEST_LOG_CAPTURE_MAX_BYTES")
        .ok()
        .or_else(|| std::env::var("KMS_TEST_LOG_MAX_BYTES").ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CAPTURE_MAX_BYTES)
}

/// Capture filter intentionally does **not** fall back to `RUST_LOG`.
/// CI sets `RUST_LOG=error` which would drop the `info!` events that
/// `logs_contain(...)` assertions depend on.
pub fn test_capture_env_filter() -> EnvFilter {
    let capture_override = std::env::var("KMS_TEST_LOG_CAPTURE_FILTER").ok();
    let shared_override = std::env::var("KMS_TEST_LOG_FILTER").ok();
    EnvFilter::new(resolve_test_capture_filter(
        capture_override.as_deref(),
        shared_override.as_deref(),
    ))
}

fn resolve_test_capture_filter(
    capture_override: Option<&str>,
    shared_override: Option<&str>,
) -> String {
    if let Some(filter) = capture_override {
        return filter.to_owned();
    }

    if let Some(filter) = shared_override {
        return filter.to_owned();
    }

    crate::config::DEFAULT_TEST_VERBOSE_FILTER.to_owned()
}

fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_test_capture_filter_defaults_to_verbose() {
        assert_eq!(
            resolve_test_capture_filter(None, None),
            crate::config::DEFAULT_TEST_VERBOSE_FILTER
        );
    }

    #[test]
    fn resolve_test_capture_filter_prefers_explicit_overrides() {
        assert_eq!(
            resolve_test_capture_filter(Some("trace"), Some("warn")),
            "trace"
        );
        assert_eq!(resolve_test_capture_filter(None, Some("warn")), "warn");
    }

    #[test]
    fn truncate_line_returns_empty_when_budget_is_zero() {
        assert_eq!(truncate_line("abcdef".to_owned(), 0), "");
    }

    #[test]
    fn truncate_line_never_exceeds_budget_when_budget_smaller_than_suffix() {
        let budget = 4;
        let truncated = truncate_line("abcdef".to_owned(), budget);
        assert!(truncated.len() <= budget);
        assert_eq!(truncated, " [tr");
    }

    #[test]
    fn capture_buffer_push_accounts_for_scope_bytes() {
        let mut buffer = CaptureBuffer::new(10);
        buffer.push(vec!["scope".to_owned()], "abcdef".to_owned());
        let stored = buffer
            .matching_lines("scope")
            .into_iter()
            .next()
            .unwrap_or_default();
        assert_eq!(stored, " [tru");
    }
}
