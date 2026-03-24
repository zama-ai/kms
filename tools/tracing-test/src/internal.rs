use std::collections::VecDeque;
use std::fmt::{self as std_fmt, Write as _};
use std::sync::{Mutex, MutexGuard, Once, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter, Layer};

pub static INITIALIZED: Once = Once::new();

const DEFAULT_TEST_CONSOLE_FILTER: &str =
    "warn,tonic=error,h2=error,hyper=error,tower=error,opentelemetry_sdk=error,reqwest=error,rustls=error";
const DEFAULT_TEST_VERBOSE_FILTER: &str =
    "info,tonic=info,h2=warn,hyper=warn,tower=warn,opentelemetry_sdk=warn,reqwest=warn,rustls=warn";
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
        let line = truncate_line(line, self.max_bytes);
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

pub fn init_subscriber() {
    let subscriber = tracing_subscriber::registry()
        .with(CaptureLayer)
        .with(test_env_filter());

    if test_console_enabled() {
        subscriber
            .with(
                tracing_fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_span_events(FmtSpan::NONE)
                    .with_ansi(false)
                    .with_writer(std::io::stderr),
            )
            .try_init()
            .expect("failed to initialize tracing-test subscriber");
    } else {
        subscriber
            .try_init()
            .expect("failed to initialize tracing-test subscriber");
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
    if max_bytes == 0 || line.len() <= max_bytes {
        return line;
    }

    let suffix_bytes = TRUNCATED_LINE_SUFFIX.len();
    let keep_bytes = max_bytes.saturating_sub(suffix_bytes);
    let truncated = truncate_to_char_boundary(&line, keep_bytes);
    line.truncate(truncated);
    line.push_str(TRUNCATED_LINE_SUFFIX);
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

// Keep the tracing-test runtime aligned with `observability::telemetry` so
// traced unit tests and spawned binaries interpret the same env vars the same
// way.
fn test_env_filter() -> EnvFilter {
    if let Ok(filter) = std::env::var("KMS_TEST_LOG_CONSOLE_FILTER") {
        return EnvFilter::new(filter);
    }

    if let Ok(filter) = std::env::var("KMS_TEST_LOG_FILTER") {
        return EnvFilter::new(filter);
    }

    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return filter;
    }

    if matches!(test_log_mode(), TestLogMode::Verbose) {
        EnvFilter::new(DEFAULT_TEST_VERBOSE_FILTER)
    } else {
        EnvFilter::new(DEFAULT_TEST_CONSOLE_FILTER)
    }
}

// `KMS_TEST_LOG_STDOUT` is kept as a backward-compatible alias for callers
// that want console output without switching away from the quiet preset.
fn test_console_enabled() -> bool {
    let stdout = std::env::var("KMS_TEST_LOG_STDOUT").ok();
    matches!(test_log_mode(), TestLogMode::Console | TestLogMode::Verbose)
        || parse_boolish_env(stdout.as_deref())
}

fn test_log_mode() -> TestLogMode {
    let mode = std::env::var("KMS_TEST_LOG_MODE").ok();
    parse_test_log_mode(mode.as_deref())
}

fn parse_test_log_mode(value: Option<&str>) -> TestLogMode {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "verbose" | "debug" | "trace" => TestLogMode::Verbose,
        "console" => TestLogMode::Console,
        _ => TestLogMode::Quiet,
    }
}

fn parse_boolish_env(value: Option<&str>) -> bool {
    matches!(
        value.map(|value| value.to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes")
    )
}

fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

// Mirror the tri-state `KMS_TEST_LOG_MODE` semantics from
// `observability::telemetry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestLogMode {
    Quiet,
    Console,
    Verbose,
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
