use crate::conf::{ExecutionEnvironment, TelemetryConfig, ENVIRONMENT};
use crate::metrics::METRICS;
use crate::sys_metrics::start_sys_metrics_collection;
use anyhow::Context;
use axum::Json;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use opentelemetry::propagation::TextMapCompositePropagator;
use opentelemetry::{global, propagation::Injector, trace::TracerProvider, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_prometheus::exporter;
pub use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
pub use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::{resource::Resource, trace::Sampler};
use prometheus::{Encoder, Registry as PrometheusRegistry, TextEncoder};
use serde::Serialize;
use std::{
    env, io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};
use tonic::{
    metadata::{MetadataKey, MetadataMap, MetadataValue},
    service::Interceptor,
    Status,
};
use tracing::{info, info_span, trace_span, Span};
use tracing_appender::non_blocking;
use tracing_appender::rolling::never;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::fmt::{layer, Layer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};

#[cfg(target_os = "linux")]
use prometheus::process_collector::ProcessCollector;

/// This is the HEADER key that will be used to store the request ID in the tracing context.
pub const TRACER_REQUEST_ID: &str = "x-zama-kms-request-id";
pub const TRACER_PARENT_SPAN_ID: &str = "x-zama-kms-parent-span-id";

pub trait ConfigTracing {
    fn telemetry(&self) -> Option<TelemetryConfig>;
}

// Default log filters for tests.
//
// These presets drive three different test logging behaviors:
// - `DEFAULT_TEST_CONSOLE_FILTER` keeps parent-process stderr quiet by default
//   during local runs and CI, while still surfacing warnings and errors.
// - `DEFAULT_TEST_FILE_FILTER` is used for persistent trace artifacts and keeps
//   the in-repo crates at `info` so the saved JSON logs remain useful for
//   debugging without opening the floodgates on transport noise.
// - `DEFAULT_TEST_VERBOSE_FILTER` is the broader preset selected by
//   `KMS_TEST_LOG_MODE=verbose|debug|trace` when no sink-specific override is
//   provided.
// - `DEFAULT_TEST_LOG_MAX_BYTES` caps persistent trace files; `init_tracing()`
//   feeds it into `TruncatingMakeWriter` so CI artifacts stay bounded.
const DEFAULT_TEST_CONSOLE_FILTER: &str =
    "warn,tonic=error,h2=error,hyper=error,tower=error,opentelemetry_sdk=error,reqwest=error,rustls=error";
const DEFAULT_TEST_FILE_FILTER: &str =
    "warn,observability=info,kms_core_client=info,kms_lib=info,kms_server=info,kms_init=info,kms_gen_keys=info,kms_custodian=info,tonic=warn,h2=error,hyper=error,tower=error,opentelemetry_sdk=error,reqwest=error,rustls=error";
const DEFAULT_TEST_VERBOSE_FILTER: &str =
    "info,tonic=info,h2=warn,hyper=warn,tower=warn,opentelemetry_sdk=warn,reqwest=warn,rustls=warn";
const DEFAULT_TEST_LOG_MAX_BYTES: usize = 4 * 1024 * 1024;

// `KMS_TEST_LOG_MODE` is the canonical high-level switch for test logging.
// `quiet` keeps the quiet defaults and no console, `console` keeps the quiet
// defaults but enables console output, and `verbose`/`debug`/`trace` enables
// the verbose defaults plus console output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestLogMode {
    Quiet,
    Console,
    Verbose,
}

#[derive(Clone)]
struct TruncatingMakeWriter<W> {
    inner: W,
    state: Arc<TruncatingWriterState>,
}

struct TruncatingWriterState {
    max_bytes: usize,
    written_bytes: AtomicUsize,
    truncated: AtomicBool,
}

struct TruncatingWriter<W> {
    inner: W,
    state: Arc<TruncatingWriterState>,
}

impl<W> TruncatingMakeWriter<W> {
    fn new(inner: W, max_bytes: usize) -> Self {
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

        let written = self.state.written_bytes.load(Ordering::Relaxed);
        let remaining = self.state.max_bytes.saturating_sub(written);
        let to_write = remaining.min(buf.len());

        if to_write > 0 {
            self.inner.write_all(&buf[..to_write])?;
            self.state
                .written_bytes
                .fetch_add(to_write, Ordering::Relaxed);
        }

        // Emit the truncation marker exactly once, covering both the case
        // where this write itself was partially dropped *and* the edge case
        // where the previous write filled the budget exactly.
        if remaining < buf.len() && !self.state.truncated.swap(true, Ordering::Relaxed) {
            self.inner.write_all(b"\n[truncated test trace output]\n")?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn test_logging_enabled() -> bool {
    matches!(
        env::var("KMS_TEST_MODE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) || matches!(env::var("RUN_MODE").as_deref(), Ok("integration"))
        || env::var("TRACE_PERSISTENCE").unwrap_or_default() == "enabled"
}

fn test_log_mode() -> TestLogMode {
    let mode = env::var("KMS_TEST_LOG_MODE").ok();
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

// Resolution order is sink-specific override -> shared override -> `RUST_LOG`
// -> preset selected by `KMS_TEST_LOG_MODE`.
fn test_log_filter(override_var: &str, quiet_default: &str) -> EnvFilter {
    if let Ok(filter) = env::var(override_var) {
        return EnvFilter::new(filter);
    }

    if let Ok(filter) = env::var("KMS_TEST_LOG_FILTER") {
        return EnvFilter::new(filter);
    }

    if let Ok(filter) = env::var("RUST_LOG") {
        return EnvFilter::new(filter);
    }

    if matches!(test_log_mode(), TestLogMode::Verbose) {
        return EnvFilter::new(DEFAULT_TEST_VERBOSE_FILTER);
    }

    EnvFilter::new(quiet_default)
}

// These helpers apply the override precedence above and expose the sink-specific
// defaults used throughout the repo:
// - `test_console_env_filter()` is used by the parent-process test subscribers
//   installed by the integration-test macro and client-side test helpers.
// - `test_persistent_env_filter()` is used by the JSON file sink when
//   `TRACE_PERSISTENCE=enabled`.
pub fn test_console_env_filter() -> EnvFilter {
    test_log_filter("KMS_TEST_LOG_CONSOLE_FILTER", DEFAULT_TEST_CONSOLE_FILTER)
}

pub fn test_persistent_env_filter() -> EnvFilter {
    test_log_filter("KMS_TEST_LOG_FILE_FILTER", DEFAULT_TEST_FILE_FILTER)
}

// Used by the persistent trace file sink in `init_tracing()` to bound artifact
// size while still emitting an explicit truncation marker.
pub fn test_log_max_bytes() -> usize {
    env::var("KMS_TEST_LOG_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TEST_LOG_MAX_BYTES)
}

// `KMS_TEST_LOG_STDOUT` is kept as a backward-compatible alias for callers
// that want console output without changing the selected log-mode preset.
fn test_console_enabled() -> bool {
    let stdout = env::var("KMS_TEST_LOG_STDOUT").ok();
    matches!(test_log_mode(), TestLogMode::Console | TestLogMode::Verbose)
        || parse_boolish_env(stdout.as_deref())
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

#[derive(Clone)]
struct MetricsState {
    config: Arc<String>, // Store the config as a string for the /config endpoint
    registry: Arc<PrometheusRegistry>,
    start_time: std::time::SystemTime,
}

impl MetricsState {
    fn new(registry: PrometheusRegistry, config: String) -> Self {
        Self {
            config: Arc::new(config),
            registry: Arc::new(registry),
            start_time: std::time::SystemTime::now(),
        }
    }
}

async fn metrics_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Response::builder()
        .status(StatusCode::OK)
        // .header(header::CONTENT_TYPE, "application/openmetrics-text;version=1.0.0;charset=utf-8") // TODO: switch to it if we need OpenMetrics format support
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(axum::body::Body::from(buffer))
        .unwrap()
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn version_handler() -> impl IntoResponse {
    (StatusCode::OK, env!("CARGO_PKG_VERSION").to_string())
}

async fn readiness_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().unwrap_or_default();
    if uptime > Duration::from_secs(10) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "warming up")
    }
}

async fn liveness_handler() -> impl IntoResponse {
    (StatusCode::OK, "alive")
}

async fn config_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    Json(state.config).into_response()
}

pub fn init_metrics<T: Serialize + ConfigTracing>(
    config: &T,
) -> Result<SdkMeterProvider, anyhow::Error> {
    if matches!(*ENVIRONMENT, ExecutionEnvironment::Integration) {
        return Ok(SdkMeterProvider::default());
    }
    let telemetry_settings = config.telemetry().unwrap_or_else(|| {
        tracing::warn!("No telemetry configuration found, using defaults");
        TelemetryConfig::builder()
            .tracing_service_name("kms_core".to_string())
            .build()
    });
    let config_json = serde_json::to_string_pretty(&config)
        .map_err(|e| anyhow::anyhow!("Failed to serialize configuration: {:?}", e))?;
    let registry = PrometheusRegistry::new();

    // Add process collector for system metrics
    #[cfg(target_os = "linux")]
    registry.register(Box::new(ProcessCollector::for_self()))?;

    // Create a Prometheus exporter
    let exporter = exporter()
        .with_registry(registry.clone())
        .build()
        .context("Failed to create Prometheus exporter")?;

    let provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(
            Resource::builder()
                .with_attributes(vec![
                    KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                        telemetry_settings
                            .tracing_service_name()
                            .unwrap_or("unknown-service")
                            .to_string(),
                    ),
                    KeyValue::new(
                        "service.version".to_string(),
                        env!("CARGO_PKG_VERSION").to_string(),
                    ),
                    KeyValue::new(
                        "deployment.environment".to_string(),
                        ENVIRONMENT.to_string(),
                    ),
                ])
                .build(),
        )
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());

    // Start metrics server if configured
    let metrics_addr = telemetry_settings
        .metrics_bind_address()
        .unwrap_or("0.0.0.0:9464")
        .parse::<SocketAddr>()
        .context("Failed to parse metrics bind address")?;

    let state = MetricsState::new(registry, config_json);

    // Use the global METRICS instance also as a sanity check that metrics are working
    METRICS.increment_request_counter("system_startup");

    // Get the current runtime handle
    let rt = tokio::runtime::Handle::current();

    rt.spawn(async move {
        // Setup public routes
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route("/ready", get(readiness_handler))
            .route("/version", get(version_handler))
            .route("/live", get(liveness_handler))
            .route("/config", get(config_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .expect("Failed to bind metrics server");

        info!("Metrics server listening on {}", metrics_addr);

        axum::serve(listener, app.into_make_service())
            .await
            .expect("Metrics server error");
    });

    Ok(provider)
}

pub async fn init_tracing(settings: &TelemetryConfig) -> Result<SdkTracerProvider, anyhow::Error> {
    // For tests annotated with `#[persistent_traces]`
    // we set up a file-based persistent logger
    if std::env::var("TRACE_PERSISTENCE").unwrap_or_default() == "enabled" {
        // Determine the root directory - use the workspace root to ensure consistency
        // between local and CI environments
        let root_dir = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .to_string_lossy()
            .to_string();

        // Get the module path and timestamp from the environment or use defaults
        let module_path =
            std::env::var("TEST_MODULE_PATH").unwrap_or_else(|_| "unknown_module".to_string());
        let test_fn_name =
            std::env::var("TEST_FUNCTION_NAME").unwrap_or_else(|_| "unknown_function".to_string());
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get process ID and job name for artifact uniqueness
        let process_id = std::env::var("TEST_PROCESS_ID").unwrap_or_else(|_| "0".to_string());
        let job_name = std::env::var("TEST_JOB_NAME").unwrap_or_else(|_| "unknown_job".to_string());

        // Create the log path with timestamp to prevent overwriting
        // Use absolute path to ensure logs are created in a consistent location
        let sep = std::path::MAIN_SEPARATOR.to_string();
        let log_path = format!(
            "{root_dir}{sep}{job_name}{sep}{module_path}{sep}{test_fn_name}_{timestamp}_pid{process_id}.log"
        );

        // Create directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(&log_path).parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!(
                        "Failed to create persistent trace directory {}",
                        parent.display()
                    )
                })?;
            }
        }

        // Use a rolling file appender to prevent excessive file sizes
        let file_appender = never("", &log_path);
        let (non_blocking, guard) = non_blocking(file_appender);

        // Store the guard to keep the file handle open
        // Explicitly ignore errors since we can still proceed with console logging if this fails
        METRICS.set_trace_guard(Box::new(guard));

        let env_filter = test_persistent_env_filter();

        // Configure file output with JSON formatting for better machine parsing
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(TruncatingMakeWriter::new(
                non_blocking,
                test_log_max_bytes(),
            ))
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(false) // Disable ANSI colors in file output
            .json()
            .with_current_span(true) // Include current span in output
            .with_span_list(true); // Include span hierarchy

        let subscriber = tracing_subscriber::registry()
            .with(file_layer)
            .with(env_filter);

        if test_console_enabled() {
            subscriber
                .with(fmt_layer())
                .try_init()
                .with_context(|| {
                    format!(
                        "Failed to initialize persistent test tracing with console output enabled and file output to {log_path}"
                    )
                })?;
        } else {
            subscriber.try_init().with_context(|| {
                format!(
                    "Failed to initialize persistent test tracing with file output to {log_path}"
                )
            })?;
        }

        info!(
            "Integration test tracing initialized with file output to {}",
            log_path
        );
        // Return a default provider for test mode
        return Ok(SdkTracerProvider::builder().build());
    }

    let service_name = settings
        .tracing_service_name()
        .unwrap_or("unknown-service")
        .to_string();
    let service_name_for_logs = service_name.clone();
    let tracing_endpoint = settings.tracing_endpoint().map(str::to_owned);
    let tracing_otlp_timeout_ms = settings.tracing_otlp_timeout().as_millis();
    let batch_override = settings.batch().map(|batch_conf| {
        (
            batch_conf.max_queue_size(),
            batch_conf.scheduled_delay(),
            batch_conf.scheduled_delay().as_millis(),
            batch_conf.max_export_batch_size(),
        )
    });
    let sample_all_stdout_spans = std::env::var("RUST_LOG")
        .map(|v| v == "trace")
        .unwrap_or(false);

    // If no endpoint is configured, set up only console logging
    let provider = if let Some(endpoint) = tracing_endpoint.as_deref() {
        // Create an exporter for OTLP
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(settings.tracing_otlp_timeout())
            .build()
            .with_context(|| {
                format!(
                    "Failed to build OTLP span exporter for endpoint {endpoint} with tracing_otlp_timeout={}ms",
                    tracing_otlp_timeout_ms
                )
            })?;

        // Configure batch processing
        let batch_config =
            if let Some((max_queue_size, scheduled_delay, _, max_export_batch_size)) =
                batch_override.as_ref()
            {
                opentelemetry_sdk::trace::BatchConfigBuilder::default()
                    .with_max_queue_size(*max_queue_size)
                    .with_scheduled_delay(*scheduled_delay)
                    .with_max_export_batch_size(*max_export_batch_size)
                    .build()
            } else {
                opentelemetry_sdk::trace::BatchConfigBuilder::default().build()
            };

        let batch_processor = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
            .with_batch_config(batch_config)
            .build();

        SdkTracerProvider::builder()
            .with_span_processor(batch_processor)
            .with_resource(
                Resource::builder()
                    .with_attributes(vec![
                        KeyValue::new(
                            opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                            service_name.clone(),
                        ),
                        KeyValue::new(
                            "service.version".to_string(),
                            env!("CARGO_PKG_VERSION").to_string(),
                        ),
                        KeyValue::new(
                            "deployment.environment".to_string(),
                            ENVIRONMENT.to_string(),
                        ),
                    ])
                    .build(),
            )
            .build()
    } else {
        SdkTracerProvider::builder()
            .with_sampler(
                // When RUST_LOG=trace, sample everything
                // Otherwise, sample nothing for OpenTelemetry
                if sample_all_stdout_spans {
                    Sampler::AlwaysOn
                } else {
                    Sampler::AlwaysOff
                },
            )
            .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
            .with_resource(
                Resource::builder()
                    .with_attributes(vec![
                        KeyValue::new(
                            opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                            service_name,
                        ),
                        KeyValue::new(
                            "service.version".to_string(),
                            env!("CARGO_PKG_VERSION").to_string(),
                        ),
                        KeyValue::new(
                            "deployment.environment".to_string(),
                            ENVIRONMENT.to_string(),
                        ),
                    ])
                    .build(),
            )
            .build()
    };

    // Clone the provider to set it globally while keeping the original for explicit shutdown
    let tracer = provider.clone().tracer("kms-core");

    let env_filter = if test_logging_enabled() {
        // Runtime test sinks stay quiet by default and inherit the shared test
        // filter policy from this module. Branch-specific startup visibility is
        // emitted after `try_init()` succeeds, while pre-init failures carry
        // explicit error context instead of unconditional bootstrap prints.
        test_console_env_filter()
    } else {
        match *ENVIRONMENT {
            // For integration and local development, optionally use a more verbose filter
            ExecutionEnvironment::Integration | ExecutionEnvironment::Local => {
                EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    EnvFilter::new("info")
                        .add_directive("tonic=info".parse().unwrap())
                        .add_directive("h2=info".parse().unwrap())
                        .add_directive("tower=warn".parse().unwrap())
                        .add_directive("hyper=warn".parse().unwrap())
                        .add_directive("opentelemetry_sdk=warn".parse().unwrap())
                })
            }
            _ => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        }
    };

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    let fmt_layer = fmt_layer();

    tracing_subscriber::registry()
        .with(telemetry)
        .with(fmt_layer)
        .with(env_filter)
        .try_init()
        .with_context(|| match tracing_endpoint.as_deref() {
            Some(endpoint) => format!(
                "Failed to initialize tracing subscriber for service `{service_name_for_logs}` with OTLP endpoint {endpoint}"
            ),
            None => format!(
                "Failed to initialize tracing subscriber for service `{service_name_for_logs}` without an OTLP endpoint"
            ),
        })?;

    match (tracing_endpoint.as_deref(), batch_override.as_ref()) {
        (Some(endpoint), Some((max_queue_size, _, scheduled_delay_ms, max_export_batch_size))) => {
            info!(
                service_name = %service_name_for_logs,
                endpoint = %endpoint,
                tracing_otlp_timeout_ms = tracing_otlp_timeout_ms,
                max_queue_size = *max_queue_size,
                scheduled_delay_ms = *scheduled_delay_ms,
                max_export_batch_size = *max_export_batch_size,
                "Tracing initialized with OTLP exporter and custom batch processing"
            );
        }
        (Some(endpoint), None) => {
            info!(
                service_name = %service_name_for_logs,
                endpoint = %endpoint,
                tracing_otlp_timeout_ms = tracing_otlp_timeout_ms,
                "Tracing initialized with OTLP exporter and default batch processing"
            );
        }
        (None, _) => {
            info!(
                service_name = %service_name_for_logs,
                sample_all_spans = sample_all_stdout_spans,
                "Tracing initialized without an OTLP endpoint; using stdout exporter"
            );
        }
    }

    // Propagate both W3C tracecontext and baggage
    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));

    // Return the provider for explicit shutdown
    Ok(provider)
}

pub async fn init_telemetry<T: Serialize + ConfigTracing>(
    config: &T,
) -> anyhow::Result<(SdkTracerProvider, SdkMeterProvider)> {
    let telemetry_conf = config.telemetry().unwrap_or_else(|| {
        TelemetryConfig::builder()
            .tracing_service_name("kms_core".to_string())
            .build()
    });
    // First initialize tracing as it's more critical
    let tracer_provider = init_tracing(&telemetry_conf).await?;

    // Now that tracing is initialized, we can use info! tracing macros
    info!("Tracing initialization completed successfully");

    let meter_provider = init_metrics(config)?;
    info!("Metrics initialization completed successfully");

    if telemetry_conf.enable_sys_metrics() {
        start_sys_metrics_collection(telemetry_conf.refresh_interval())?;
    }

    info!("Telemetry stack initialization completed");
    Ok((tracer_provider, meter_provider))
}

fn fmt_layer<S>() -> Layer<S> {
    layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
}

pub fn make_span<B>(request: &tonic::codegen::http::Request<B>) -> Span {
    let endpoint = request.uri().path();

    // Create span without blocking
    if endpoint.contains("Health/Check") {
        return trace_span!("health_grpc_request", ?endpoint);
    }

    let headers = request.headers();
    let mut headers_map = http::HeaderMap::new();
    for (k, v) in headers.iter() {
        if let Ok(name) = http::header::HeaderName::from_bytes(k.as_str().as_bytes()) {
            if let Ok(value) = http::header::HeaderValue::from_bytes(v.as_bytes()) {
                headers_map.insert(name, value);
            }
        }
    }

    let request_id = headers
        .get(TRACER_REQUEST_ID)
        .and_then(|r| r.to_str().ok())
        .map(String::from);

    let parent_span_id = headers
        .get(TRACER_PARENT_SPAN_ID)
        .and_then(|r| r.to_str().ok())
        .map(String::from);

    let span = match (request_id, parent_span_id) {
        (Some(request_id), Some(parent_span_id)) => {
            info_span!("grpc_request", ?endpoint, %request_id, %parent_span_id)
        }
        (Some(request_id), None) => info_span!("grpc_request", ?endpoint, %request_id),
        (None, Some(parent_span_id)) => info_span!("grpc_request", ?endpoint, %parent_span_id),
        (None, None) => info_span!("grpc_request", ?endpoint),
    };

    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(&headers_map))
    });
    let _ = span.set_parent(parent_context);
    span
}

/// Propagate the current span context to the outgoing request.
#[derive(Clone)]
pub struct ContextPropagator;

impl Interceptor for ContextPropagator {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let context = Span::current().context();
        let mut injector = MetadataInjector(request.metadata_mut());
        global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&context, &mut injector)
        });
        Ok(request)
    }
}

/// `MetadataInjector` is a helper struct to inject metadata into a request.
/// It is used to propagate the current span context to the outgoing request. See `ContextPropagator`.
struct MetadataInjector<'a>(&'a mut MetadataMap);

impl Injector for MetadataInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(key) = MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = MetadataValue::try_from(&value) {
                self.0.insert(key, val);
            }
        }
    }
}
