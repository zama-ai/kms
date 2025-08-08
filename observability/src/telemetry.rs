use crate::conf::{ExecutionEnvironment, TelemetryConfig, ENVIRONMENT};
use crate::metrics::METRICS;
use crate::sys_metrics::start_sys_metrics_collection;
use anyhow::Context;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use opentelemetry::{global, propagation::Injector, trace::TracerProvider, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_prometheus::exporter;
pub use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
pub use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::{resource::Resource, trace::Sampler};
use prometheus::{Encoder, Registry as PrometheusRegistry, TextEncoder};
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
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
use tracing_subscriber::fmt::{layer, Layer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};

#[cfg(target_os = "linux")]
use prometheus::process_collector::ProcessCollector;

/// This is the HEADER key that will be used to store the request ID in the tracing context.
pub const TRACER_REQUEST_ID: &str = "x-zama-kms-request-id";
pub const TRACER_PARENT_SPAN_ID: &str = "x-zama-kms-parent-span-id";

#[derive(Clone)]
struct MetricsState {
    registry: Arc<PrometheusRegistry>,
    start_time: std::time::SystemTime,
}

impl MetricsState {
    fn new(registry: PrometheusRegistry) -> Self {
        Self {
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

pub fn init_metrics(settings: &TelemetryConfig) -> Result<SdkMeterProvider, anyhow::Error> {
    if matches!(*ENVIRONMENT, ExecutionEnvironment::Integration) {
        return Ok(SdkMeterProvider::default());
    }

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
                        settings
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
    let metrics_addr = settings
        .metrics_bind_address()
        .unwrap_or("0.0.0.0:9464")
        .parse::<SocketAddr>()
        .context("Failed to parse metrics bind address")?;

    let state = MetricsState::new(registry);

    // Use the global METRICS instance also as a sanity check that metrics are working
    METRICS.increment_request_counter("system_startup");

    // Get the current runtime handle
    let rt = tokio::runtime::Handle::current();

    rt.spawn(async move {
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route("/ready", get(readiness_handler))
            .route("/live", get(liveness_handler))
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
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        // Use a rolling file appender to prevent excessive file sizes
        let file_appender = never("", &log_path);
        let (non_blocking, guard) = non_blocking(file_appender);

        // Store the guard to keep the file handle open
        // Explicitly ignore errors since we can still proceed with console logging if this fails
        METRICS.set_trace_guard(Box::new(guard));

        let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info")
                .add_directive("tonic=info".parse().unwrap())
                .add_directive("h2=info".parse().unwrap())
                .add_directive("tower=warn".parse().unwrap())
                .add_directive("hyper=warn".parse().unwrap())
                .add_directive("opentelemetry_sdk=warn".parse().unwrap())
        });

        // Configure file output with JSON formatting for better machine parsing
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(false) // Disable ANSI colors in file output
            .json()
            .with_current_span(true) // Include current span in output
            .with_span_list(true); // Include span hierarchy

        let console_layer = fmt_layer();

        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .with(env_filter)
            .try_init()
            .context("Failed to initialize tracing")?;

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

    // If no endpoint is configured, set up only console logging
    let provider = if let Some(endpoint) = settings.tracing_endpoint() {
        println!(
            "Configuring OTLP Tracing exporter with endpoint: {} and tracing_otlp_timeout={}ms",
            endpoint,
            settings.tracing_otlp_timeout().as_millis()
        );

        // Create an exporter for OTLP
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(settings.tracing_otlp_timeout())
            .build()?;

        // Configure batch processing
        let batch_config = if let Some(batch_conf) = settings.batch() {
            println!(
                "Configuring batch processing with: max_queue_size={}, scheduled_delay={}ms, max_export_batch_size={}",
                batch_conf.max_queue_size(),
                batch_conf.scheduled_delay().as_millis(),
                batch_conf.max_export_batch_size(),
            );

            opentelemetry_sdk::trace::BatchConfigBuilder::default()
                .with_max_queue_size(batch_conf.max_queue_size())
                .with_scheduled_delay(batch_conf.scheduled_delay())
                .with_max_export_batch_size(batch_conf.max_export_batch_size())
                .build()
        } else {
            println!("Using default batch processing configuration");
            opentelemetry_sdk::trace::BatchConfigBuilder::default().build()
        };

        let batch_processor = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
            .with_batch_config(batch_config)
            .build();

        SdkTracerProvider::builder()
            .with_span_processor(batch_processor)
            .with_resource(
                Resource::builder()
                    .with_attributes(vec![KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                        service_name,
                    )])
                    .build(),
            )
            .build()
    } else {
        println!("No tracing_endpoint is provided");
        SdkTracerProvider::builder()
            .with_sampler(
                // When RUST_LOG=trace, sample everything
                // Otherwise, sample nothing for OpenTelemetry
                if std::env::var("RUST_LOG")
                    .map(|v| v == "trace")
                    .unwrap_or(false)
                {
                    Sampler::AlwaysOn
                } else {
                    Sampler::AlwaysOff
                },
            )
            .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
            .with_resource(
                Resource::builder()
                    .with_attributes(vec![KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                        service_name,
                    )])
                    .build(),
            )
            .build()
    };

    // Clone the provider to set it globally while keeping the original for explicit shutdown
    let tracer = provider.clone().tracer("kms-core");

    let env_filter = match *ENVIRONMENT {
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
    };

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    let fmt_layer = fmt_layer();

    tracing_subscriber::registry()
        .with(telemetry)
        .with(fmt_layer)
        .with(env_filter)
        .try_init()
        .context("Failed to initialize tracing")?;

    global::set_text_map_propagator(TraceContextPropagator::new());

    // Return the provider for explicit shutdown
    Ok(provider)
}

pub async fn init_telemetry(
    settings: &TelemetryConfig,
) -> anyhow::Result<(SdkTracerProvider, SdkMeterProvider)> {
    println!("Starting telemetry initialization...");

    // First initialize tracing as it's more critical
    println!("Initializing tracing subsystem...");
    let tracer_provider = init_tracing(settings).await?;

    // Now that tracing is initialized, we can use info! tracing macros
    info!("Tracing initialization completed successfully");

    println!("Initializing metrics subsystem...");
    let meter_provider = init_metrics(settings)?;
    info!("Metrics initialization completed successfully");

    if settings.enable_sys_metrics() {
        start_sys_metrics_collection(settings.refresh_interval())?;
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

    let span = if let Some(request_id) = request_id {
        info_span!("grpc_request", ?endpoint, %request_id)
    } else {
        info_span!("grpc_request", ?endpoint)
    };

    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(&headers_map))
    });
    span.set_parent(parent_context);
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
