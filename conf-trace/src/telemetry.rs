use crate::conf::{ExecutionEnvironment, TelemetryConfig, ENVIRONMENT};
use crate::metrics::METRICS;
use anyhow::Context;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use opentelemetry::{global, propagation::Injector, trace::TracerProvider as _, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::{metrics::SdkMeterProvider, runtime::Tokio, Resource};
use prometheus::{
    process_collector::ProcessCollector, Encoder, Registry as PrometheusRegistry, TextEncoder,
};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::Body;
use tonic::Status;
use tracing::{info, info_span, trace_span, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::{layer, Layer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};

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
    registry.register(Box::new(ProcessCollector::for_self()))?;

    // Create a Prometheus exporter
    let exporter = exporter()
        .with_registry(registry.clone())
        .build()
        .context("Failed to create Prometheus exporter")?;

    let provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(Resource::new(vec![
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
        ]))
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
    METRICS
        .increment_request_counter("system_startup")
        .context("Failed to increment system startup counter")?;

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

pub fn init_tracing(settings: &TelemetryConfig) -> Result<(), anyhow::Error> {
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

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(settings.tracing_otlp_timeout())
            .build()?;

        let batch_config = if let Some(batch_conf) = settings.batch() {
            println!(
                "Configuring batch processing with: max_queue_size={}, scheduled_delay={}ms, max_export_batch_size={}, max_concurrent_exports={}, export_timeout={}ms",
                batch_conf.max_queue_size(),
                batch_conf.scheduled_delay().as_millis(),
                batch_conf.max_export_batch_size(),
                batch_conf.max_concurrent_exports(),
                batch_conf.export_timeout().as_millis(),
            );

            opentelemetry_sdk::trace::BatchConfigBuilder::default()
                .with_max_queue_size(batch_conf.max_queue_size())
                .with_scheduled_delay(batch_conf.scheduled_delay())
                .with_max_export_batch_size(batch_conf.max_export_batch_size())
                .with_max_concurrent_exports(batch_conf.max_concurrent_exports())
                .with_max_export_timeout(batch_conf.export_timeout())
                .build()
        } else {
            println!("Using default batch processing configuration");
            opentelemetry_sdk::trace::BatchConfigBuilder::default().build()
        };

        let batch = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter, Tokio)
            .with_batch_config(batch_config)
            .build();

        opentelemetry_sdk::trace::TracerProvider::builder()
            .with_span_processor(batch)
            .with_resource(Resource::new(vec![KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                service_name,
            )]))
            .build()
    } else {
        // Set up console-only logging when no endpoint is configured
        println!("No tracing_endpoint is provided");
        if std::env::var("RUST_LOG")
            .map(|v| v == "trace")
            .unwrap_or(false)
        {
            println!("Traces are being printed into stdout");
            opentelemetry_sdk::trace::TracerProvider::builder()
                .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
                .build()
        } else {
            println!("Traces are disabled completely");
            return Ok(());
        }
    };

    // Set up the tracer
    let tracer = provider.tracer("kms-core");

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

    Ok(())
}

pub fn init_telemetry(settings: &TelemetryConfig) -> anyhow::Result<SdkMeterProvider> {
    println!("Starting telemetry initialization...");

    // First initialize tracing as it's more critical
    println!("Initializing tracing subsystem...");
    init_tracing(settings)?;

    // Now that tracing is initialized, we can use info! tracing macros
    info!("Tracing initialization completed successfully");

    println!("Initializing metrics subsystem...");
    let provider = init_metrics(settings)?;
    info!("Metrics initialization completed successfully");

    info!("Telemetry stack initialization completed");
    Ok(provider)
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

pub fn make_span(request: &tonic::codegen::http::Request<Body>) -> Span {
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
