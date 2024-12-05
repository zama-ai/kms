use crate::conf::{ExecutionEnvironment, Tracing, ENVIRONMENT};
use anyhow::Context;
use axum::{
    http::{header::CONTENT_TYPE, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use opentelemetry::global;
use opentelemetry::propagation::Injector;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_http::{HeaderExtractor, Request};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{Config, Tracer, TracerProvider};
use opentelemetry_sdk::Resource;
use prometheus::{Encoder, Registry as PrometheusRegistry, TextEncoder};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::Body;
use tonic::Status;
use tracing::{info_span, trace_span, warn, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::{layer, Layer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};

/// This is the HEADER key that will be used to store the request ID in the tracing context.
pub const TRACER_REQUEST_ID: &str = "x-zama-kms-request-id";
pub const TRACER_PARENT_SPAN_ID: &str = "x-zama-kms-parent-span-id";

/// Default timeout for trace export operations
const DEFAULT_EXPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for initialization operations
const DEFAULT_INIT_TIMEOUT: Duration = Duration::from_secs(10);

impl From<Tracing> for Tracer {
    fn from(settings: Tracing) -> Self {
        let result;
        if *ENVIRONMENT == ExecutionEnvironment::Local {
            result = stdout_pipeline(settings.service_name());
            tracing::info!("Environment is {:?}. Logging to stdout", *ENVIRONMENT);
            result
        } else if let Some(endpoint) = settings.endpoint() {
            let mut pipeline = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(endpoint)
                        .with_timeout(DEFAULT_EXPORT_TIMEOUT),
                )
                .with_trace_config(
                    opentelemetry_sdk::trace::config()
                        .with_resource(Resource::new(vec![KeyValue::new(
                            opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                            settings.service_name().to_string(),
                        )]))
                        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
                            opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(0.1),
                        ))),
                );

            if let Some(batch) = settings.batch() {
                let batch_config = opentelemetry_sdk::trace::BatchConfigBuilder::default()
                    .with_max_queue_size(batch.max_queue_size())
                    .with_scheduled_delay(batch.scheduled_delay())
                    .with_max_export_batch_size(batch.max_export_batch_size())
                    .with_max_concurrent_exports(batch.max_concurrent_exports())
                    .with_max_export_timeout(DEFAULT_EXPORT_TIMEOUT)
                    .build();
                pipeline = pipeline.with_batch_config(batch_config);
            }

            result = pipeline
                .install_batch(Tokio)
                .expect("Failed to install OpenTelemetry tracer.");

            tracing::info!(
                "Environment is {:?}. Logging to endpoint: {:?}",
                *ENVIRONMENT,
                endpoint,
            );
            result
        } else {
            result = stdout_pipeline(settings.service_name());
            tracing::info!("Environment is {:?}. Logging to stdout", *ENVIRONMENT);
            result
        }
    }
}

/// Initialize metrics with the given settings and return a shutdown signal sender
pub fn init_metrics(settings: Tracing) -> (SdkMeterProvider, tokio::sync::oneshot::Sender<()>) {
    // Skip metrics initialization in test mode
    if matches!(*ENVIRONMENT, ExecutionEnvironment::Integration) {
        // Return a completely empty meter provider that does nothing
        let (tx, _) = tokio::sync::oneshot::channel();
        return (SdkMeterProvider::default(), tx);
    }

    let registry = PrometheusRegistry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .expect("Failed to create Prometheus exporter.");

    // Create and install the meter provider first
    let provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(Resource::new(vec![KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
            settings.service_name().to_string(),
        )]))
        .build();

    // Set the global meter provider
    opentelemetry::global::set_meter_provider(provider.clone());

    // Start metrics HTTP server
    let port = settings.metrics_port();
    let addr = format!("0.0.0.0:{}", port)
        .parse::<SocketAddr>()
        .expect("Failed to parse metrics address");

    // Create a new Tokio runtime for the metrics server
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    // Create a channel to signal when the server is ready
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        rt.block_on(async move {
            let app = Router::new()
                .route(
                    "/metrics",
                    get(move || {
                        let registry = registry.clone();
                        async move {
                            let encoder = TextEncoder::new();
                            let metric_families = registry.gather();
                            let mut buffer = vec![];
                            encoder.encode(&metric_families, &mut buffer).unwrap();

                            (
                                StatusCode::OK,
                                [(CONTENT_TYPE, "text/plain; version=0.0.4")],
                                buffer,
                            )
                                .into_response()
                        }
                    }),
                )
                .route(
                    "/health",
                    get(|| async { (StatusCode::OK, [(CONTENT_TYPE, "text/plain")], "ok") }),
                );

            let server = axum::serve(
                tokio::net::TcpListener::bind(&addr)
                    .await
                    .expect("Failed to bind metrics server"),
                app,
            )
            .with_graceful_shutdown(async {
                shutdown_rx.await.ok();
            });

            // Signal that we're ready to accept connections
            tx.send(()).expect("Failed to send ready signal");

            // Start serving
            server.await.expect("Metrics server error");
        });
    });

    // Wait for server to be ready
    rx.recv().expect("Failed to receive ready signal");

    tracing::info!("Metrics server listening on {}", addr);

    (provider, shutdown_tx)
}

fn stdout_pipeline(service_name: &str) -> Tracer {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let config = Config::default().with_resource(Resource::new(vec![KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
        service_name.to_string(),
    )]));
    TracerProvider::builder()
        .with_simple_exporter(exporter)
        .with_config(config)
        .build()
        .tracer(service_name.to_string())
}

fn fmt_layer<S>() -> Layer<S> {
    match *ENVIRONMENT {
        ExecutionEnvironment::Production
        | ExecutionEnvironment::Development
        | ExecutionEnvironment::Stage => layer().with_span_events(FmtSpan::CLOSE),
        _ => layer(),
    }
}

pub async fn init_tracing(settings: Tracing) -> Result<(), anyhow::Error> {
    let init_span = info_span!("init_tracing").entered();

    // Initialize components concurrently with timeout
    let init_result = tokio::time::timeout(DEFAULT_INIT_TIMEOUT, async {
        // Create tracer and metrics concurrently
        let settings_for_tracer = settings.clone();
        let settings_for_metrics = settings.clone();
        let (tracer, metrics) = tokio::join!(
            tokio::task::spawn_blocking(move || -> Result<Tracer, anyhow::Error> {
                Ok(settings_for_tracer.into())
            }),
            tokio::task::spawn_blocking(move || -> Result<SdkMeterProvider, anyhow::Error> {
                Ok(init_metrics(settings_for_metrics).0)
            })
        );

        let tracer = tracer.context("Failed to create tracer")?;
        let metrics = metrics.context("Failed to create metrics provider")?;

        // Set up propagator and error handler in background
        tokio::task::spawn_blocking(move || {
            global::set_text_map_propagator(TraceContextPropagator::new());
            global::set_error_handler(|error| tracing::error!("OpenTelemetry error: {:?}", error))
                .unwrap();
        })
        .await?;

        // Layer to filter traces based on level
        let fmt_layer = fmt_layer();
        let env_filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap();

        // Layer to add our configured tracer
        let tracing_layer = tracing_opentelemetry::layer().with_tracer(tracer?);

        let subscriber = Registry::default().with(tracing_layer).with(env_filter);

        // Set up subscriber based on json_logs setting
        if settings.json_logs().unwrap_or(false) {
            tracing::subscriber::set_global_default(subscriber.with(Layer::default().json()))
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        } else {
            tracing::subscriber::set_global_default(subscriber.with(fmt_layer))
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        }

        // Set meter provider and initialize metrics registry
        global::set_meter_provider(metrics?);

        // Initialize the global metrics instance
        let _ = crate::metrics::METRICS.clone();

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Initialization timed out")?;

    init_span.exit();
    init_result
}

pub fn make_span(request: &Request<Body>) -> Span {
    let endpoint = request.uri().path();

    // Create span without blocking
    if endpoint.contains("Health/Check") {
        return trace_span!("health_grpc_request", ?endpoint);
    }

    let headers = request.headers();

    let request_id = headers
        .get(TRACER_REQUEST_ID)
        .and_then(|r| r.to_str().ok())
        .map(String::from);

    let span = if let Some(request_id) = request_id {
        info_span!("grpc_request", ?endpoint, %request_id)
    } else {
        info_span!("grpc_request", ?endpoint)
    };

    let parent_context =
        global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)));
    span.set_parent(parent_context);
    span
}

/// Propagate the current span context to the outgoing request.
#[derive(Clone)]
pub struct ContextPropagator;

/// Implement the `Interceptor` trait to propagate the current span context to the outgoing request.
impl Interceptor for ContextPropagator {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        global::get_text_map_propagator(|propagator| {
            let context = Span::current().context();
            propagator.inject_context(&context, &mut MetadataInjector(request.metadata_mut()))
        });

        Ok(request)
    }
}

/// `MetadataInjector` is a helper struct to inject metadata into a request.
/// It is used to propagate the current span context to the outgoing request. See `ContextPropagator`.
///
/// This used to be in pairs with the `ContextPropagator` struct. `ContextPropagator` is used for
/// the client side, in this case the party that is sending protocol messages to other parties.
/// `MetadataInjector` is used for the server side, in this case the party that is receiving protocol
struct MetadataInjector<'a>(&'a mut MetadataMap);

/// Implement the `Injector` trait to propagate the current span context to the outgoing request.
impl Injector for MetadataInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        match MetadataKey::from_bytes(key.as_bytes()) {
            Ok(key) => match MetadataValue::try_from(&value) {
                Ok(value) => {
                    self.0.insert(key, value);
                }

                Err(error) => warn!(value, error = format!("{error:#}"), "parse metadata value"),
            },

            Err(error) => warn!(key, error = format!("{error:#}"), "parse metadata key"),
        }
    }
}
