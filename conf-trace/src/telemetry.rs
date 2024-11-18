use crate::conf::{ExecutionEnvironment, Tracing, ENVIRONMENT};
use opentelemetry::propagation::Injector;
use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry::{global, KeyValue};
use opentelemetry_http::{HeaderExtractor, Request};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{Config, Tracer, TracerProvider};
use opentelemetry_sdk::Resource;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::Body;
use tonic::Status;
use tracing::{field, info_span, trace_span, warn, Id, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::{layer, Layer};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{EnvFilter, Registry};

/// This is the HEADER key that will be used to store the request ID in the tracing context.
pub const TRACER_REQUEST_ID: &str = "x-zama-kms-request-id";
pub const TRACER_PARENT_SPAN_ID: &str = "x-zama-kms-parent-span-id";

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
                        .with_endpoint(endpoint),
                )
                .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
                    Resource::new(vec![KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                        settings.service_name().to_string(),
                    )]),
                ));
            if let Some(batch) = settings.batch() {
                let batch_config = opentelemetry_sdk::trace::BatchConfigBuilder::default()
                    .with_max_queue_size(batch.max_queue_size())
                    .with_scheduled_delay(batch.scheduled_delay())
                    .with_max_export_batch_size(batch.max_export_batch_size())
                    .with_max_concurrent_exports(batch.max_concurrent_exports())
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

fn init_metrics(settings: Tracing) -> SdkMeterProvider {
    let registry = prometheus::Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .expect("Failed to create Prometheus exporter.");
    SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(Resource::new(vec![KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
            settings.service_name().to_string(),
        )]))
        .build()
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

pub fn init_tracing(settings: Tracing) -> Result<(), anyhow::Error> {
    // Define Tracer
    let tracer: Tracer = settings.clone().into();

    // Layer to filter traces based on level - trace, debug, info, warn, error.
    let fmt_layer = fmt_layer();
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    // Layer to add our configured tracer.
    let tracing_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Setting a trace context propagation data.
    global::set_text_map_propagator(TraceContextPropagator::new());
    global::set_error_handler(|error| tracing::error!("OpenTelemetry error: {:?}", error)).unwrap();

    let subscriber = Registry::default().with(tracing_layer).with(env_filter);

    // Simplest option to have conditional subscribers because of tracing-subscriber inability to
    // Clone
    if settings.json_logs().unwrap_or(false) {
        tracing::subscriber::set_global_default(subscriber.with(Layer::default().json()))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    } else {
        tracing::subscriber::set_global_default(subscriber.with(fmt_layer))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    };

    let metrics = init_metrics(settings);
    global::set_meter_provider(metrics);
    Ok(())
}

pub fn make_span(request: &Request<Body>) -> Span {
    let headers = request.headers();
    let endpoint = request.uri().path();
    let request_id = headers
        .get(TRACER_REQUEST_ID)
        .map(|r| r.to_str().map(|x| x.to_string()));

    let span = if endpoint.contains("Health/Check") {
        return trace_span!("healt_grpc_request", ?endpoint, ?headers);
    } else {
        match request_id {
            Some(Ok(request_id)) => {
                info_span!("grpc_request", ?endpoint, ?headers, trace_id = %request_id)
            }
            _ => info_span!("grpc_request", ?endpoint, ?headers, trace_id = field::Empty),
        }
    };

    match headers.get(TRACER_PARENT_SPAN_ID).map(|r| {
        tracing::debug!("Span header: {:?}", r);
        r.to_str()
            .unwrap_or("0")
            .to_string()
            .parse::<u64>()
            .unwrap_or(0)
    }) {
        Some(parent_span_id_u64) if parent_span_id_u64 > 0 => {
            tracing::debug!("Propagating span id {parent_span_id_u64}");
            let id = Id::from_u64(parent_span_id_u64);
            span.follows_from(id);
            tracing::debug!("Span id propagated.");
        }
        Some(_) | None => {
            tracing::warn!("Invalid or missing parent span id: {TRACER_PARENT_SPAN_ID}");
        }
    }
    span
}

/// Trace context propagation: associate the current span with the OTel trace of the given request,
/// if any and valid.
pub fn accept_trace(request: Request<Body>) -> Request<Body> {
    // Current context, if no or invalid data is received.
    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    Span::current().set_parent(parent_context);

    request
}

/// Record the OTel trace ID of the given request as "trace_id" field in the current span.
pub fn record_trace_id(request: Request<Body>) -> Request<Body> {
    let span = Span::current(); // Tokio tracing span.
    let trace_id = span.context().span().span_context().trace_id(); // OpenTelemetry trace ID.
    span.record("trace_id", trace_id.to_string());

    request
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
