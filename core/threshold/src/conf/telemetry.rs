use opentelemetry::propagation::Injector;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_http::{HeaderExtractor, Request};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{BatchSpanProcessor, Config, Tracer, TracerProvider};
use opentelemetry_sdk::Resource;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::Body;
use tonic::Status;
use tracing::{info_span, warn, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::{layer, Layer};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{EnvFilter, Registry};

use super::{Mode, Tracing, ENVIRONMENT};

impl From<Tracing> for Tracer {
    fn from(settings: Tracing) -> Self {
        match *ENVIRONMENT {
            Mode::Production | Mode::Development | Mode::Stage => {
                opentelemetry_otlp::new_pipeline()
                    .tracing()
                    .with_exporter(
                        opentelemetry_otlp::new_exporter()
                            .tonic()
                            .with_endpoint(settings.endpoint()),
                    )
                    .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
                        Resource::new(vec![KeyValue::new(
                            opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
                            settings.service_name().to_string(),
                        )]),
                    ))
                    .install_batch(Tokio)
                    .expect("Failed to install OpenTelemetry tracer.")
            }
            _ => stdout_pipeline(),
        }
    }
}

fn stdout_pipeline() -> Tracer {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let processor = BatchSpanProcessor::builder(exporter, Tokio).build();
    let config = Config::default().with_resource(Resource::new(vec![KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
        "distributed-decryption".to_string(),
    )]));
    TracerProvider::builder()
        .with_span_processor(processor)
        .with_config(config)
        .build()
        .tracer("distributed-decryption")
}

fn fmt_layer<S>() -> Layer<S> {
    match *ENVIRONMENT {
        Mode::Production | Mode::Development | Mode::Stage => layer(),
        _ => layer().with_span_events(FmtSpan::CLOSE),
    }
}

pub fn init_tracing(settings: Option<Tracing>) -> Result<(), anyhow::Error> {
    // Define Tracer
    let tracer: Tracer = settings
        .clone()
        .map(Into::into)
        .unwrap_or_else(stdout_pipeline);
    // Layer to filter traces based on level - trace, debug, info, warn, error.
    let fmt_layer = fmt_layer();
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    // Layer to add our configured tracer.
    let tracing_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    // Setting a trace context propagation data.
    let subscriber = Registry::default().with(tracing_layer);
    global::set_text_map_propagator(TraceContextPropagator::new());
    global::set_error_handler(|error| eprintln!("OpenTelemetry error {:}", error)).unwrap();
    let last_layer = subscriber.with(env_filter).with(fmt_layer);
    tracing::subscriber::set_global_default(last_layer).map_err(|e| anyhow::anyhow!("{e:?}"))
}

pub fn make_span(request: &Request<Body>) -> Span {
    let headers = request.headers();
    let endpoint = request.uri().path();
    info_span!("grpc_request", ?endpoint, ?headers)
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

/// Propagate the current span context to the outgoing request.
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
