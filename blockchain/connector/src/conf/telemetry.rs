use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{Config, Tracer, TracerProvider};
use opentelemetry_sdk::Resource;
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
            _ => stdout_pipeline(settings.clone()),
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

fn stdout_pipeline(settings: Tracing) -> Tracer {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let config = Config::default().with_resource(Resource::new(vec![KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME.to_string(),
        settings.service_name().to_string(),
    )]));
    TracerProvider::builder()
        .with_simple_exporter(exporter)
        .with_config(config)
        .build()
        .tracer(settings.service_name().to_string())
}

fn fmt_layer<S>() -> Layer<S> {
    match *ENVIRONMENT {
        Mode::Production | Mode::Development | Mode::Stage => {
            layer().with_span_events(FmtSpan::CLOSE)
        }
        _ => layer(),
    }
}

pub fn init_tracing(settings: Option<Tracing>) -> Result<(), anyhow::Error> {
    // Define Tracer
    let tracer: Tracer = settings
        .clone()
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!("No settings found."))?;
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
    tracing::subscriber::set_global_default(last_layer).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let settings = settings.ok_or_else(|| anyhow::anyhow!("No settings found."))?;
    let metrics = init_metrics(settings);
    global::set_meter_provider(metrics);
    Ok(())
}
