use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{MeterProvider, PeriodicReader};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::{self, Tokio};
use opentelemetry_sdk::trace::{BatchSpanProcessor, Config, Tracer, TracerProvider};
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
                            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
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

fn init_metrics(settings: Tracing) -> MeterProvider {
    let exporter = opentelemetry_stdout::MetricsExporter::default();
    let reader = PeriodicReader::builder(exporter, runtime::Tokio).build();
    MeterProvider::builder()
        .with_reader(reader)
        .with_resource(Resource::new(vec![KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            settings.service_name().to_string(),
        )]))
        .build()
}

fn stdout_pipeline() -> Tracer {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let processor = BatchSpanProcessor::builder(exporter, Tokio).build();
    let config = Config::default().with_resource(Resource::new(vec![KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME,
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
    tracing::subscriber::set_global_default(last_layer).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let settings = settings.ok_or_else(|| anyhow::anyhow!("No settings found."))?;
    let metrics = init_metrics(settings);
    global::set_meter_provider(metrics);
    Ok(())
}
