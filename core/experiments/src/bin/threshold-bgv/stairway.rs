//! MPC party binary for the BGV threshold network.
//! Uses the experimental BGV/BFV choreography routing helper.
use clap::Parser;
use experiments::choreography;
use experiments::choreography::bgv::strategies::ExperimentalChoreoRoutingHelper;
use experiments::conf::party::PartyConf;
use observability::conf::{Settings, TelemetryConfig};
use observability::telemetry::init_tracing;
#[cfg(feature = "measure_memory")]
use peak_alloc::PeakAlloc;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: PeakAlloc = PeakAlloc;

#[derive(Parser, Debug)]
#[clap(name = "stairway")]
#[clap(about = "MPC party in a BGV threshold network")]
pub struct Cli {
    /// Config file with the party's configuration.
    #[clap(short, long)]
    conf_file: Option<String>,

    /// Disable telemetry (tracing and metrics).
    #[clap(long)]
    no_telemetry: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    default_provider().install_default().unwrap();
    #[cfg(feature = "measure_memory")]
    experiments::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    println!("STARTING STAIRWAY BINARY");
    let args = Cli::parse();

    let settings_builder = Settings::builder();
    let settings: PartyConf = if let Some(path) = args.conf_file {
        settings_builder
            .path(&path)
            .env_prefix("DDEC")
            .build()
            .init_conf()?
    } else {
        settings_builder.env_prefix("DDEC").build().init_conf()?
    };

    let telemetry_config = settings.telemetry.clone().unwrap_or_else(|| {
        TelemetryConfig::builder()
            .tracing_service_name("stairway".to_string())
            .build()
    });

    let tracer_provider = if args.no_telemetry {
        None
    } else {
        Some(init_tracing(&telemetry_config).await?)
    };

    // Use degree 4 as that's the default when compiling the algebra library, doesn't matter at all for BGV
    let result = choreography::server::run::<4>(&settings, ExperimentalChoreoRoutingHelper).await;

    // Sleep to let some time for the process to export all the spans before shutdown
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Explicitly shut down telemetry
    if let Some(provider) = tracer_provider
        && let Err(e) = provider.shutdown()
    {
        eprintln!("Error shutting down tracer provider: {e}");
    }

    result
}
