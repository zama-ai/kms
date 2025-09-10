use clap::Parser;
use observability::conf::{Settings, TelemetryConfig};
use observability::telemetry::init_tracing;
#[cfg(feature = "measure_memory")]
use peak_alloc::PeakAlloc;
use threshold_fhe::conf::party::PartyConf;
use threshold_fhe::grpc;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: PeakAlloc = PeakAlloc;

#[derive(Parser, Debug)]
#[clap(name = "moby")]
#[clap(about = "MPC party in a FHE threshold network")]
pub struct Cli {
    /// Config file with the party's configuration.
    #[clap(short, long)]
    conf_file: Option<String>,
}

// Below we set EXTENSION_DEGREE to be the highest available from the compilation flags
#[cfg(all(
    feature = "extension_degree_3",
    not(any(
        feature = "extension_degree_8",
        feature = "extension_degree_7",
        feature = "extension_degree_6",
        feature = "extension_degree_5",
        feature = "extension_degree_4"
    ))
))]
const EXTENSION_DEGREE: usize = 3;
#[cfg(all(
    feature = "extension_degree_4",
    not(any(
        feature = "extension_degree_8",
        feature = "extension_degree_7",
        feature = "extension_degree_6",
        feature = "extension_degree_5",
    ))
))]
const EXTENSION_DEGREE: usize = 4;
#[cfg(all(
    feature = "extension_degree_5",
    not(any(
        feature = "extension_degree_8",
        feature = "extension_degree_7",
        feature = "extension_degree_6",
    ))
))]
const EXTENSION_DEGREE: usize = 5;
#[cfg(all(
    feature = "extension_degree_6",
    not(any(feature = "extension_degree_8", feature = "extension_degree_7",))
))]
const EXTENSION_DEGREE: usize = 6;
#[cfg(all(
    feature = "extension_degree_7",
    not(any(feature = "extension_degree_8",))
))]
const EXTENSION_DEGREE: usize = 7;
#[cfg(feature = "extension_degree_8")]
const EXTENSION_DEGREE: usize = 8;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    default_provider().install_default().unwrap();
    #[cfg(feature = "measure_memory")]
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    println!("STARTING MOBY BINARY WITH EXTENSION DEGREE {EXTENSION_DEGREE}");
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
            .tracing_service_name("moby".to_string())
            .build()
    });

    let tracer_provider = init_tracing(&telemetry_config).await?;

    // Run the server and get the result
    let result = grpc::server::run::<EXTENSION_DEGREE>(&settings).await;

    // After the server has completed, shut down telemetry
    // Sleep to let some time for the process to export all the spans before shutdown
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Explicitly shut down telemetry
    if let Err(e) = tracer_provider.shutdown() {
        eprintln!("Error shutting down tracer provider: {e}");
    }

    result
}
