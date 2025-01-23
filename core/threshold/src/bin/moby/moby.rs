use clap::Parser;
use conf_trace::conf::{Settings, TelemetryConfig};
use conf_trace::telemetry::init_tracing;
use distributed_decryption::conf::party::PartyConf;
use distributed_decryption::grpc;
use peak_alloc::PeakAlloc;

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
#[cfg(feature = "extension_degree_8")]
const EXTENSION_DEGREE: usize = 8;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    distributed_decryption::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);
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

    let telemetry_config = settings.telemetry.clone().unwrap_or(
        TelemetryConfig::builder()
            .tracing_service_name("moby".to_string())
            .build(),
    );

    init_tracing(&telemetry_config)?;
    grpc::server::run::<EXTENSION_DEGREE>(&settings).await
}
