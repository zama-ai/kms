use clap::Parser;
use kms_blockchain_connector::application::Mode;
use kms_blockchain_connector::conf::telemetry::init_tracing;
use kms_blockchain_connector::conf::{ConnectorConfig, Settings};

#[derive(Parser, Debug)]
#[clap(name = "kms-asc-connector")]
pub struct Cli {
    #[clap(short, long, default_value = "config/default.toml")]
    conf_file: Option<String>,

    #[command(subcommand)]
    mode: Option<Mode>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mode = cli.mode.unwrap_or(Mode::KmsCore);
    let settings = Settings::builder().path(cli.conf_file.as_deref()).build();
    let config: ConnectorConfig = settings
        .init_conf()
        .map_err(|e| anyhow::anyhow!("Error on inititalizing config {:?}", e))?;
    init_tracing(config.tracing.clone())
        .map_err(|e| anyhow::anyhow!("Error initializing tracing and metrics {:?}", e))?;

    tracing::info!("Starting kms-asc-connector with mode '{:?}'", mode);

    kms_blockchain_connector::application::listen(config, mode).await
}
