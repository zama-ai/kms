use clap::Parser;
use kms_blockchain_connector::application::Mode;
use kms_blockchain_connector::conf::{init_conf_with_trace, ConnectorConfig};

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
    let config: ConnectorConfig = init_conf_with_trace(cli.conf_file.as_deref().unwrap())?;

    tracing::info!(
        "Starting kms-asc-connector in mode '{:?}' - config {:?}",
        mode,
        config
    );

    kms_blockchain_connector::application::listen(config, mode).await
}
