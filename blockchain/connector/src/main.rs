use clap::Parser;
use kms_blockchain_connector::application::Mode;
use kms_blockchain_connector::conf::{init_conf_with_trace, ConnectorConfig};

// TODO: rename conf-file to config-file for consistency between core and connector
#[derive(Parser, Debug)]
#[clap(name = "kms-asc-connector")]
pub struct Cli {
    #[clap(short, long, default_value = "config/default.toml")]
    conf_file: Option<String>,

    #[clap(long)]
    catch_up_num_blocks: Option<usize>,

    #[command(subcommand)]
    mode: Option<Mode>,
}

// TODO(#1694): Move this into a bin folder, and remove the mode Option.
// This crate should either be used as a binary to instantiate the connector between KMS BC and core
// or as a lib by the GW to communicate with the KMS BC.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mode = cli.mode.unwrap_or(Mode::KmsCore);
    let config: ConnectorConfig = init_conf_with_trace(cli.conf_file.as_deref().unwrap()).await?;

    tracing::info!(
        "Starting kms-asc-connector in mode '{:?}' - config {:?}. Catching up {:?} blocks in the past.",
        mode,
        config,
        cli.catch_up_num_blocks
    );

    kms_blockchain_connector::application::listen(config, mode, cli.catch_up_num_blocks).await
}
