use clap::Parser;
use kms_blockchain_connector::config::{init_conf_with_trace, ConnectorConfig};

#[derive(Parser, Debug)]
#[clap(name = "kms-bsc-connector")]
pub struct Cli {
    #[clap(short, long, default_value = "config/default.toml")]
    config_file: Option<String>,

    #[clap(long)]
    catch_up_num_blocks: Option<usize>,
}

// This crate should either be used as a binary to instantiate the connector between KMS BC and core
// or as a lib by the GW to communicate with the KMS BC.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config: ConnectorConfig = init_conf_with_trace(cli.config_file.as_deref().unwrap()).await?;

    tracing::info!(
        "Starting kms-bsc-connector - config {:?}. Catching up {:?} blocks in the past.",
        config,
        cli.catch_up_num_blocks
    );

    kms_blockchain_connector::application::listen(config, cli.catch_up_num_blocks).await
}
