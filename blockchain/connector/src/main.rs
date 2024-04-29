use clap::Parser;
use connector::application::sync_handler::SyncHandler;
use connector::conf::telemetry::init_tracing;
use connector::conf::{ConnectorConfig, Settings};

#[derive(Parser, Debug)]
#[clap(name = "kms-asc-connector")]
pub struct Cli {
    #[clap(short, long, default_value = "config/default.toml")]
    conf_file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let settings = Settings::builder().path(cli.conf_file.as_deref()).build();
    let config: ConnectorConfig = settings
        .init_conf()
        .map_err(|e| anyhow::anyhow!("Error on inititalizing config {:?}", e))?;
    init_tracing(config.tracing.clone())
        .map_err(|e| anyhow::anyhow!("Error initializing tracing and metrics {:?}", e))?;

    let handler = SyncHandler::new_with_config(config).await?;

    handler.listen_for_events().await
}
