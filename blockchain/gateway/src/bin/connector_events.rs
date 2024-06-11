use events::kms::KmsEvent;
use kms_blockchain_connector::application::oracle_sync::OracleSyncHandler;
use kms_blockchain_connector::application::SyncHandler;
use kms_blockchain_connector::conf::ConnectorConfig;
use kms_blockchain_connector::conf::Settings;
use kms_blockchain_connector::domain::oracle::Oracle;
use tracing::info;

#[derive(Clone)]
pub struct GatewayClient {
    //metrics: OpenTelemetryMetrics,
}

#[async_trait::async_trait]
impl Oracle for GatewayClient {
    async fn respond(&self, event: KmsEvent) -> anyhow::Result<()> {
        info!("tx_id: {:#?}", event.txn_id());
        info!("🚀🚀🚀🚀🚀🚀 Gateway event: {:?}", event);
        Ok(())
    }
}

pub async fn listen() -> anyhow::Result<()> {
    let gateway = GatewayClient {};

    let settings = Settings::builder()
        .path(Some("config/default.toml"))
        .build();
    let config: ConnectorConfig = settings
        .init_conf()
        .map_err(|e| anyhow::anyhow!("Error on inititalizing config {:?}", e))?;

    OracleSyncHandler::new_with_config_and_listener(config, gateway)
        .await?
        .listen_for_events()
        .await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber with env filter
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        //.with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    listen().await?;
    Ok(())
}
