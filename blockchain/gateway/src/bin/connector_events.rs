use events::kms::KmsEvent;
use gateway::config::init_conf_with_trace_connector;
use kms_blockchain_connector::application::oracle_sync::OracleSyncHandler;
use kms_blockchain_connector::application::SyncHandler;
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

    let config = init_conf_with_trace_connector("config/default.toml")?;

    OracleSyncHandler::new_with_config_and_listener(config, gateway)
        .await?
        .listen_for_events(None)
        .await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    listen().await?;
    Ok(())
}
