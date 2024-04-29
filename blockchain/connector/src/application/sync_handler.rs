use crate::conf::ConnectorConfig;
use crate::domain::blockchain::Blockchain;
use crate::domain::kms::{create_kms_operation, Kms};
use crate::infrastructure::blockchain::KmsBlockchain;
use crate::infrastructure::coordinator::KmsCoordinator;
use events::kms::KmsEvent;
use events::subscription::handler::{SubscriptionEventBuilder, SubscriptionHandler};
use typed_builder::TypedBuilder;

#[derive(Clone)]
struct KmsConnectorEventHandler<B> {
    blockchain: B,
    kms_client: KmsCoordinator,
}

#[async_trait::async_trait]
impl<B> SubscriptionHandler for KmsConnectorEventHandler<B>
where
    B: Blockchain + Send + Sync,
{
    async fn on_message(
        &self,
        message: KmsEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Received message: {:?}", message);
        let result = create_kms_operation(message, self.kms_client.clone())?
            .run_operation()
            .await?;
        tracing::info!("Sending result to blockchain: {}", result.to_string());
        self.blockchain.send_result(result).await?;
        tracing::info!("Result sent to blockchain");
        Ok(())
    }
}

#[derive(Clone, TypedBuilder)]
pub struct SyncHandler<B> {
    kms_connector_handler: KmsConnectorEventHandler<B>,
    config: ConnectorConfig,
}

impl SyncHandler<KmsBlockchain> {
    pub async fn new_with_config(config: ConnectorConfig) -> anyhow::Result<Self> {
        let blockchain = KmsBlockchain::new(config.clone()).await?;
        let kms = KmsCoordinator::new(config.clone()).await?;
        let handler = KmsConnectorEventHandler {
            blockchain,
            kms_client: kms,
        };
        Ok(Self {
            kms_connector_handler: handler,
            config,
        })
    }
}

impl<B> SyncHandler<B>
where
    B: Blockchain + Send + Sync + Clone + 'static,
{
    pub async fn listen_for_events(self) -> anyhow::Result<()> {
        let grpc_addresses = self.config.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.contract_addresses)
            .tick_time_in_sec(self.config.tick_interval_secs)
            .grpc_addresses(&grpc_addresses)
            .storage_path(&self.config.storage_path)
            .build()
            .subscription()
            .await?;

        tracing::info!(
            "Starting subscription to events from blockchain with {:?}",
            grpc_addresses
        );
        subscription
            .subscribe(self.kms_connector_handler.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe: {:?}", e))
    }
}
