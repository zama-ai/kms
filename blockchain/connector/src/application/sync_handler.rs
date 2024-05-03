use crate::conf::ConnectorConfig;
use crate::domain::blockchain::Blockchain;
use crate::domain::kms::{create_kms_operation, Kms};
use crate::infrastructure::blockchain::KmsBlockchain;
use crate::infrastructure::coordinator::KmsCoordinator;
use crate::infrastructure::metrics::{MetricType, Metrics, OpenTelemetryMetrics};
use events::kms::KmsEvent;
use events::subscription::handler::{SubscriptionEventBuilder, SubscriptionHandler};
use typed_builder::TypedBuilder;

#[derive(Clone)]
struct KmsConnectorEventHandler<B, O> {
    blockchain: B,
    kms_client: KmsCoordinator,
    observability: O,
}

#[async_trait::async_trait]
impl<B, O> SubscriptionHandler for KmsConnectorEventHandler<B, O>
where
    B: Blockchain + Send + Sync,
    O: Metrics + Send + Sync,
{
    async fn on_message(
        &self,
        message: KmsEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Received message: {:?}", message);
        let result = create_kms_operation(message, self.kms_client.clone())?
            .run_operation()
            .await
            .map_err(|e| {
                self.observability
                    .increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
                e
            })?;
        tracing::info!("Sending result to blockchain: {}", result.to_string());
        let tx_id = result.txn_id_hex();
        self.blockchain.send_result(result).await.map_err(|e| {
            self.observability
                .increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
            e
        })?;
        self.observability
            .increment(MetricType::TxProcessed, 1, &[("tx_id", tx_id.as_str())]);
        tracing::info!("Result sent to blockchain");
        Ok(())
    }
}

#[derive(Clone, TypedBuilder)]
pub struct SyncHandler<B, O> {
    kms_connector_handler: KmsConnectorEventHandler<B, O>,
    config: ConnectorConfig,
}

impl SyncHandler<KmsBlockchain, OpenTelemetryMetrics> {
    pub async fn new_with_config(config: ConnectorConfig) -> anyhow::Result<Self> {
        let metrics = OpenTelemetryMetrics::new();
        let blockchain = KmsBlockchain::new(config.blockchain.clone(), metrics.clone()).await?;
        let kms = KmsCoordinator::new(config.coordinator.clone(), metrics.clone()).await?;
        let handler = KmsConnectorEventHandler {
            blockchain,
            kms_client: kms,
            observability: metrics,
        };
        Ok(Self {
            kms_connector_handler: handler,
            config,
        })
    }
}

impl<B, O> SyncHandler<B, O>
where
    B: Blockchain + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + Clone + 'static,
{
    pub async fn listen_for_events(self) -> anyhow::Result<()> {
        let grpc_addresses = self.config.blockchain.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.blockchain.contract_address)
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
