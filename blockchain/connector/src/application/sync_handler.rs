use crate::conf::ConnectorConfig;
use crate::domain::blockchain::Blockchain;
use crate::domain::kms::KmsOperation;
use crate::infrastructure::blockchain::KmsBlockchain;
use crate::infrastructure::coordinator::KmsCoordinator;
use crate::infrastructure::metrics::{MetricType, Metrics, OpenTelemetryMetrics};
use events::kms::KmsEvent;
use events::subscription::handler::{SubscriptionEventBuilder, SubscriptionHandler};
use typed_builder::TypedBuilder;

#[derive(Clone)]
struct KmsConnectorEventHandler<B, K, O> {
    blockchain: B,
    kms: K,
    observability: O,
}

#[async_trait::async_trait]
impl<B, K, O> SubscriptionHandler for KmsConnectorEventHandler<B, K, O>
where
    B: Blockchain + Send + Sync,
    K: KmsOperation + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync,
{
    async fn on_message(
        &self,
        message: KmsEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Received message: {:?}", message);
        let result = self.kms.run(message).await.map_err(|e| {
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
pub struct SyncHandler<B, K, O> {
    kms_connector_handler: KmsConnectorEventHandler<B, K, O>,
    config: ConnectorConfig,
}

impl<B, K, O> SyncHandler<B, K, O>
where
    B: Blockchain + Clone,
    K: KmsOperation + Clone,
    O: Metrics + Clone,
{
    pub async fn new(blockchain: B, kms: K, metrics: O) -> anyhow::Result<Self> {
        let handler = KmsConnectorEventHandler {
            blockchain,
            kms,
            observability: metrics,
        };
        Ok(Self {
            kms_connector_handler: handler,
            config: ConnectorConfig::default(),
        })
    }
}

impl SyncHandler<KmsBlockchain, KmsCoordinator, OpenTelemetryMetrics> {
    pub async fn new_with_config(config: ConnectorConfig) -> anyhow::Result<Self> {
        let metrics = OpenTelemetryMetrics::new();
        let blockchain = KmsBlockchain::new(config.blockchain.clone(), metrics.clone()).await?;
        let kms = KmsCoordinator::new(config.coordinator.clone(), metrics.clone()).await?;
        let handler = KmsConnectorEventHandler {
            blockchain,
            kms,
            observability: metrics,
        };
        Ok(Self {
            kms_connector_handler: handler,
            config,
        })
    }
}

impl<B, K, O> SyncHandler<B, K, O>
where
    B: Blockchain + Send + Sync + Clone + 'static,
    K: KmsOperation + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + Clone + 'static,
{
    pub async fn listen_for_events(self) -> anyhow::Result<()> {
        let grpc_addresses = self.config.blockchain.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.blockchain.contract)
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
