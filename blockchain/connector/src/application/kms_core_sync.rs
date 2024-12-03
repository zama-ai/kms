use crate::conf::ConnectorConfig;
use crate::domain::blockchain::Blockchain;
use crate::domain::kms::Kms;
use crate::infrastructure::blockchain::KmsBlockchain;
use crate::infrastructure::core::KmsCore;
use crate::infrastructure::metrics::{MetricType, Metrics, OpenTelemetryMetrics};
use crate::infrastructure::store::KVStore;
use events::kms::TransactionEvent;
use events::subscription::handler::{EventsMode, SubscriptionEventBuilder, SubscriptionHandler};
use typed_builder::TypedBuilder;

use super::SyncHandler;

#[derive(Clone, TypedBuilder)]
pub struct KmsCoreEventHandler<B, K, O> {
    blockchain: B,
    kms: K,
    observability: O,
}

#[async_trait::async_trait]
impl<B, K, O> SubscriptionHandler for KmsCoreEventHandler<B, K, O>
where
    B: Blockchain + Send + Sync,
    K: Kms + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync,
{
    async fn on_message(
        &self,
        message: TransactionEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Received message: {:?}", message);
        let operation_value = self
            .blockchain
            .get_operation_value(&message.event)
            .await
            .inspect_err(|e| {
                self.observability
                    .increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
            })?;

        tracing::info!("Running KMS operation with value: {:?}", operation_value);
        let kms_config = if operation_value.needs_kms_config() {
            Some(self.blockchain.get_kms_configuration().await?)
        } else {
            None
        };
        tracing::info!("Successfully retrieved kms configuration {:?}", kms_config);

        let result = self
            .kms
            .run(message.event, operation_value, kms_config)
            .await
            .inspect_err(|e| {
                tracing::error!("KMS connector error running kms operation: {:?}", e);
                self.observability
                    .increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
            })?;

        tracing::info!("Sending response to the blockchain: {}", result.to_string());
        let tx_id = result.txn_id_hex();
        self.blockchain.send_result(result).await.inspect_err(|e| {
            tracing::error!(
                "KMS connector error sending the response to the blockchain: {:?}",
                e
            );
            self.observability
                .increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
        })?;
        self.observability
            .increment(MetricType::TxProcessed, 1, &[("tx_id", tx_id.as_str())]);
        tracing::info!("Result sent to blockchain");
        Ok(())
    }
}

#[derive(Clone, TypedBuilder)]
pub struct KmsCoreSyncHandler<B, K, O> {
    kms_connector_handler: KmsCoreEventHandler<B, K, O>,
    config: ConnectorConfig,
}

impl<B, K, O> KmsCoreSyncHandler<B, K, O>
where
    B: Blockchain + Clone + 'static + Send + Sync,
    K: Kms + Clone + 'static + Send + Sync,
    O: Metrics + Clone + 'static + Send + Sync,
{
    pub async fn new(blockchain: B, kms: K, metrics: O) -> anyhow::Result<Self> {
        let handler = KmsCoreEventHandler {
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

impl KmsCoreSyncHandler<KmsBlockchain, KmsCore<KVStore>, OpenTelemetryMetrics> {
    pub async fn new_with_config(config: ConnectorConfig) -> anyhow::Result<Self> {
        let metrics = OpenTelemetryMetrics::new();
        let blockchain = KmsBlockchain::new(config.blockchain.clone(), metrics.clone()).await?;
        let storage = KVStore::new(config.store.clone());
        // TODO the core should read the addresses from the blockchain
        // instead of the config
        let kms = KmsCore::new(config.core.clone(), storage, metrics.clone())?;
        let handler = KmsCoreEventHandler {
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

#[async_trait::async_trait]
impl<B, K, O> SyncHandler for KmsCoreSyncHandler<B, K, O>
where
    B: Blockchain + Send + Sync + Clone + 'static,
    K: Kms + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + Clone + 'static,
{
    async fn listen_for_events(self) -> anyhow::Result<()> {
        let grpc_addresses = self.config.blockchain.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.blockchain.asc_address)
            .tick_time_in_sec(self.config.tick_interval_secs)
            .grpc_addresses(&grpc_addresses)
            .storage_path(&self.config.storage_path)
            .filter_events_mode(EventsMode::Request)
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
