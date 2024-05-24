use crate::conf::ConnectorConfig;
use crate::domain::oracle::Oracle;
use crate::infrastructure::metrics::{MetricType, Metrics, OpenTelemetryMetrics};
use crate::infrastructure::oracle::OracleClient;
use events::kms::TransactionEvent;
use events::subscription::handler::{EventsMode, SubscriptionEventBuilder, SubscriptionHandler};
use typed_builder::TypedBuilder;

use super::SyncHandler;

#[derive(Clone, TypedBuilder)]
pub struct OracleEventHandler<R, O> {
    oracle: R,
    observability: O,
}

#[async_trait::async_trait]
impl<R, O> SubscriptionHandler for OracleEventHandler<R, O>
where
    R: Oracle + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync,
{
    async fn on_message(
        &self,
        message: TransactionEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Responding to Oracle with message: {:?}", message);
        self.oracle.respond(message.event).await.map_err(|e| {
            self.observability
                .increment(MetricType::OracleError, 1, &[("error", &e.to_string())]);
            e
        })?;
        Ok(())
    }
}

#[derive(Clone, TypedBuilder)]
pub struct OracleSyncHandler<R, O> {
    oracle_handler: OracleEventHandler<R, O>,
    config: ConnectorConfig,
}

impl<R, O> OracleSyncHandler<R, O>
where
    R: Oracle + Clone + 'static + Send + Sync,
    O: Metrics + Clone + 'static + Send + Sync,
{
    pub async fn new(oracle: R, metrics: O) -> anyhow::Result<Self> {
        let handler = OracleEventHandler {
            oracle,
            observability: metrics,
        };
        Ok(Self {
            oracle_handler: handler,
            config: ConnectorConfig::default(),
        })
    }
}

impl OracleSyncHandler<OracleClient, OpenTelemetryMetrics> {
    pub async fn new_with_config(config: ConnectorConfig) -> anyhow::Result<Self> {
        let metrics = OpenTelemetryMetrics::new();
        let oracle = OracleClient::new(config.oracle.clone(), metrics.clone()).await?;
        let handler = OracleEventHandler {
            oracle,
            observability: metrics,
        };
        Ok(Self {
            oracle_handler: handler,
            config,
        })
    }
}

#[async_trait::async_trait]
impl<R, O> SyncHandler for OracleSyncHandler<R, O>
where
    R: Oracle + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + Clone + 'static,
{
    async fn listen_for_events(self) -> anyhow::Result<()> {
        let grpc_addresses = self.config.blockchain.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.blockchain.contract)
            .tick_time_in_sec(self.config.tick_interval_secs)
            .grpc_addresses(&grpc_addresses)
            .storage_path(&self.config.storage_path)
            .filter_events_mode(EventsMode::Response)
            .build()
            .subscription()
            .await?;

        tracing::info!(
            "Starting subscription to events from blockchain with {:?}",
            grpc_addresses
        );
        subscription
            .subscribe(self.oracle_handler.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe: {:?}", e))
    }
}
