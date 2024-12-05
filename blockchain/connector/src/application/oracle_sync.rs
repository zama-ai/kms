use crate::conf::ConnectorConfig;
use crate::domain::oracle::Oracle;
use crate::infrastructure::metrics::{MetricType, Metrics, OpenTelemetryMetrics};
use crate::infrastructure::oracle::OracleClient;
use events::kms::TransactionEvent;
use events::subscription::handler::{EventsMode, SubscriptionEventBuilder, SubscriptionHandler};
use events::subscription::Tx;
use typed_builder::TypedBuilder;

use super::SyncHandler;

#[derive(Clone, TypedBuilder)]
pub struct OracleEventHandler<R, O> {
    oracle: R,
    observability: O,
}

#[async_trait::async_trait]
impl<R, O> SubscriptionHandler<Tx> for OracleEventHandler<R, O>
where
    R: Oracle + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + Clone + 'static,
{
    #[tracing::instrument(level = "info", skip(self))]
    async fn on_message(
        &self,
        message: TransactionEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let oracle = self.oracle.clone();
        let observability = self.observability.clone();
        tokio::spawn(async move {
            tracing::debug!("Responding to Oracle with message: {:?}", message);
            let _ = oracle.respond(message.event).await.inspect_err(|e| {
                observability.increment(MetricType::OracleError, 1, &[("error", &e.to_string())]);
                tracing::error!("{:?}", e);
            });
        });
        Ok(())
    }

    // The gateway acts exactly the same whether it's catching up or
    // processing current messages
    async fn on_catchup(
        &self,
        message: TransactionEvent,
        _past_txs: &mut Vec<Tx>,
        _past_events: &mut Vec<TransactionEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.on_message(message).await
    }

    // The gateway does not need any past_txs, so rejects everything
    // in its filtering
    fn filter_for_catchup(&self, _tx: Tx) -> Option<Tx> {
        None
    }
}

//TODO(#1694): RENAME THIS GATEWAY-CONNECTOR

/// This is the _connector_ used by the Gateway.
///
/// (i.e. the component the Gateway uses to read from the KMS BC.)
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

// TODO(#1694): I think this should be removed when moving main.rs into a binary
// (As this is only used when running main with mode::Oracle which makes no sense AFAICT)
// Note that the OracleClient used here does simply nothing
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

impl<R> OracleSyncHandler<R, OpenTelemetryMetrics>
where
    R: Oracle + Send + Sync + Clone + 'static,
{
    pub async fn new_with_config_and_listener(
        config: ConnectorConfig,
        oracle: R,
    ) -> anyhow::Result<Self> {
        let metrics = OpenTelemetryMetrics::new();
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
    async fn listen_for_events(self, catch_up_num_blocks: Option<usize>) -> anyhow::Result<()> {
        let grpc_addresses = self.config.blockchain.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.blockchain.asc_address)
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
            .subscribe(self.oracle_handler.clone(), catch_up_num_blocks)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe: {:?}", e))
    }
}
