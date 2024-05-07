use dashmap::DashMap;
use opentelemetry::metrics::ObservableCounter;
use opentelemetry::{global, KeyValue};

pub trait Metrics {
    fn increment(&self, counter: MetricType, amount: u64, tags: &[(&str, &str)]);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricType {
    TxProcessed,
    TxError,
    BlockchainSuccess,
    BlockchainError,
    CoordinatorSuccess,
    CoordinatorError,
    CoordinatorResponseSuccess,
    CoordinatorResponseError,
}

#[derive(Clone)]
pub struct OpenTelemetryMetrics {
    counters: DashMap<MetricType, ObservableCounter<u64>>,
}

impl OpenTelemetryMetrics {
    pub(crate) fn new() -> Self {
        let meter = global::meter("kms_connector");
        let connector_txs_processed = meter
            .u64_observable_counter("txs_processed")
            .with_description(
                "Count the number of transactions processed successfully by the connector",
            )
            .init();
        let connector_txs_error = meter
            .u64_observable_counter("txs_error")
            .with_description(
                "Count the number of transactions not processed or with errors by the connector",
            )
            .init();
        let blockchain_submit_response_error = meter
            .u64_observable_counter("blockchain_submit_response_error")
            .with_description(
                "Count the number of transactions responses submitted to blockchain that failed",
            )
            .init();
        let blockchain_submit_response_success = meter
            .u64_observable_counter("blockchain_submit_response_success")
            .with_description(
                "Count the number of transactions responses submitted to blockchain that succeeded",
            )
            .init();
        let coordinator_success = meter
            .u64_observable_counter("coordinator_success")
            .with_description("Count the number of successful coordinator requests")
            .init();
        let coordinator_error = meter
            .u64_observable_counter("coordinator_error")
            .with_description("Count the number of failed coordinator requests")
            .init();
        let coordinator_response_success = meter
            .u64_observable_counter("coordinator_response_success")
            .with_description(
                "Count the number of successful coordinator responses (not including polling)",
            )
            .init();
        let coordinator_response_error = meter
            .u64_observable_counter("coordinator_error")
            .with_description(
                "Count the number of failed coordinator responses (not including polling)",
            )
            .init();
        let counters = vec![
            (MetricType::TxProcessed, connector_txs_processed),
            (MetricType::TxError, connector_txs_error),
            (
                MetricType::BlockchainSuccess,
                blockchain_submit_response_success,
            ),
            (
                MetricType::BlockchainError,
                blockchain_submit_response_error,
            ),
            (MetricType::CoordinatorSuccess, coordinator_success),
            (MetricType::CoordinatorError, coordinator_error),
            (
                MetricType::CoordinatorResponseSuccess,
                coordinator_response_success,
            ),
            (
                MetricType::CoordinatorResponseError,
                coordinator_response_error,
            ),
        ]
        .into_iter()
        .collect::<DashMap<MetricType, ObservableCounter<u64>>>();
        OpenTelemetryMetrics { counters }
    }
}

impl Metrics for OpenTelemetryMetrics {
    fn increment(&self, counter: MetricType, amount: u64, tags: &[(&str, &str)]) {
        if let Some(count) = self.counters.get_mut(&counter) {
            count.observe(
                amount,
                tags.iter()
                    .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                    .collect::<Vec<KeyValue>>()
                    .as_slice(),
            );
        } else {
            tracing::warn!("Counter {:?} not found", counter);
        }
    }
}
