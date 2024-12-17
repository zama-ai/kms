use dashmap::DashMap;
use opentelemetry::metrics::Counter;
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
    CoreSuccess,
    CoreError,
    CoreResponseSuccess,
    CoreResponseError,
    OracleSuccess,
    OracleError,
}

#[derive(Clone, Default)]
pub struct OpenTelemetryMetrics {
    counters: DashMap<MetricType, Counter<u64>>,
}

impl OpenTelemetryMetrics {
    pub fn new() -> Self {
        let meter = global::meter("kms_connector");
        let connector_txs_processed = meter
            .u64_counter("txs_processed")
            .with_description(
                "Count the number of transactions processed successfully by the connector",
            )
            .build();
        let connector_txs_error = meter
            .u64_counter("txs_error")
            .with_description(
                "Count the number of transactions not processed or with errors by the connector",
            )
            .build();
        let blockchain_submit_response_error = meter
            .u64_counter("blockchain_submit_response_error")
            .with_description(
                "Count the number of transactions responses submitted to blockchain that failed",
            )
            .build();
        let blockchain_submit_response_success = meter
            .u64_counter("blockchain_submit_response_success")
            .with_description(
                "Count the number of transactions responses submitted to blockchain that succeeded",
            )
            .build();
        let core_success = meter
            .u64_counter("core_success")
            .with_description("Count the number of successful core requests")
            .build();
        let core_error = meter
            .u64_counter("core_error")
            .with_description("Count the number of failed core requests")
            .build();
        let core_response_success = meter
            .u64_counter("core_response_success")
            .with_description(
                "Count the number of successful core responses (not including polling)",
            )
            .build();
        let core_response_error = meter
            .u64_counter("core_response_error")
            .with_description("Count the number of failed core responses (not including polling)")
            .build();
        let oracle_success = meter
            .u64_counter("oracle_success")
            .with_description("Count the number of successful oracle requests")
            .build();
        let oracle_error = meter
            .u64_counter("oracle_error")
            .with_description("Count the number of failed oracle requests")
            .build();
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
            (MetricType::CoreSuccess, core_success),
            (MetricType::CoreError, core_error),
            (MetricType::CoreResponseSuccess, core_response_success),
            (MetricType::CoreResponseError, core_response_error),
            (MetricType::OracleSuccess, oracle_success),
            (MetricType::OracleError, oracle_error),
        ]
        .into_iter()
        .collect::<DashMap<MetricType, Counter<u64>>>();
        OpenTelemetryMetrics { counters }
    }
}

impl Metrics for OpenTelemetryMetrics {
    fn increment(&self, counter: MetricType, amount: u64, tags: &[(&str, &str)]) {
        if let Some(count) = self.counters.get_mut(&counter) {
            count.add(
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
