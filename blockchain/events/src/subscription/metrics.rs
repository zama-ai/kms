use opentelemetry::metrics::Counter;
use opentelemetry::{global, KeyValue};

pub trait Metrics: Send + Sync {
    fn increment_tx_processed(&self, amount: u64, tags: &[(&str, &str)]);
    fn increment_tx_error(&self, amount: u64, tags: &[(&str, &str)]);
    fn increment_connection_errors(&self, amount: u64, tags: &[(&str, &str)]);
}

pub struct OpenTelemetryMetrics {
    txs_processed: Counter<u64>,
    txs_error: Counter<u64>,
    connection_error: Counter<u64>,
}

impl OpenTelemetryMetrics {
    pub(crate) fn new() -> Self {
        let meter = global::meter("events");
        let txs_processed = meter
            .u64_counter("txs_processed")
            .with_description(
                "Count the number of transactions processed successfully by the synchronizer",
            )
            .build();

        let txs_error = meter
            .u64_counter("txs_error")
            .with_description(
                "Count the number of transactions not processed or with errors by the synchronizer",
            )
            .build();

        let connection_error = meter
            .u64_counter("connection_error")
            .with_description("Connection errors against validator service")
            .build();

        OpenTelemetryMetrics {
            txs_processed,
            txs_error,
            connection_error,
        }
    }
}

impl Metrics for OpenTelemetryMetrics {
    fn increment_tx_processed(&self, amount: u64, tags: &[(&str, &str)]) {
        self.txs_processed.add(
            amount,
            tags.iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect::<Vec<KeyValue>>()
                .as_slice(),
        );
    }

    fn increment_tx_error(&self, amount: u64, tags: &[(&str, &str)]) {
        self.txs_error.add(
            amount,
            tags.iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect::<Vec<KeyValue>>()
                .as_slice(),
        );
    }

    fn increment_connection_errors(&self, amount: u64, tags: &[(&str, &str)]) {
        self.connection_error.add(
            amount,
            tags.iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect::<Vec<KeyValue>>()
                .as_slice(),
        );
    }
}
