use std::sync::Arc;

use opentelemetry::metrics::ObservableCounter;
use opentelemetry::{global, KeyValue};

pub trait Metrics: Send + Sync {
    fn increment_tx_processed(&self, amount: u64, tags: &[(&str, &str)]);
    fn increment_tx_error(&self, amount: u64, tags: &[(&str, &str)]);
    fn increment_connection_errors(&self, amount: u64, tags: &[(&str, &str)]);
}

pub struct OpenTelemetryMetrics {
    txs_processed: ObservableCounter<u64>,
    txs_error: ObservableCounter<u64>,
    connection_error: ObservableCounter<u64>,
}

impl OpenTelemetryMetrics {
    pub(crate) fn new() -> Self {
        let meter = global::meter("events");
        let txs_processed = meter
            .u64_observable_counter("txs_processed")
            .with_description(
                "Count the number of transactions processed successfully by the synchronizer",
            )
            .init();
        let txs_error = meter
            .u64_observable_counter("txs_error")
            .with_description(
                "Count the number of transactions not processed or with errors by the synchronizer",
            )
            .init();
        let connection_error = meter
            .u64_observable_counter("connection_error")
            .with_description("Connection errors agains validator service")
            .init();
        OpenTelemetryMetrics {
            txs_processed,
            txs_error,
            connection_error,
        }
    }
}

impl Metrics for OpenTelemetryMetrics {
    fn increment_tx_processed(&self, amount: u64, tags: &[(&str, &str)]) {
        self.txs_processed.observe(
            amount,
            tags.iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect::<Vec<KeyValue>>()
                .as_slice(),
        );
    }

    fn increment_tx_error(&self, amount: u64, tags: &[(&str, &str)]) {
        self.txs_error.observe(
            amount,
            tags.iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect::<Vec<KeyValue>>()
                .as_slice(),
        );
    }

    fn increment_connection_errors(&self, amount: u64, tags: &[(&str, &str)]) {
        self.connection_error.observe(
            amount,
            tags.iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect::<Vec<KeyValue>>()
                .as_slice(),
        );
    }
}

// Trivial implementation for the Arc version
impl<A> Metrics for Arc<A>
where
    A: Metrics,
{
    fn increment_tx_processed(&self, amount: u64, tags: &[(&str, &str)]) {
        (**self).increment_tx_processed(amount, tags);
    }
    fn increment_tx_error(&self, amount: u64, tags: &[(&str, &str)]) {
        (**self).increment_tx_error(amount, tags);
    }
    fn increment_connection_errors(&self, amount: u64, tags: &[(&str, &str)]) {
        (**self).increment_connection_errors(amount, tags);
    }
}
