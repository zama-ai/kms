use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Error types for metrics operations
#[derive(Debug, Error)]
pub enum MetricError {
    #[error("Invalid tag: {0}")]
    InvalidTag(String),
    #[error("Failed to record metric: {0}")]
    RecordingFailed(String),
    #[error("Failed to initialize metric: {0}")]
    InitializationError(String),
}

/// Type-safe wrapper for metric tags
#[derive(Debug, Clone)]
pub struct MetricTag {
    key: &'static str,
    value: String,
}

impl MetricTag {
    pub fn new(key: &'static str, value: impl Into<String>) -> Result<Self, MetricError> {
        let value = value.into();
        if key.is_empty() {
            return Err(MetricError::InvalidTag("Tag key cannot be empty".into()));
        }
        if value.is_empty() {
            return Err(MetricError::InvalidTag("Tag value cannot be empty".into()));
        }
        Ok(Self { key, value })
    }

    fn into_key_value(self) -> KeyValue {
        KeyValue::new(self.key, self.value)
    }
}

/// Tagged metric wrapper that automatically handles labels
#[derive(Debug, Clone)]
pub struct TaggedMetric<T> {
    metric: T,
    default_tags: Vec<MetricTag>,
}

impl<T> TaggedMetric<T> {
    fn new(metric: T, name: &'static str) -> Result<Self, MetricError> {
        Ok(Self {
            metric,
            default_tags: vec![MetricTag::new("name", name)?],
        })
    }

    fn with_tags(&self, tags: &[MetricTag]) -> Vec<KeyValue> {
        self.default_tags
            .iter()
            .cloned()
            .chain(tags.iter().cloned())
            .map(|tag| tag.into_key_value())
            .collect()
    }
}

/// Core metrics for tracking KMS operations
#[derive(Debug, Clone)]
pub struct CoreMetrics {
    // Counters
    request_counter: TaggedMetric<Counter<u64>>,
    error_counter: TaggedMetric<Counter<u64>>,
    network_rx_counter: TaggedMetric<Counter<u64>>, //Note: Because we use counter we need to increment from last seen value.
    network_tx_counter: TaggedMetric<Counter<u64>>, //Note: Because we use counter we need to increment from last seen value.

    // Histograms
    duration_histogram: TaggedMetric<Histogram<f64>>,
    size_histogram: TaggedMetric<Histogram<f64>>,
    // Gauges
    gauge: TaggedMetric<Gauge<i64>>,
    cpu_load_gauge: TaggedMetric<Gauge<f64>>,
    memory_usage_gauge: TaggedMetric<Gauge<u64>>,
    // Trace guard for file-based logging
    trace_guard: Arc<Mutex<Option<Box<dyn std::any::Any + Send + Sync>>>>,
}

impl CoreMetrics {
    pub fn new() -> Result<Self, MetricError> {
        Self::with_config(MetricsConfig::default())
    }

    pub fn with_config(config: MetricsConfig) -> Result<Self, MetricError> {
        let meter = global::meter("kms");

        // Store metric names as static strings
        let operations: Cow<'static, str> = format!("{}_operations", config.prefix).into();
        let operation_errors: Cow<'static, str> =
            format!("{}_operation_errors", config.prefix).into();
        let duration_metric: Cow<'static, str> =
            format!("{}_operation_duration_ms", config.prefix).into();
        let size_metric: Cow<'static, str> = format!("{}_payload_size_bytes", config.prefix).into();
        let cpu_load_metric: Cow<'static, str> = format!("{}_cpu_load", config.prefix).into();
        let memory_usage_metric: Cow<'static, str> =
            format!("{}_memory_usage", config.prefix).into();
        let network_rx_metric: Cow<'static, str> =
            format!("{}_network_rx_bytes", config.prefix).into();
        let network_tx_metric: Cow<'static, str> =
            format!("{}_network_tx_bytes", config.prefix).into();
        let gauge: Cow<'static, str> = format!("{}_gauge", config.prefix).into();

        let request_counter = meter
            .u64_counter(operations)
            .with_description("Total number of operations processed")
            .with_unit("operations")
            .build();
        //Increment by 0 just to make sure the counter is exported
        request_counter.add(0, &[]);

        let error_counter = meter
            .u64_counter(operation_errors)
            .with_description("Total number of operation errors")
            .with_unit("errors")
            .build();
        //Increment by 0 just to make sure the counter is exported
        error_counter.add(0, &[]);

        let network_rx_counter = meter
            .u64_counter(network_rx_metric)
            .with_description("Total number of bytes received over the network")
            .with_unit("bytes")
            .build();
        //Increment by 0 just to make sure the counter is exported
        network_rx_counter.add(0, &[]);

        let network_tx_counter = meter
            .u64_counter(network_tx_metric)
            .with_description("Total number of bytes sent over the network")
            .with_unit("bytes")
            .build();
        //Increment by 0 just to make sure the counter is exported
        network_tx_counter.add(0, &[]);

        let duration_histogram = meter
            .f64_histogram(duration_metric)
            .with_description("Duration of KMS operations")
            .with_unit("milliseconds")
            .build();
        //Record 0 just to make sure the histogram is exported
        duration_histogram.record(0.0, &[]);

        let size_histogram = meter
            .f64_histogram(size_metric)
            .with_description("Size of KMS operation payloads")
            .with_unit("bytes")
            .build();
        //Record 0 just to make sure the histogram is exported
        size_histogram.record(0.0, &[]);

        let cpu_gauge = meter
            .f64_gauge(cpu_load_metric)
            .with_description("CPU load for KMS (averaged over all CPUs)")
            .with_unit("percentage")
            .build();
        //Record 0 just to make sure the histogram is exported
        cpu_gauge.record(0.0, &[]);

        let memory_gauge = meter
            .u64_gauge(memory_usage_metric)
            .with_description("Memory used for KMS")
            .with_unit("bytes")
            .build();
        //Record 0 just to make sure the histogram is exported
        memory_gauge.record(0, &[]);

        let gauge = meter
            .i64_gauge(gauge)
            .with_description("An instrument that records independent values")
            .with_unit("value")
            .build();
        //Record 0 just to make sure the gauge is exported
        gauge.record(0, &[]);

        Ok(Self {
            request_counter: TaggedMetric::new(request_counter, "operations")?,
            error_counter: TaggedMetric::new(error_counter, "errors")?,
            network_rx_counter: TaggedMetric::new(network_rx_counter, "network_rx")?,
            network_tx_counter: TaggedMetric::new(network_tx_counter, "network_tx")?,
            duration_histogram: TaggedMetric::new(duration_histogram, "duration")?,
            size_histogram: TaggedMetric::new(size_histogram, "size")?,
            cpu_load_gauge: TaggedMetric::new(cpu_gauge, "cpu_load")?,
            memory_usage_gauge: TaggedMetric::new(memory_gauge, "memory_usage")?,
            gauge: TaggedMetric::new(gauge, "active_operations")?,
            trace_guard: Arc::new(Mutex::new(None)),
        })
    }

    /// Set the trace guard to keep the file handle open
    pub fn set_trace_guard(&self, guard: Box<dyn std::any::Any + Send + Sync>) {
        if let Ok(mut trace_guard) = self.trace_guard.lock() {
            *trace_guard = Some(guard);
        }
    }

    fn create_operation_tag(operation: impl Into<String>) -> Result<MetricTag, MetricError> {
        MetricTag::new("operation", operation)
    }

    // Counter methods
    pub fn increment_request_counter(
        &self,
        operation: impl Into<String>,
    ) -> Result<(), MetricError> {
        let tags = vec![Self::create_operation_tag(operation)?];
        self.request_counter
            .metric
            .add(1, &self.request_counter.with_tags(&tags));
        Ok(())
    }

    pub fn increment_error_counter(
        &self,
        operation: impl Into<String>,
        error: impl Into<String>,
    ) -> Result<(), MetricError> {
        let mut tags = vec![Self::create_operation_tag(operation)?];
        tags.push(MetricTag::new("error", error)?);
        self.error_counter
            .metric
            .add(1, &self.error_counter.with_tags(&tags));
        Ok(())
    }

    pub fn increment_network_rx_counter(&self, bytes: u64) -> Result<(), MetricError> {
        self.network_rx_counter
            .metric
            .add(bytes, &self.network_rx_counter.with_tags(&[]));
        Ok(())
    }

    pub fn increment_network_tx_counter(&self, bytes: u64) -> Result<(), MetricError> {
        self.network_tx_counter
            .metric
            .add(bytes, &self.network_tx_counter.with_tags(&[]));
        Ok(())
    }

    // Histogram methods
    fn record_duration_with_tags(
        &self,
        operation: impl AsRef<str>,
        duration: Duration,
        extra_tags: &[(&'static str, String)],
    ) -> Result<(), MetricError> {
        let mut tags = vec![Self::create_operation_tag(operation.as_ref())?];
        for (key, value) in extra_tags {
            tags.push(MetricTag::new(key, value)?);
        }

        self.duration_histogram.metric.record(
            duration.as_millis() as f64,
            &self.duration_histogram.with_tags(&tags),
        );
        Ok(())
    }

    pub fn observe_duration(
        &self,
        operation: impl AsRef<str>,
        duration: Duration,
    ) -> Result<(), MetricError> {
        self.record_duration_with_tags(operation, duration, &[])
    }

    pub fn observe_duration_with_tags(
        &self,
        operation: impl AsRef<str>,
        duration: Duration,
        tags: &[(&'static str, String)],
    ) -> Result<(), MetricError> {
        self.record_duration_with_tags(operation, duration, tags)
    }

    pub fn observe_size(&self, operation: impl Into<String>, size: f64) -> Result<(), MetricError> {
        let tags = vec![Self::create_operation_tag(operation)?];
        self.size_histogram
            .metric
            .record(size, &self.size_histogram.with_tags(&tags));
        Ok(())
    }

    // Gauge methods
    pub fn gauge(&self, operation: impl Into<String>, value: i64) -> Result<(), MetricError> {
        let tags = vec![Self::create_operation_tag(operation)?];
        self.gauge
            .metric
            .record(value, &self.gauge.with_tags(&tags));
        Ok(())
    }

    /// Start building a duration guard for timing an operation
    pub fn time_operation(
        &self,
        operation: impl Into<String>,
    ) -> Result<DurationGuardBuilder<'_>, MetricError> {
        Ok(DurationGuardBuilder {
            metrics: self,
            operation: operation.into(),
            tags: Vec::new(),
        })
    }

    /// Record the current CPU load into the gauge
    pub fn record_cpu_load(&self, load: f64) -> Result<(), MetricError> {
        self.cpu_load_gauge
            .metric
            .record(load, &self.cpu_load_gauge.with_tags(&[]));
        Ok(())
    }

    /// Record the current memory usage into the gauge
    pub fn record_memory_usage(&self, usage: u64) -> Result<(), MetricError> {
        self.memory_usage_gauge
            .metric
            .record(usage, &self.memory_usage_gauge.with_tags(&[]));
        Ok(())
    }
}

/// Builder for DurationGuard to ensure proper initialization
#[derive(Debug)]
pub struct DurationGuardBuilder<'a> {
    metrics: &'a CoreMetrics,
    operation: String,
    tags: Vec<(&'static str, String)>,
}

impl<'a> DurationGuardBuilder<'a> {
    /// Add a single tag
    pub fn tag(mut self, key: &'static str, value: impl Into<String>) -> Result<Self, MetricError> {
        let value = value.into();
        // Validate tag before adding
        MetricTag::new(key, value.clone())?;
        self.tags.push((key, value));
        Ok(self)
    }

    /// Add multiple tags at once
    pub fn tags(
        mut self,
        tags: impl IntoIterator<Item = (&'static str, String)>,
    ) -> Result<Self, MetricError> {
        for (key, value) in tags {
            // Validate each tag before adding
            MetricTag::new(key, value.clone())?;
            self.tags.push((key, value));
        }
        Ok(self)
    }

    /// Start timing the operation
    pub fn start(self) -> DurationGuard<'a> {
        DurationGuard {
            metrics: self.metrics,
            operation: self.operation,
            tags: self.tags,
            start: Instant::now(),
            record_on_drop: true,
        }
    }
}

/// RAII guard that records operation duration when dropped
#[derive(Debug)]
pub struct DurationGuard<'a> {
    metrics: &'a CoreMetrics,
    operation: String,
    tags: Vec<(&'static str, String)>,
    start: Instant,
    record_on_drop: bool,
}

impl DurationGuard<'_> {
    /// Force recording of the current duration and consume the guard
    pub fn record_now(mut self) -> Duration {
        let duration = self.start.elapsed();
        self.metrics
            .record_duration_with_tags(&self.operation, duration, &self.tags)
            .unwrap();
        self.record_on_drop = false;
        duration
    }

    /// Add a single tag
    pub fn tag(&mut self, key: &'static str, value: impl Into<String>) -> Result<(), MetricError> {
        let value = value.into();
        // Validate tag before adding
        MetricTag::new(key, value.clone())?;
        self.tags.push((key, value));
        Ok(())
    }

    /// Add multiple tags at once
    pub fn tags(
        &mut self,
        tags: impl IntoIterator<Item = (&'static str, String)>,
    ) -> Result<(), MetricError> {
        for (key, value) in tags {
            // Validate each tag before adding
            MetricTag::new(key, value.clone())?;
            self.tags.push((key, value));
        }
        Ok(())
    }
}

impl Drop for DurationGuard<'_> {
    fn drop(&mut self) {
        if self.record_on_drop {
            self.metrics
                .record_duration_with_tags(&self.operation, self.start.elapsed(), &self.tags)
                .unwrap();
        }
    }
}

// Global metrics instance
lazy_static::lazy_static! {
    pub static ref METRICS: CoreMetrics = {
        CoreMetrics::new().unwrap()
    };
}

/// Configuration for metrics initialization
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub prefix: String,
    pub default_unit: Option<String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prefix: "kms".to_string(),
            default_unit: None,
        }
    }
}
