use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Type-safe wrapper for metric tags
#[derive(Debug, Clone)]
pub struct MetricTag {
    key: &'static str,
    value: String,
}

impl MetricTag {
    pub fn new(key: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        if key.is_empty() || value.is_empty() {
            tracing::warn!("Tag key or value is empty {key}:{value}");
        }
        Self { key, value }
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
    fn new(metric: T) -> Self {
        Self {
            metric,
            default_tags: vec![],
        }
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
    file_descriptor_gauge: TaggedMetric<Gauge<u64>>,
    socat_processes_gauge: TaggedMetric<Gauge<u64>>,
    thread_gauge: TaggedMetric<Gauge<u64>>,
    // Internal system gauges
    // TODO rate limiter, session gause and meta store should actually be counters but we need to add decorators to ensure it is always updated
    rate_limiter_gauge: TaggedMetric<Gauge<u64>>,
    meta_storage_pub_dec_gauge: TaggedMetric<Gauge<u64>>, // Number of ongoing public decryptions in meta storage
    meta_storage_user_dec_gauge: TaggedMetric<Gauge<u64>>, // Number of ongoing user decryptions in meta storage
    // Trace guard for file-based logging
    trace_guard: Arc<Mutex<Option<Box<dyn std::any::Any + Send + Sync>>>>,
}

impl Default for CoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreMetrics {
    pub fn new() -> Self {
        Self::with_config(MetricsConfig::default())
    }

    pub fn with_config(config: MetricsConfig) -> Self {
        let meter = global::meter("kms");

        // Start by recording the version
        meter
            .u64_gauge("kms_version")
            .with_description("KMS version information")
            .with_unit("version")
            .build()
            .record(1, &[KeyValue::new("version", env!("CARGO_PKG_VERSION"))]);

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
        let file_descriptors_metric: Cow<'static, str> =
            format!("{}_file_descriptors", config.prefix).into();
        let socat_processes_metric: Cow<'static, str> =
            format!("{}_socat_processes", config.prefix).into();
        let thread_metric: Cow<'static, str> = format!("{}_threads", config.prefix).into();
        let rate_limiter_metric: Cow<'static, str> =
            format!("{}_rate_limiter_usage", config.prefix).into();
        let session_metric: Cow<'static, str> = format!("{}_live_sessions", config.prefix).into();
        let meta_store_user_metric: Cow<'static, str> =
            format!("{}_meta_storage_user_decryptions", config.prefix).into();
        let meta_store_pub_metric: Cow<'static, str> =
            format!("{}_meta_storage_pub_decryptions", config.prefix).into();
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

        let file_descriptor_gauge = meter
            .u64_gauge(file_descriptors_metric)
            .with_description("File descriptor usage for the KMS")
            .with_unit("file_descriptors")
            .build();
        //Record 0 just to make sure the histogram is exported
        file_descriptor_gauge.record(0, &[]);

        let socat_processes_gauge = meter
            .u64_gauge(socat_processes_metric)
            .with_description("Number of socat file descriptors")
            .with_unit("processes")
            .build();
        //Record 0 just to make sure the histogram is exported
        socat_processes_gauge.record(0, &[]);

        let thread_gauge = meter
            .u64_gauge(thread_metric)
            .with_description("Number of threads used by the KMS")
            .with_unit("threads")
            .build();
        //Record 0 just to make sure the gauge is exported
        thread_gauge.record(0, &[]);

        let rate_limiter_gauge = meter
            .u64_gauge(rate_limiter_metric)
            .with_description("Rate limiter usage for the KMS")
            .with_unit("requests")
            .build();
        //Record 0 just to make sure the gauge is exported
        rate_limiter_gauge.record(0, &[]);

        let session_gauge = meter
            .u64_gauge(session_metric)
            .with_description("Number of live sessions in the KMS")
            .with_unit("sessions")
            .build();
        //Record 0 just to make sure the gauge is exported
        session_gauge.record(0, &[]);

        let meta_storage_user_dec_gauge = meter
            .u64_gauge(meta_store_user_metric)
            .with_description("Number of ONGOING user decryptions in meta storage")
            .with_unit("user decryptions")
            .build();
        //Record 0 just to make sure the gauge is exported
        meta_storage_user_dec_gauge.record(0, &[]);

        let meta_storage_pub_dec_gauge = meter
            .u64_gauge(meta_store_pub_metric)
            .with_description("Number of ONGOING public decryptions in meta storage")
            .with_unit("public decryptions")
            .build();
        //Record 0 just to make sure the gauge is exported
        meta_storage_pub_dec_gauge.record(0, &[]);

        let gauge = meter
            .i64_gauge(gauge)
            .with_description("An instrument that records independent values")
            .with_unit("value")
            .build();
        //Record 0 just to make sure the gauge is exported
        gauge.record(0, &[]);

        Self {
            request_counter: TaggedMetric::new(request_counter),
            error_counter: TaggedMetric::new(error_counter),
            network_rx_counter: TaggedMetric::new(network_rx_counter),
            network_tx_counter: TaggedMetric::new(network_tx_counter),
            duration_histogram: TaggedMetric::new(duration_histogram),
            size_histogram: TaggedMetric::new(size_histogram),
            cpu_load_gauge: TaggedMetric::new(cpu_gauge),
            memory_usage_gauge: TaggedMetric::new(memory_gauge),
            file_descriptor_gauge: TaggedMetric::new(file_descriptor_gauge),
            socat_processes_gauge: TaggedMetric::new(socat_processes_gauge),
            thread_gauge: TaggedMetric::new(thread_gauge),
            rate_limiter_gauge: TaggedMetric::new(rate_limiter_gauge),
            meta_storage_pub_dec_gauge: TaggedMetric::new(meta_storage_pub_dec_gauge),
            meta_storage_user_dec_gauge: TaggedMetric::new(meta_storage_user_dec_gauge),
            gauge: TaggedMetric::new(gauge),
            trace_guard: Arc::new(Mutex::new(None)),
        }
    }

    /// Set the trace guard to keep the file handle open
    pub fn set_trace_guard(&self, guard: Box<dyn std::any::Any + Send + Sync>) {
        if let Ok(mut trace_guard) = self.trace_guard.lock() {
            *trace_guard = Some(guard);
        }
    }

    fn create_operation_tag(operation: impl Into<String>) -> MetricTag {
        MetricTag::new("operation", operation)
    }

    // Counter methods
    pub fn increment_request_counter(&self, operation: impl Into<String>) {
        let tags = vec![Self::create_operation_tag(operation)];
        self.request_counter
            .metric
            .add(1, &self.request_counter.with_tags(&tags));
    }

    pub fn increment_error_counter(&self, operation: impl Into<String>, error: impl Into<String>) {
        let mut tags = vec![Self::create_operation_tag(operation)];
        tags.push(MetricTag::new("error", error));
        self.error_counter
            .metric
            .add(1, &self.error_counter.with_tags(&tags));
    }

    pub fn increment_network_rx_counter(&self, bytes: u64) {
        self.network_rx_counter
            .metric
            .add(bytes, &self.network_rx_counter.with_tags(&[]));
    }

    pub fn increment_network_tx_counter(&self, bytes: u64) {
        self.network_tx_counter
            .metric
            .add(bytes, &self.network_tx_counter.with_tags(&[]));
    }

    // Histogram methods
    fn record_duration_with_tags(
        &self,
        operation: impl AsRef<str>,
        duration: Duration,
        extra_tags: &[(&'static str, String)],
    ) {
        let mut tags = vec![Self::create_operation_tag(operation.as_ref())];
        for (key, value) in extra_tags {
            tags.push(MetricTag::new(key, value));
        }

        self.duration_histogram.metric.record(
            duration.as_millis() as f64,
            &self.duration_histogram.with_tags(&tags),
        );
    }

    pub fn observe_duration(&self, operation: impl AsRef<str>, duration: Duration) {
        self.record_duration_with_tags(operation, duration, &[])
    }

    pub fn observe_duration_with_tags(
        &self,
        operation: impl AsRef<str>,
        duration: Duration,
        tags: &[(&'static str, String)],
    ) {
        self.record_duration_with_tags(operation, duration, tags)
    }

    pub fn observe_size(&self, operation: impl Into<String>, size: f64) {
        let tags = vec![Self::create_operation_tag(operation)];
        self.size_histogram
            .metric
            .record(size, &self.size_histogram.with_tags(&tags));
    }

    // Gauge methods
    pub fn gauge(&self, operation: impl Into<String>, value: i64) {
        let tags = vec![Self::create_operation_tag(operation)];
        self.gauge
            .metric
            .record(value, &self.gauge.with_tags(&tags));
    }

    /// Start building a duration guard for timing an operation
    pub fn time_operation(&self, operation: impl Into<String>) -> DurationGuardBuilder<'_> {
        DurationGuardBuilder {
            metrics: self,
            operation: operation.into(),
            tags: Vec::new(),
        }
    }

    /// Record the current CPU load into the gauge
    pub fn record_cpu_load(&self, load: f64) {
        self.cpu_load_gauge
            .metric
            .record(load, &self.cpu_load_gauge.with_tags(&[]));
    }

    /// Record the current memory usage into the gauge
    pub fn record_memory_usage(&self, usage: u64) {
        self.memory_usage_gauge
            .metric
            .record(usage, &self.memory_usage_gauge.with_tags(&[]));
    }

    pub fn record_threads(&self, count: u64) {
        self.thread_gauge
            .metric
            .record(count, &self.thread_gauge.with_tags(&[]));
    }

    pub fn record_open_file_descriptors(&self, count: u64) {
        self.file_descriptor_gauge
            .metric
            .record(count, &self.file_descriptor_gauge.with_tags(&[]));
    }

    pub fn record_socat_processes(&self, count: u64) {
        self.socat_processes_gauge
            .metric
            .record(count, &self.socat_processes_gauge.with_tags(&[]));
    }

    pub fn record_rate_limiter_usage(&self, count: u64) {
        self.rate_limiter_gauge
            .metric
            .record(count, &self.rate_limiter_gauge.with_tags(&[]));
    }

    pub fn record_meta_storage_user_decryptions(&self, count: u64) {
        self.meta_storage_user_dec_gauge
            .metric
            .record(count, &self.meta_storage_user_dec_gauge.with_tags(&[]));
    }

    pub fn record_meta_storage_public_decryptions(&self, count: u64) {
        self.meta_storage_pub_dec_gauge
            .metric
            .record(count, &self.meta_storage_pub_dec_gauge.with_tags(&[]));
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
    pub fn tag(mut self, key: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        // Validate tag before adding
        MetricTag::new(key, value.clone());
        self.tags.push((key, value));
        self
    }

    /// Add multiple tags at once
    pub fn tags(mut self, tags: impl IntoIterator<Item = (&'static str, String)>) -> Self {
        for (key, value) in tags {
            // Validate each tag before adding
            MetricTag::new(key, value.clone());
            self.tags.push((key, value));
        }
        self
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
            .record_duration_with_tags(&self.operation, duration, &self.tags);
        self.record_on_drop = false;
        duration
    }

    /// Add a single tag
    pub fn tag(&mut self, key: &'static str, value: impl Into<String>) {
        let value = value.into();
        // Validate tag before adding
        MetricTag::new(key, value.clone());
        self.tags.push((key, value));
    }

    /// Add multiple tags at once
    pub fn tags(&mut self, tags: impl IntoIterator<Item = (&'static str, String)>) {
        for (key, value) in tags {
            // Validate each tag before adding
            MetricTag::new(key, value.clone());
            self.tags.push((key, value));
        }
    }
}

impl Drop for DurationGuard<'_> {
    fn drop(&mut self) {
        if self.record_on_drop {
            self.metrics.record_duration_with_tags(
                &self.operation,
                self.start.elapsed(),
                &self.tags,
            );
        }
    }
}

// Global metrics instance
lazy_static::lazy_static! {
    pub static ref METRICS: CoreMetrics = {
        CoreMetrics::new()
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
