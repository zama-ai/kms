use crate::metrics_names::{TAG_OPERATION_TYPE, TAG_PARTY_ID, TAG_TFHE_TYPE};
use prometheus::{Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// Label keys for the duration histogram (must match all tag keys used by callers)
const DURATION_LABEL_KEYS: &[&str] = &[TAG_OPERATION_TYPE, TAG_PARTY_ID, TAG_TFHE_TYPE];

/// Core metrics for tracking KMS operations
#[derive(Debug, Clone)]
pub struct CoreMetrics {
    // Counters
    request_counter: IntCounterVec,
    error_counter: IntCounterVec,
    network_rx_counter: IntCounter, // Note: Because we use counter we need to increment from last seen value.
    network_tx_counter: IntCounter, // Note: Because we use counter we need to increment from last seen value.

    // Histograms
    duration_histogram: HistogramVec,
    size_histogram: HistogramVec, // TODO currently not used

    // Gauges
    file_descriptor_gauge: IntGauge, // Number of file descriptors of the KMS
    socat_file_descriptor_gauge: IntGauge, // Number of socat file descriptors
    socat_task_gauge: IntGauge,      // Number of socat tasks
    task_gauge: IntGauge,            // Numbers active child processes of the KMS

    // Internal system gauges
    // TODO rate limiter, session gauge and meta store should actually be counters but we need to add decorators to ensure it is always updated
    rate_limiter_gauge: IntGauge, // Number tokens used in the rate limiter
    active_session_gauge: IntGauge, // Number of active sessions
    inactive_session_gauge: IntGauge, // Number of inactive sessions
    meta_storage_pub_dec_gauge: IntGauge, // Number of ongoing public decryptions in meta storage
    meta_storage_user_dec_gauge: IntGauge, // Number of ongoing user decryptions in meta storage
    meta_storage_pub_dec_total_gauge: IntGauge, // Total number of public decryptions in meta storage
    meta_storage_user_dec_total_gauge: IntGauge, // Total number of user decryptions in meta storage

    // System metrics
    total_cpus_gauge: IntGauge,     // Total number of CPUs
    process_cpu_usage_gauge: Gauge, // CPU load for the current process in percentage
    total_memory_gauge: IntGauge,   // Total memory available
    process_memory_gauge: IntGauge, // Memory usage for the current process
    cpu_load_gauge: Gauge,          // 1-minute average CPU load, divided by number of cores
    memory_usage_gauge: IntGauge,

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
        let prefix = &config.prefix;

        // Version gauge
        let version_gauge = Gauge::with_opts(
            Opts::new("kms_version", "KMS version information")
                .const_label("version", env!("CARGO_PKG_VERSION")),
        )
        .expect("failed to create version gauge");
        prometheus::register(Box::new(version_gauge.clone()))
            .expect("failed to register version gauge");
        version_gauge.set(1.0);

        // Counters
        let request_counter = IntCounterVec::new(
            Opts::new(
                format!("{prefix}_operations_total"),
                "Total number of operations processed",
            ),
            &["operation"],
        )
        .expect("failed to create request counter");
        prometheus::register(Box::new(request_counter.clone()))
            .expect("failed to register request counter");

        let error_counter = IntCounterVec::new(
            Opts::new(
                format!("{prefix}_operation_errors_total"),
                "Total number of operation errors",
            ),
            &["operation", "error"],
        )
        .expect("failed to create error counter");
        prometheus::register(Box::new(error_counter.clone()))
            .expect("failed to register error counter");

        let network_rx_counter = IntCounter::with_opts(Opts::new(
            format!("{prefix}_network_rx_bytes_total"),
            "Total number of bytes received over the network",
        ))
        .expect("failed to create network rx counter");
        prometheus::register(Box::new(network_rx_counter.clone()))
            .expect("failed to register network rx counter");

        let network_tx_counter = IntCounter::with_opts(Opts::new(
            format!("{prefix}_network_tx_bytes_total"),
            "Total number of bytes sent over the network",
        ))
        .expect("failed to create network tx counter");
        prometheus::register(Box::new(network_tx_counter.clone()))
            .expect("failed to register network tx counter");

        // Histograms
        let duration_histogram = HistogramVec::new(
            HistogramOpts::new(
                format!("{prefix}_operation_duration_ms"),
                "Duration of KMS operations",
            ),
            DURATION_LABEL_KEYS,
        )
        .expect("failed to create duration histogram");
        prometheus::register(Box::new(duration_histogram.clone()))
            .expect("failed to register duration histogram");

        let size_histogram = HistogramVec::new(
            HistogramOpts::new(
                format!("{prefix}_payload_size_bytes"),
                "Size of KMS operation payloads",
            ),
            &["operation"],
        )
        .expect("failed to create size histogram");
        prometheus::register(Box::new(size_histogram.clone()))
            .expect("failed to register size histogram");

        // IntGauge (u64) metrics
        let file_descriptor_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_file_descriptors"),
            "File descriptor usage for the KMS",
        ))
        .expect("failed to create file descriptor gauge");
        prometheus::register(Box::new(file_descriptor_gauge.clone()))
            .expect("failed to register file descriptor gauge");

        let socat_file_descriptor_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_socat_file_descriptors"),
            "Number of socat file descriptors",
        ))
        .expect("failed to create socat file descriptor gauge");
        prometheus::register(Box::new(socat_file_descriptor_gauge.clone()))
            .expect("failed to register socat file descriptor gauge");

        let socat_task_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_socat_tasks"),
            "Number of socat tasks",
        ))
        .expect("failed to create socat task gauge");
        prometheus::register(Box::new(socat_task_gauge.clone()))
            .expect("failed to register socat task gauge");

        let task_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_tasks"),
            "Number of tasks started by the KMS",
        ))
        .expect("failed to create task gauge");
        prometheus::register(Box::new(task_gauge.clone())).expect("failed to register task gauge");

        let rate_limiter_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_rate_limiter_usage"),
            "Rate limiter usage for the KMS",
        ))
        .expect("failed to create rate limiter gauge");
        prometheus::register(Box::new(rate_limiter_gauge.clone()))
            .expect("failed to register rate limiter gauge");

        let active_session_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_active_sessions"),
            "Number of active sessions in the KMS",
        ))
        .expect("failed to create active session gauge");
        prometheus::register(Box::new(active_session_gauge.clone()))
            .expect("failed to register active session gauge");

        let inactive_session_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_inactive_sessions"),
            "Number of inactive sessions in the KMS",
        ))
        .expect("failed to create inactive session gauge");
        prometheus::register(Box::new(inactive_session_gauge.clone()))
            .expect("failed to register inactive session gauge");

        let meta_storage_user_dec_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_meta_storage_user_decryptions"),
            "Number of ONGOING user decryptions in meta storage",
        ))
        .expect("failed to create meta storage user dec gauge");
        prometheus::register(Box::new(meta_storage_user_dec_gauge.clone()))
            .expect("failed to register meta storage user dec gauge");

        let meta_storage_pub_dec_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_meta_storage_pub_decryptions"),
            "Number of ONGOING public decryptions in meta storage",
        ))
        .expect("failed to create meta storage pub dec gauge");
        prometheus::register(Box::new(meta_storage_pub_dec_gauge.clone()))
            .expect("failed to register meta storage pub dec gauge");

        let meta_storage_user_dec_total_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_meta_storage_user_decryptions_in_store"),
            "Total number of user decryptions in meta storage",
        ))
        .expect("failed to create meta storage user dec total gauge");
        prometheus::register(Box::new(meta_storage_user_dec_total_gauge.clone()))
            .expect("failed to register meta storage user dec total gauge");

        let meta_storage_pub_dec_total_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_meta_storage_pub_decryptions_in_store"),
            "Total number of public decryptions in meta storage",
        ))
        .expect("failed to create meta storage pub dec total gauge");
        prometheus::register(Box::new(meta_storage_pub_dec_total_gauge.clone()))
            .expect("failed to register meta storage pub dec total gauge");

        let total_cpus_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_total_cpus"),
            "Amount of CPU cores available to the system",
        ))
        .expect("failed to create total cpus gauge");
        prometheus::register(Box::new(total_cpus_gauge.clone()))
            .expect("failed to register total cpus gauge");

        let total_memory_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_total_memory"),
            "Amount of available memory in the system",
        ))
        .expect("failed to create total memory gauge");
        prometheus::register(Box::new(total_memory_gauge.clone()))
            .expect("failed to register total memory gauge");

        let process_memory_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_process_memory_usage"),
            "Memory usage for the current process",
        ))
        .expect("failed to create process memory gauge");
        prometheus::register(Box::new(process_memory_gauge.clone()))
            .expect("failed to register process memory gauge");

        let memory_usage_gauge = IntGauge::with_opts(Opts::new(
            format!("{prefix}_memory_usage"),
            "Memory used for KMS",
        ))
        .expect("failed to create memory usage gauge");
        prometheus::register(Box::new(memory_usage_gauge.clone()))
            .expect("failed to register memory usage gauge");

        // Gauge (f64) metrics
        let process_cpu_usage_gauge = Gauge::with_opts(Opts::new(
            format!("{prefix}_process_cpu_usage"),
            "CPU usage for the current process",
        ))
        .expect("failed to create process cpu usage gauge");
        prometheus::register(Box::new(process_cpu_usage_gauge.clone()))
            .expect("failed to register process cpu usage gauge");

        let cpu_load_gauge = Gauge::with_opts(Opts::new(
            format!("{prefix}_cpu_load"),
            "CPU load for KMS (averaged over all CPUs)",
        ))
        .expect("failed to create cpu load gauge");
        prometheus::register(Box::new(cpu_load_gauge.clone()))
            .expect("failed to register cpu load gauge");

        Self {
            request_counter,
            error_counter,
            network_rx_counter,
            network_tx_counter,
            duration_histogram,
            size_histogram,
            cpu_load_gauge,
            memory_usage_gauge,
            file_descriptor_gauge,
            socat_file_descriptor_gauge,
            socat_task_gauge,
            task_gauge,
            rate_limiter_gauge,
            active_session_gauge,
            inactive_session_gauge,
            meta_storage_pub_dec_gauge,
            meta_storage_user_dec_gauge,
            meta_storage_pub_dec_total_gauge,
            meta_storage_user_dec_total_gauge,
            total_cpus_gauge,
            total_memory_gauge,
            process_cpu_usage_gauge,
            process_memory_gauge,
            trace_guard: Arc::new(Mutex::new(None)),
        }
    }

    /// Set the trace guard to keep the file handle open
    pub fn set_trace_guard(&self, guard: Box<dyn std::any::Any + Send + Sync>) {
        if let Ok(mut trace_guard) = self.trace_guard.lock() {
            *trace_guard = Some(guard);
        }
    }

    // Counter methods
    pub fn increment_request_counter(&self, operation: impl AsRef<str>) {
        self.request_counter
            .with_label_values(&[operation.as_ref()])
            .inc();
    }

    pub fn increment_error_counter(&self, operation: impl AsRef<str>, error: impl AsRef<str>) {
        self.error_counter
            .with_label_values(&[operation.as_ref(), error.as_ref()])
            .inc();
    }

    pub fn increment_network_rx_counter(&self, bytes: u64) {
        self.network_rx_counter.inc_by(bytes);
    }

    pub fn increment_network_tx_counter(&self, bytes: u64) {
        self.network_tx_counter.inc_by(bytes);
    }

    // Histogram methods
    fn record_duration_with_tags(
        &self,
        operation: impl AsRef<str>,
        duration: Duration,
        extra_tags: &[(&'static str, String)],
    ) {
        let mut values: Vec<&str> = vec![""; DURATION_LABEL_KEYS.len()];
        values[0] = operation.as_ref();
        for (key, value) in extra_tags {
            if let Some(idx) = DURATION_LABEL_KEYS.iter().position(|k| k == key) {
                values[idx] = value;
            } else {
                warn!(key, "ignoring unknown duration metric tag key");
            }
        }
        self.duration_histogram
            .with_label_values(&values)
            .observe(duration.as_millis() as f64);
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

    pub fn observe_size(&self, operation: impl AsRef<str>, size: f64) {
        if size == 0.0 {
            return;
        }
        self.size_histogram
            .with_label_values(&[operation.as_ref()])
            .observe(size);
    }

    /// Start building a duration guard for timing an operation
    pub fn time_operation(&self, operation: impl Into<String>) -> DurationGuardBuilder<'_> {
        DurationGuardBuilder {
            metrics: self,
            operation: operation.into(),
            tags: Vec::new(),
        }
    }

    /// Record the current number of tasks into the gauge
    pub fn record_tasks(&self, count: u64) {
        // Should never be 0
        if count == 0 {
            return;
        }
        self.task_gauge.set(count as i64);
    }

    /// Record the current number of open file descriptors into the gauge
    pub fn record_open_file_descriptors(&self, count: u64) {
        // Should never be 0
        if count == 0 {
            return;
        }
        self.file_descriptor_gauge.set(count as i64);
    }

    /// Record the current number of socat file descriptors into the gauge
    pub fn record_socat_file_descriptors(&self, count: u64) {
        self.socat_file_descriptor_gauge.set(count as i64);
    }

    /// Record the current number of socat tasks into the gauge
    pub fn record_socat_tasks(&self, count: u64) {
        self.socat_task_gauge.set(count as i64);
    }

    /// Record the current rate limiter usage into the gauge
    pub fn record_rate_limiter_usage(&self, count: u64) {
        self.rate_limiter_gauge.set(count as i64);
    }

    /// Record the sum of active sessions done with other parties into the gauge
    pub fn record_active_sessions(&self, count: u64) {
        self.active_session_gauge.set(count as i64);
    }

    /// Record the sum of inactive sessions done with other parties into the gauge
    pub fn record_inactive_sessions(&self, count: u64) {
        self.inactive_session_gauge.set(count as i64);
    }

    /// Record the current number of ongoing public decryptions into the gauge
    pub fn record_meta_storage_user_decryptions(&self, count: u64) {
        self.meta_storage_user_dec_gauge.set(count as i64);
    }

    /// Record the current number of ongoing user decryptions into the gauge
    pub fn record_meta_storage_public_decryptions(&self, count: u64) {
        self.meta_storage_pub_dec_gauge.set(count as i64);
    }

    /// Record the total number of user decryptions in meta storage into the gauge
    pub fn record_meta_storage_user_decryptions_total(&self, count: u64) {
        // Should never be 0
        if count == 0 {
            return;
        }
        self.meta_storage_user_dec_total_gauge.set(count as i64);
    }

    /// Record the total number of public decryptions in meta storage into the gauge
    pub fn record_meta_storage_public_decryptions_total(&self, count: u64) {
        // Should never be 0
        if count == 0 {
            return;
        }
        self.meta_storage_pub_dec_total_gauge.set(count as i64);
    }

    /// Record the amount of CPU cores
    pub fn record_total_cpus(&self, amount: u64) {
        // Should never be 0
        if amount == 0 {
            return;
        }
        self.total_cpus_gauge.set(amount as i64);
    }

    /// Record the current CPU load into the gauge
    pub fn record_cpu_load(&self, load: f64) {
        self.cpu_load_gauge.set(load);
    }

    /// Record the total memory on the system
    pub fn record_total_memory(&self, memory: u64) {
        // Should never be 0
        if memory == 0 {
            return;
        }
        self.total_memory_gauge.set(memory as i64);
    }

    /// Record the current memory usage into the gauge
    pub fn record_memory_usage(&self, usage: u64) {
        self.memory_usage_gauge.set(usage as i64);
    }

    /// Record the current process CPU usage into the gauge
    pub fn record_process_cpu_usage(&self, usage: f64) {
        self.process_cpu_usage_gauge.set(usage);
    }

    /// Record the current process memory usage into the gauge
    pub fn record_process_memory_usage(&self, usage: u64) {
        if usage == 0 {
            return;
        }
        self.process_memory_gauge.set(usage as i64);
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
        self.tags.push((key, value.into()));
        self
    }

    /// Add multiple tags at once
    pub fn tags(mut self, tags: impl IntoIterator<Item = (&'static str, String)>) -> Self {
        for (key, value) in tags {
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
        self.tags.push((key, value.into()));
    }

    /// Add multiple tags at once
    pub fn tags(&mut self, tags: impl IntoIterator<Item = (&'static str, String)>) {
        for (key, value) in tags {
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
