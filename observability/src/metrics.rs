use crate::metrics_names::{
    TAG_OPERATION_TYPE, TAG_PARTY_ID, TAG_PUBLIC_DECRYPTION_KIND, TAG_TFHE_TYPE,
    TAG_USER_DECRYPTION_KIND,
};
use prometheus::{Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// Label keys for the duration histogram (must match all tag keys used by callers)
const DURATION_LABEL_KEYS: &[&str] = &[
    TAG_OPERATION_TYPE,
    TAG_PARTY_ID,
    TAG_TFHE_TYPE,
    TAG_PUBLIC_DECRYPTION_KIND,
    TAG_USER_DECRYPTION_KIND,
];

/// Buckets (ms) for `kms_operation_duration_ms`. Durations are recorded in whole milliseconds,
/// so sub-ms ops are observed as `0`; KMS ops can still range up to minutes. Prometheus' default
/// histogram buckets are tuned for seconds and would put most ms-valued observations in `+Inf`.
const DURATION_BUCKETS_MS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0, 30_000.0,
    60_000.0, 120_000.0, 300_000.0,
];

/// Buckets (bytes) for `kms_payload_size_bytes`, from small ciphertexts up to the
/// multi-GiB FHE key/keyset payloads written during keygen (top buckets 4/16/64 GiB).
const SIZE_BUCKETS_BYTES: &[f64] = &[
    1_024.0,
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
    16_777_216.0,
    67_108_864.0,
    268_435_456.0,
    1_073_741_824.0,
    4_294_967_296.0,
    17_179_869_184.0,
    68_719_476_736.0,
];

/// Core metrics for tracking KMS operations
#[derive(Debug, Clone)]
pub struct CoreMetrics {
    // Counters
    request_counter: IntCounterVec,
    error_counter: IntCounterVec,
    backup_error_counter: IntCounterVec, // Keeps track of errors when making a backup. These MUST be handled as it means some party may not have everything backed up properly
    network_rx_counter: IntCounter, // Note: Because we use counter we need to increment from last seen value.
    network_tx_counter: IntCounter, // Note: Because we use counter we need to increment from last seen value.

    // Histograms
    duration_histogram: HistogramVec,
    size_histogram: HistogramVec, // Serialized payload sizes; see `observe_size`

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

    // Static const-labels applied to every metric (from `KMS_METRICS_LABELS`), retained so they can
    // be inspected/logged at runtime. Empty by default.
    labels: BTreeMap<String, String>,

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

    /// Build metrics with `config`, registering them in the global default registry — the one the
    /// `/metrics` endpoint scrapes.
    pub fn with_config(config: MetricsConfig) -> Self {
        Self::with_config_in_registry(config, prometheus::default_registry())
    }

    /// Build metrics with `config`, registering every metric in `registry`. Production uses the
    /// process-global default registry via [`CoreMetrics::with_config`]; tests pass a fresh registry
    /// so a single instance can be inspected in isolation without colliding with that shared state.
    fn with_config_in_registry(mut config: MetricsConfig, registry: &prometheus::Registry) -> Self {
        let prefix = &config.prefix;

        // Apply the configured labels as const-labels to every metric, so the registration sites
        // below need no change. See `MetricsConfig::from_env`.
        filter_metrics_labels(&mut config.labels);
        let const_labels: HashMap<String, String> = config.labels.clone().into_iter().collect();
        let opts = |name: String, help: &'static str| {
            Opts::new(name, help).const_labels(const_labels.clone())
        };
        let hist_opts = |name: String, help: &'static str| {
            HistogramOpts::new(name, help).const_labels(const_labels.clone())
        };

        // Version gauge
        let version_gauge = Gauge::with_opts(
            opts("kms_version".to_string(), "KMS version information")
                .const_label("version", env!("CARGO_PKG_VERSION")),
        )
        .expect("failed to create version gauge");
        registry
            .register(Box::new(version_gauge.clone()))
            .expect("failed to register version gauge");
        version_gauge.set(1.0);

        // Counters
        let request_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_operations_total"),
                "Total number of operations processed",
            ),
            &["operation"],
        )
        .expect("failed to create request counter");
        registry
            .register(Box::new(request_counter.clone()))
            .expect("failed to register request counter");

        let error_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_operation_errors_total"),
                "Total number of operation errors",
            ),
            &["operation", "error"],
        )
        .expect("failed to create error counter");
        registry
            .register(Box::new(error_counter.clone()))
            .expect("failed to register error counter");

        let backup_error_counter = IntCounterVec::new(
            opts(
                format!("{prefix}_backup_errors_total"),
                "Total number of backup errors",
            ),
            &["operation", "error"],
        )
        .expect("failed to create backup error counter");
        registry
            .register(Box::new(backup_error_counter.clone()))
            .expect("failed to register backup error counter");

        let network_rx_counter = IntCounter::with_opts(opts(
            format!("{prefix}_network_rx_bytes_total"),
            "Total number of bytes received over the network",
        ))
        .expect("failed to create network rx counter");
        registry
            .register(Box::new(network_rx_counter.clone()))
            .expect("failed to register network rx counter");

        let network_tx_counter = IntCounter::with_opts(opts(
            format!("{prefix}_network_tx_bytes_total"),
            "Total number of bytes sent over the network",
        ))
        .expect("failed to create network tx counter");
        registry
            .register(Box::new(network_tx_counter.clone()))
            .expect("failed to register network tx counter");

        // Histograms
        let duration_histogram = HistogramVec::new(
            hist_opts(
                format!("{prefix}_operation_duration_ms"),
                "Duration of KMS operations",
            )
            .buckets(DURATION_BUCKETS_MS.to_vec()),
            DURATION_LABEL_KEYS,
        )
        .expect("failed to create duration histogram");
        registry
            .register(Box::new(duration_histogram.clone()))
            .expect("failed to register duration histogram");

        let size_histogram = HistogramVec::new(
            hist_opts(
                format!("{prefix}_payload_size_bytes"),
                "Size of KMS operation payloads",
            )
            .buckets(SIZE_BUCKETS_BYTES.to_vec()),
            &["operation"],
        )
        .expect("failed to create size histogram");
        registry
            .register(Box::new(size_histogram.clone()))
            .expect("failed to register size histogram");

        // IntGauge (u64) metrics
        let file_descriptor_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_file_descriptors"),
            "File descriptor usage for the KMS",
        ))
        .expect("failed to create file descriptor gauge");
        registry
            .register(Box::new(file_descriptor_gauge.clone()))
            .expect("failed to register file descriptor gauge");

        let socat_file_descriptor_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_socat_file_descriptors"),
            "Number of socat file descriptors",
        ))
        .expect("failed to create socat file descriptor gauge");
        registry
            .register(Box::new(socat_file_descriptor_gauge.clone()))
            .expect("failed to register socat file descriptor gauge");

        let socat_task_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_socat_tasks"),
            "Number of socat tasks",
        ))
        .expect("failed to create socat task gauge");
        registry
            .register(Box::new(socat_task_gauge.clone()))
            .expect("failed to register socat task gauge");

        let task_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_tasks"),
            "Number of tasks started by the KMS",
        ))
        .expect("failed to create task gauge");
        registry
            .register(Box::new(task_gauge.clone()))
            .expect("failed to register task gauge");

        let rate_limiter_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_rate_limiter_usage"),
            "Rate limiter usage for the KMS",
        ))
        .expect("failed to create rate limiter gauge");
        registry
            .register(Box::new(rate_limiter_gauge.clone()))
            .expect("failed to register rate limiter gauge");

        let active_session_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_active_sessions"),
            "Number of active sessions in the KMS",
        ))
        .expect("failed to create active session gauge");
        registry
            .register(Box::new(active_session_gauge.clone()))
            .expect("failed to register active session gauge");

        let inactive_session_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_inactive_sessions"),
            "Number of inactive sessions in the KMS",
        ))
        .expect("failed to create inactive session gauge");
        registry
            .register(Box::new(inactive_session_gauge.clone()))
            .expect("failed to register inactive session gauge");

        let meta_storage_user_dec_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_meta_storage_user_decryptions"),
            "Number of ONGOING user decryptions in meta storage",
        ))
        .expect("failed to create meta storage user dec gauge");
        registry
            .register(Box::new(meta_storage_user_dec_gauge.clone()))
            .expect("failed to register meta storage user dec gauge");

        let meta_storage_pub_dec_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_meta_storage_pub_decryptions"),
            "Number of ONGOING public decryptions in meta storage",
        ))
        .expect("failed to create meta storage pub dec gauge");
        registry
            .register(Box::new(meta_storage_pub_dec_gauge.clone()))
            .expect("failed to register meta storage pub dec gauge");

        let meta_storage_user_dec_total_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_meta_storage_user_decryptions_in_store"),
            "Total number of user decryptions in meta storage",
        ))
        .expect("failed to create meta storage user dec total gauge");
        registry
            .register(Box::new(meta_storage_user_dec_total_gauge.clone()))
            .expect("failed to register meta storage user dec total gauge");

        let meta_storage_pub_dec_total_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_meta_storage_pub_decryptions_in_store"),
            "Total number of public decryptions in meta storage",
        ))
        .expect("failed to create meta storage pub dec total gauge");
        registry
            .register(Box::new(meta_storage_pub_dec_total_gauge.clone()))
            .expect("failed to register meta storage pub dec total gauge");

        let total_cpus_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_total_cpus"),
            "Amount of CPU cores available to the system",
        ))
        .expect("failed to create total cpus gauge");
        registry
            .register(Box::new(total_cpus_gauge.clone()))
            .expect("failed to register total cpus gauge");

        let total_memory_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_total_memory"),
            "Amount of available memory in the system",
        ))
        .expect("failed to create total memory gauge");
        registry
            .register(Box::new(total_memory_gauge.clone()))
            .expect("failed to register total memory gauge");

        let process_memory_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_process_memory_usage"),
            "Memory usage for the current process",
        ))
        .expect("failed to create process memory gauge");
        registry
            .register(Box::new(process_memory_gauge.clone()))
            .expect("failed to register process memory gauge");

        let memory_usage_gauge = IntGauge::with_opts(opts(
            format!("{prefix}_memory_usage"),
            "Memory used for KMS",
        ))
        .expect("failed to create memory usage gauge");
        registry
            .register(Box::new(memory_usage_gauge.clone()))
            .expect("failed to register memory usage gauge");

        // Gauge (f64) metrics
        let process_cpu_usage_gauge = Gauge::with_opts(opts(
            format!("{prefix}_process_cpu_usage"),
            "CPU usage for the current process",
        ))
        .expect("failed to create process cpu usage gauge");
        registry
            .register(Box::new(process_cpu_usage_gauge.clone()))
            .expect("failed to register process cpu usage gauge");

        let cpu_load_gauge = Gauge::with_opts(opts(
            format!("{prefix}_cpu_load"),
            "CPU load for KMS (averaged over all CPUs)",
        ))
        .expect("failed to create cpu load gauge");
        registry
            .register(Box::new(cpu_load_gauge.clone()))
            .expect("failed to register cpu load gauge");

        Self {
            request_counter,
            error_counter,
            backup_error_counter,
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
            labels: config.labels,
            trace_guard: Arc::new(Mutex::new(None)),
        }
    }

    /// The static const-labels applied to every metric (from `KMS_METRICS_LABELS`); empty if none
    /// are configured. Reflects exactly what was attached to the metrics at construction.
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
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

    pub fn increment_backup_error_counter(
        &self,
        operation: impl AsRef<str>,
        error: impl AsRef<str>,
    ) {
        self.backup_error_counter
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

/// Env var holding static metric labels as `key=value,key=value`; see [`MetricsConfig::from_env`].
pub const METRICS_LABELS_ENV: &str = "KMS_METRICS_LABELS";

// Global metrics instance, built from the environment (see `MetricsConfig::from_env`).
pub static METRICS: LazyLock<CoreMetrics> =
    LazyLock::new(|| CoreMetrics::with_config(MetricsConfig::from_env()));

/// Configuration for metrics initialization
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub prefix: String,
    pub default_unit: Option<String>,
    /// Static const-labels added to every metric to distinguish deployments (e.g.
    /// `deployment_profile=kind-ci`); populated by [`MetricsConfig::from_env`], empty by default.
    pub labels: BTreeMap<String, String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prefix: "kms".to_string(),
            default_unit: None,
            labels: BTreeMap::new(),
        }
    }
}

impl MetricsConfig {
    /// Build config from the environment, reading [`METRICS_LABELS_ENV`] (`KMS_METRICS_LABELS`) as a
    /// `key=value,key=value` list of const-labels applied to every metric — e.g. to tag kind-CI
    /// metrics so a scraper can tell them from production. Malformed/invalidly-named entries are
    /// skipped with a warning; unset/empty means no labels.
    pub fn from_env() -> Self {
        Self {
            labels: parse_metrics_labels(std::env::var(METRICS_LABELS_ENV).ok().as_deref()),
            ..Self::default()
        }
    }
}

/// Parse a `key=value,key=value` label list. Empty, `=`-less, empty-key, invalidly-named, or
/// reserved/colliding entries (see [`is_reserved_label_name`]) are skipped with a warning — a bad
/// env var must not crash metric registration.
fn parse_metrics_labels(raw: Option<&str>) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let Some(raw) = raw else {
        return labels;
    };
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((key, value)) = entry.split_once('=') else {
            warn!(
                entry,
                "ignoring malformed metrics label (expected key=value)"
            );
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if !is_acceptable_label_key(key) {
            continue;
        }
        labels.insert(key.to_string(), value.to_string());
    }
    labels
}

/// Drop invalid or reserved keys from `labels` in place (warns on each rejection).
fn filter_metrics_labels(labels: &mut BTreeMap<String, String>) {
    labels.retain(|key, _| is_acceptable_label_key(key));
}

/// Returns whether `key` may be used as a configured const-label. Invalid or reserved names are
/// logged and rejected so metric registration cannot panic.
fn is_acceptable_label_key(key: &str) -> bool {
    if !is_valid_label_name(key) {
        warn!(key, "ignoring metrics label with invalid label name");
        return false;
    }
    if is_reserved_label_name(key) {
        warn!(
            key,
            "ignoring metrics label that collides with a built-in metric label name"
        );
        return false;
    }
    true
}

/// Returns whether `name` is a valid, non-reserved Prometheus label name. Valid names match
/// `[a-zA-Z_][a-zA-Z0-9_]*`; names beginning with `__` are reserved by Prometheus for internal use
/// and are rejected so a configured label can never shadow them.
fn is_valid_label_name(name: &str) -> bool {
    if name.starts_with("__") {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Label names already used by built-in metrics, as variable labels (`operation`/`error`, the
/// duration tags in [`DURATION_LABEL_KEYS`]) or const-labels (`version` on the version gauge), plus
/// `le` — the bucket-boundary label Prometheus attaches to histogram series. A configured
/// const-label colliding with one of these makes Prometheus reject the metric at registration —
/// which would panic the process — so such entries are skipped instead. (`le` specifically is
/// rejected by the `prometheus` crate when building either histogram, panicking the `.expect(...)`.)
fn is_reserved_label_name(name: &str) -> bool {
    const EXTRA_RESERVED: &[&str] = &["operation", "error", "version", "le"];
    DURATION_LABEL_KEYS.contains(&name) || EXTRA_RESERVED.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn metric_families_match_allowlist() {
        // Touch the LazyLock to ensure metrics are registered
        let _ = &*METRICS;

        // Seed Vec-type metrics so they appear in gather()
        METRICS.increment_request_counter("_test");
        METRICS.increment_error_counter("_test", "_test");
        METRICS.increment_backup_error_counter("_test", "_test");
        METRICS.observe_duration("_test", Duration::from_millis(0));
        METRICS.observe_size("_test", 1.0);

        let families = prometheus::gather();
        let mut names: Vec<&str> = families.iter().map(|f| f.name()).collect();
        names.sort();

        // Exhaustive allowlist — update this when adding/removing metrics
        #[allow(unused_mut)]
        let mut expected_metrics = vec![
            "kms_active_sessions",
            "kms_backup_errors_total",
            "kms_cpu_load",
            "kms_file_descriptors",
            "kms_inactive_sessions",
            "kms_memory_usage",
            "kms_meta_storage_pub_decryptions",
            "kms_meta_storage_pub_decryptions_in_store",
            "kms_meta_storage_user_decryptions",
            "kms_meta_storage_user_decryptions_in_store",
            "kms_network_rx_bytes_total",
            "kms_network_tx_bytes_total",
            "kms_operation_duration_ms",
            "kms_operation_errors_total",
            "kms_operations_total",
            "kms_payload_size_bytes",
            "kms_process_cpu_usage",
            "kms_process_memory_usage",
            "kms_rate_limiter_usage",
            "kms_socat_file_descriptors",
            "kms_socat_tasks",
            "kms_tasks",
            "kms_total_cpus",
            "kms_total_memory",
            "kms_version",
        ];
        // process_* metrics come from the prometheus crate's `process` feature (linux only),
        #[cfg(target_os = "linux")]
        expected_metrics.extend_from_slice(&[
            "process_cpu_seconds_total",
            "process_max_fds",
            "process_open_fds",
            "process_resident_memory_bytes",
            "process_start_time_seconds",
            "process_threads",
            "process_virtual_memory_bytes",
        ]);

        assert_eq!(
            names, expected_metrics,
            "Metric families changed. If intentional, update the allowlist in this test."
        );
    }

    #[test]
    fn duration_histogram_uses_only_low_cardinality_labels() {
        let _ = &*METRICS;

        METRICS.observe_duration_with_tags(
            "_test_cardinality",
            Duration::from_millis(1),
            &[
                (TAG_PARTY_ID, "1".to_string()),
                (TAG_TFHE_TYPE, "fhe_uint8".to_string()),
                (TAG_PUBLIC_DECRYPTION_KIND, "test".to_string()),
            ],
        );

        let duration_family = prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "kms_operation_duration_ms")
            .expect("duration histogram should be registered");
        let observed_metric = duration_family
            .get_metric()
            .iter()
            .find(|metric| {
                metric.get_label().iter().any(|label| {
                    label.name() == TAG_OPERATION_TYPE && label.value() == "_test_cardinality"
                })
            })
            .expect("seeded duration sample should be present");

        let actual_labels: BTreeSet<&str> = observed_metric
            .get_label()
            .iter()
            .map(|label| label.name())
            .collect();
        let expected_labels: BTreeSet<&str> = DURATION_LABEL_KEYS.iter().copied().collect();

        // All declared label keys must be present; extra const-labels (from `KMS_METRICS_LABELS`)
        // are allowed — they are constant per process, not a cardinality risk.
        assert!(
            expected_labels.is_subset(&actual_labels),
            "duration histogram must keep all low-cardinality label keys; got {actual_labels:#?}"
        );

        println!("Actual labels: {actual_labels:#?}");

        for disallowed_label in ["key_id", "context_id", "epoch_id", "crs_id"] {
            assert!(
                !actual_labels.contains(disallowed_label),
                "high-cardinality label {disallowed_label} should not be exported"
            );
        }

        let configured: BTreeSet<&str> = METRICS.labels().keys().map(String::as_str).collect();
        for &key in &actual_labels {
            assert!(
                expected_labels.contains(key) || configured.contains(key),
                "unexpected label key {key} on duration histogram"
            );
        }
    }

    #[test]
    fn parse_metrics_labels_parses_valid_pairs() {
        let labels = parse_metrics_labels(Some(
            "deployment_profile=kind-ci, deployment_type=threshold",
        ));
        assert_eq!(
            labels.get("deployment_profile").map(String::as_str),
            Some("kind-ci")
        );
        assert_eq!(
            labels.get("deployment_type").map(String::as_str),
            Some("threshold")
        );
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn parse_metrics_labels_skips_malformed_and_empty() {
        assert!(parse_metrics_labels(None).is_empty());
        assert!(parse_metrics_labels(Some("")).is_empty());
        assert!(parse_metrics_labels(Some("   ")).is_empty());

        let labels = parse_metrics_labels(Some("noequals,=novalue,1bad=x,good=ok,,"));
        assert_eq!(labels.get("good").map(String::as_str), Some("ok"));
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn is_valid_label_name_accepts_and_rejects() {
        assert!(is_valid_label_name("deployment_profile"));
        assert!(is_valid_label_name("_private"));
        assert!(is_valid_label_name("a1_b2"));
        assert!(!is_valid_label_name(""));
        assert!(!is_valid_label_name("1leading_digit"));
        assert!(!is_valid_label_name("has-dash"));
        assert!(!is_valid_label_name("has.dot"));
        assert!(!is_valid_label_name("__reserved"));
    }

    #[test]
    fn reserved_label_names_are_detected() {
        assert!(is_reserved_label_name("operation"));
        assert!(is_reserved_label_name("error"));
        assert!(is_reserved_label_name("version"));
        assert!(is_reserved_label_name("le"));
        assert!(is_reserved_label_name(TAG_OPERATION_TYPE));
        assert!(!is_reserved_label_name("deployment_profile"));
    }

    #[test]
    fn parse_metrics_labels_skips_reserved_and_colliding_names() {
        let labels = parse_metrics_labels(Some(
            "operation=x,error=y,version=z,le=bucket,operation_type=w,__r=1,deployment_profile=kind-ci",
        ));
        assert_eq!(
            labels.get("deployment_profile").map(String::as_str),
            Some("kind-ci")
        );
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn from_env_uses_default_prefix_and_parses_labels_from_env() {
        let expected = parse_metrics_labels(std::env::var(METRICS_LABELS_ENV).ok().as_deref());
        let config = MetricsConfig::from_env();
        assert_eq!(config.prefix, "kms");
        assert_eq!(config.labels, expected);
    }

    #[test]
    fn with_config_filters_invalid_and_reserved_labels() {
        let mut config = MetricsConfig::default();
        config
            .labels
            .insert("deployment_profile".to_string(), "kind-ci".to_string());
        config.labels.insert("le".to_string(), "bucket".to_string());
        config
            .labels
            .insert("operation".to_string(), "x".to_string());
        config
            .labels
            .insert("__reserved".to_string(), "1".to_string());
        config.labels.insert("1bad".to_string(), "x".to_string());

        let registry = prometheus::Registry::new();
        let metrics = CoreMetrics::with_config_in_registry(config, &registry);

        assert_eq!(metrics.labels().len(), 1);
        assert_eq!(
            metrics
                .labels()
                .get("deployment_profile")
                .map(String::as_str),
            Some("kind-ci")
        );
    }

    #[test]
    fn config_labels_are_attached_to_every_metric() {
        let mut config = MetricsConfig::default();
        config
            .labels
            .insert("deployment_profile".to_string(), "kind-ci".to_string());
        let registry = prometheus::Registry::new();
        let metrics = CoreMetrics::with_config_in_registry(config, &registry);

        assert_eq!(
            metrics
                .labels()
                .get("deployment_profile")
                .map(String::as_str),
            Some("kind-ci")
        );

        let families = registry.gather();
        let version = families
            .iter()
            .find(|f| f.name() == "kms_version")
            .and_then(|f| f.get_metric().first())
            .expect("kms_version should be registered");
        assert!(
            version
                .get_label()
                .iter()
                .any(|l| l.name() == "deployment_profile" && l.value() == "kind-ci"),
            "configured const-label should appear on every exported metric"
        );
    }
}
