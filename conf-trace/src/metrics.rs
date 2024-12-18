use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};
use std::borrow::Cow;
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
    // Histograms
    duration_histogram: TaggedMetric<Histogram<f64>>,
    size_histogram: TaggedMetric<Histogram<f64>>,
    // Gauges
    gauge: TaggedMetric<Gauge<i64>>,
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
        let gauge: Cow<'static, str> = format!("{}_gauge", config.prefix).into();

        let request_counter = meter
            .u64_counter(operations)
            .with_description("Total number of operations processed")
            .with_unit("operations")
            .build();

        let error_counter = meter
            .u64_counter(operation_errors)
            .with_description("Total number of operation errors")
            .with_unit("errors")
            .build();

        let duration_histogram = meter
            .f64_histogram(duration_metric)
            .with_description("Duration of KMS operations")
            .with_unit("milliseconds")
            .build();

        let size_histogram = meter
            .f64_histogram(size_metric)
            .with_description("Size of KMS operation payloads")
            .with_unit("bytes")
            .build();

        let gauge = meter
            .i64_gauge(gauge)
            .with_description("An instrument that records independent values")
            .with_unit("value")
            .build();

        Ok(Self {
            request_counter: TaggedMetric::new(request_counter, "operations")?,
            error_counter: TaggedMetric::new(error_counter, "errors")?,
            duration_histogram: TaggedMetric::new(duration_histogram, "duration")?,
            size_histogram: TaggedMetric::new(size_histogram, "size")?,
            gauge: TaggedMetric::new(gauge, "active_operations")?,
        })
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
