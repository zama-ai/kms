use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

// Default configuration constants
const TRACER_MAX_QUEUE_SIZE: usize = 8192;
const TRACER_MAX_EXPORT_BATCH_SIZE: usize = 2048;
const TRACER_MAX_CONCURRENT_EXPORTS: usize = 4;
const TRACER_DEFAULT_TIMEOUT_SECS: u64 = 5;
const TRACER_DEFAULT_INIT_TIMEOUT_SECS: u64 = 10;
const TRACER_DEFAULT_RETRY_COUNT: u32 = 3;
const TRACER_DEFAULT_SAMPLING_RATIO: u64 = 10;

lazy_static::lazy_static! {
    pub(crate) static ref ENVIRONMENT: ExecutionEnvironment = mode();
    static ref TRACER_SCHEDULED_DELAY: Duration = Duration::from_millis(500);
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, TypedBuilder, Eq)]
pub struct BatchConf {
    /// The maximum number of spans that can be queued before they are exported.
    /// Defaults to `telemetry::TRACER_MAX_QUEUE_SIZE`
    #[builder(default, setter(strip_option))]
    max_queue_size: Option<usize>,
    /// The maximum number of spans that can be exported in a single batch.
    /// Defaults to `telemetry::TRACER_MAX_EXPORT_BATCH_SIZE`
    #[builder(default, setter(strip_option))]
    max_export_batch_size: Option<usize>,

    /// The maximum number of concurrent exports that are allowed to happen at the same time.
    /// Defaults to `telemetry::TRACER_MAX_CONCURRENT_EXPORTS`
    #[builder(default, setter(strip_option))]
    max_concurrent_exports: Option<usize>,

    /// The delay between two consecutive exports.
    /// Defaults to `telemetry::TRACER_SCHEDULED_DELAY`
    #[builder(default, setter(strip_option))]
    scheduled_delay: Option<Duration>,

    /// Timeout for export operations
    #[builder(default, setter(strip_option))]
    export_timeout: Option<Duration>,

    /// Retry configuration for failed exports
    #[builder(default, setter(strip_option))]
    retry_config: Option<RetryConfig>,
}

impl BatchConf {
    /// Returns the max queue size.
    pub fn max_queue_size(&self) -> usize {
        self.max_queue_size.unwrap_or(TRACER_MAX_QUEUE_SIZE)
    }

    /// Returns the max export batch size.
    pub fn max_export_batch_size(&self) -> usize {
        self.max_export_batch_size
            .unwrap_or(TRACER_MAX_EXPORT_BATCH_SIZE)
    }

    /// Returns the max concurrent exports.
    pub fn max_concurrent_exports(&self) -> usize {
        self.max_concurrent_exports
            .unwrap_or(TRACER_MAX_CONCURRENT_EXPORTS)
    }

    /// Returns the scheduled delay.
    pub fn scheduled_delay(&self) -> Duration {
        self.scheduled_delay.unwrap_or(*TRACER_SCHEDULED_DELAY)
    }

    /// Returns the export timeout
    pub fn export_timeout(&self) -> Duration {
        self.export_timeout
            .unwrap_or_else(|| Duration::from_secs(TRACER_DEFAULT_TIMEOUT_SECS))
    }

    /// Returns the retry configuration
    pub fn retry_config(&self) -> Option<RetryConfig> {
        self.retry_config.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, TypedBuilder, PartialEq, Eq)]
pub struct Tracing {
    /// The service name. This is used to identify the service in the tracing system.
    /// It is recommended to use the same service name across all instances of the service.
    ///
    /// Service Name should contain the following pattern:
    ///
    /// ```text
    /// <service_name> := <alpha>_<service_name> | <alpha>
    /// <alpha> := [a-z]*
    /// ```
    #[builder(setter(into))]
    service_name: String,

    // All the following settings are optional.
    /// The endpoint of the tracing system. If it is not set, tracing will be redirected to stdout.
    #[builder(default, setter(strip_option))]
    endpoint: Option<String>,

    /// Port for exposing Prometheus metrics. Defaults to 9464 if not specified.
    #[builder(default, setter(strip_option))]
    metrics_port: Option<u16>,

    /// Batch configuration.
    /// If this is set, the tracing system will not batch the spans before exporting them.
    #[builder(default, setter(strip_option))]
    batch: Option<BatchConf>,

    /// If this is set, the tracing system will use json logs.
    #[builder(default, setter(strip_option))]
    json_logs: Option<bool>,

    /// Sampling configuration (0 - 100, where 100 means 100% sampling)
    #[builder(default, setter(strip_option))]
    sampling_ratio: Option<u64>,

    /// Initialization timeout in seconds
    #[builder(default, setter(strip_option))]
    init_timeout_secs: Option<u64>,

    /// Whether to enable async initialization
    #[builder(default, setter(strip_option))]
    async_init: Option<bool>,
}

impl Tracing {
    /// Returns the service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the endpoint.
    pub fn endpoint(&self) -> &Option<String> {
        &self.endpoint
    }

    /// Returns the batch configuration.
    pub fn batch(&self) -> &Option<BatchConf> {
        &self.batch
    }

    /// Returns the json configuration.
    pub fn json_logs(&self) -> &Option<bool> {
        &self.json_logs
    }

    /// Returns the sampling ratio (0 - 100)
    pub fn sampling_ratio(&self) -> u64 {
        self.sampling_ratio.unwrap_or(TRACER_DEFAULT_SAMPLING_RATIO)
    }

    /// Returns the initialization timeout
    pub fn init_timeout(&self) -> Duration {
        Duration::from_secs(
            self.init_timeout_secs
                .unwrap_or(TRACER_DEFAULT_INIT_TIMEOUT_SECS),
        )
    }

    /// Returns whether async initialization is enabled
    pub fn async_init(&self) -> bool {
        self.async_init.unwrap_or(true)
    }

    /// Returns the metrics port
    pub fn metrics_port(&self) -> u16 {
        self.metrics_port.unwrap_or(9464)
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(ratio) = self.sampling_ratio {
            if !(0..=100).contains(&ratio) {
                return Err(ConfigError::Message(
                    "sampling_ratio must be between 0 and 100".to_string(),
                ));
            }
        }

        if let Some(endpoint) = &self.endpoint {
            if endpoint.trim().is_empty() {
                return Err(ConfigError::Message(
                    "endpoint must not be empty if specified".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    #[builder(default, setter(strip_option))]
    max_retries: Option<u32>,

    /// Initial retry delay in milliseconds
    #[builder(default, setter(strip_option))]
    initial_delay_ms: Option<u64>,

    /// Maximum retry delay in milliseconds
    #[builder(default, setter(strip_option))]
    max_delay_ms: Option<u64>,
}

impl RetryConfig {
    pub fn max_retries(&self) -> u32 {
        self.max_retries.unwrap_or(TRACER_DEFAULT_RETRY_COUNT)
    }

    pub fn initial_delay(&self) -> Duration {
        Duration::from_millis(self.initial_delay_ms.unwrap_or(100))
    }

    pub fn max_delay(&self) -> Duration {
        Duration::from_millis(self.max_delay_ms.unwrap_or(5000))
    }
}

#[derive(
    Default, Display, Deserialize, Serialize, Clone, EnumString, AsRefStr, Eq, PartialEq, Debug,
)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ExecutionEnvironment {
    #[default]
    Local,
    #[strum(serialize = "dev")]
    Development,
    Stage,
    #[strum(serialize = "prod")]
    Production,
    Integration,
    #[cfg(test)]
    Test,
}

#[derive(TypedBuilder, Debug)]
pub struct Settings<'a> {
    #[builder(setter(strip_option), default = None)]
    path: Option<&'a str>,
    env_prefix: &'a str,
    #[builder(default)]
    parse_keys: Vec<&'a str>,
}

fn mode() -> ExecutionEnvironment {
    env::var("RUN_MODE")
        .map(|enum_str| ExecutionEnvironment::from_str(enum_str.as_str()).unwrap_or_default())
        .unwrap_or_else(|_| ExecutionEnvironment::Local)
}

impl Settings<'_> {
    /// Creates a new instance of `Settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created or deserialized.
    pub fn init_conf<'de, T: Deserialize<'de> + std::fmt::Debug>(&self) -> Result<T, ConfigError> {
        let mut env_conf = config::Environment::default()
            .prefix(self.env_prefix)
            .separator("__")
            .list_separator(",");
        if !self.parse_keys.is_empty() {
            env_conf = env_conf.try_parsing(true);
        }
        for key in &self.parse_keys {
            env_conf = env_conf.with_list_parse_key(key);
        }
        let mut config_builder = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(
                File::with_name(&format!("config/{}", self.env_prefix.to_lowercase()))
                    .required(false),
            )
            .add_source(
                File::with_name(&format!(
                    "config/{}-{}",
                    self.env_prefix.to_lowercase(),
                    *ENVIRONMENT
                ))
                .required(false),
            )
            .add_source(
                File::with_name(&format!(
                    "/etc/config/{}.toml",
                    self.env_prefix.to_lowercase()
                ))
                .required(false),
            );

        if let Some(path) = self.path {
            config_builder = config_builder.add_source(File::with_name(path).required(true))
        };

        let config = config_builder.add_source(env_conf).build()?;

        let settings: T = config.try_deserialize()?;

        tracing::info!("DEBUG: SETTINGS: {:?}", settings);

        Ok(settings)
    }
}
