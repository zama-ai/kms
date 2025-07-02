use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use strum_macros::{AsRefStr, Display, EnumString};
use tracing::{debug, warn};
use typed_builder::TypedBuilder;
use validator::Validate;

// Default configuration constants
const TRACER_MAX_QUEUE_SIZE: usize = 8192;
const TRACER_MAX_EXPORT_BATCH_SIZE: usize = 2048;
const TRACER_OTLP_TIMEOUT_MS: u64 = 10000;
const TRACER_DEFAULT_RETRY_COUNT: u32 = 3;
const TRACER_DEFAULT_SCHEDULED_DELAY_MS: u64 = 500;
const TRACER_DEFAULT_RETRY_INITIAL_DELAY_MS: u64 = 100;
const TRACER_DEFAULT_RETRY_MAX_DELAY_MS: u64 = 1000;

lazy_static::lazy_static! {
    pub(crate) static ref ENVIRONMENT: ExecutionEnvironment = mode();
    static ref TRACER_SCHEDULED_DELAY: Duration = Duration::from_millis(TRACER_DEFAULT_SCHEDULED_DELAY_MS);
}

#[derive(Debug, Deserialize, Serialize, Validate, Clone, TypedBuilder, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(rename = "telemetry")]
pub struct TelemetryConfig {
    /// Service name for tracing
    #[validate(length(min = 1))]
    #[builder(default, setter(strip_option))]
    pub tracing_service_name: Option<String>,

    /// Endpoint for tracing
    #[validate(length(min = 1))]
    #[builder(default, setter(strip_option))]
    pub tracing_endpoint: Option<String>,

    /// Timeout for OTLP exporter operations (HTTP/gRPC requests) in milliseconds
    #[validate(range(min = 1))]
    #[builder(default, setter(strip_option))]
    pub tracing_otlp_timeout_ms: Option<u64>,

    /// Address to expose metrics on
    #[validate(length(min = 1))]
    #[builder(default, setter(strip_option))]
    pub metrics_bind_address: Option<String>,

    /// Batch configuration for tracing
    #[builder(default, setter(strip_option))]
    pub batch: Option<Batch>,
}

impl TelemetryConfig {
    pub fn tracing_service_name(&self) -> Option<&str> {
        let res = self.tracing_service_name.as_deref();
        debug!(
            "Getting tracing_service_name: {}",
            res.unwrap_or("tracing_service_name not found.")
        );
        res
    }

    pub fn tracing_endpoint(&self) -> Option<&str> {
        self.tracing_endpoint.as_deref()
    }

    pub fn tracing_otlp_timeout(&self) -> Duration {
        Duration::from_millis(
            self.tracing_otlp_timeout_ms
                .unwrap_or(TRACER_OTLP_TIMEOUT_MS),
        )
    }

    pub fn metrics_bind_address(&self) -> Option<&str> {
        let res = self.metrics_bind_address.as_deref();
        debug!(
            "Getting metrics_bind_address: {}",
            res.unwrap_or("metrics_bind_address not found.")
        );
        res
    }

    pub fn batch(&self) -> Option<&Batch> {
        self.batch.as_ref()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        debug!("Validating telemetry config: {:?}", self);
        if let Some(endpoint) = &self.tracing_endpoint {
            if endpoint.is_empty() {
                warn!("Empty tracing endpoint provided");
                return Err(ConfigError::Message(
                    "tracing endpoint cannot be empty".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, TypedBuilder, Eq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "lowercase")]
pub struct Batch {
    /// The maximum number of spans that can be queued before they are exported.
    /// Defaults to `telemetry::TRACER_MAX_QUEUE_SIZE`
    #[builder(default, setter(strip_option))]
    max_queue_size: Option<usize>,
    /// The maximum number of spans that can be exported in a single batch.
    /// Defaults to `telemetry::TRACER_MAX_EXPORT_BATCH_SIZE`
    #[builder(default, setter(strip_option))]
    max_export_batch_size: Option<usize>,

    /// The delay between two consecutive exports in milliseconds.
    /// Defaults to `telemetry::TRACER_SCHEDULED_DELAY_MS`
    #[builder(default, setter(strip_option))]
    scheduled_delay_ms: Option<u64>,
}

impl<'de> Deserialize<'de> for Batch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        struct BatchHelper {
            max_queue_size: Option<usize>,
            max_export_batch_size: Option<usize>,
            scheduled_delay_ms: Option<u64>,
        }

        let helper = BatchHelper::deserialize(deserializer)?;

        Ok(Batch {
            max_queue_size: helper.max_queue_size,
            max_export_batch_size: helper.max_export_batch_size,
            scheduled_delay_ms: helper.scheduled_delay_ms,
        })
    }
}

impl Batch {
    /// Returns the max queue size.
    pub fn max_queue_size(&self) -> usize {
        self.max_queue_size.unwrap_or(TRACER_MAX_QUEUE_SIZE)
    }

    /// Returns the max export batch size.
    pub fn max_export_batch_size(&self) -> usize {
        self.max_export_batch_size
            .unwrap_or(TRACER_MAX_EXPORT_BATCH_SIZE)
    }

    /// Returns the scheduled delay.
    pub fn scheduled_delay(&self) -> Duration {
        Duration::from_millis(
            self.scheduled_delay_ms
                .unwrap_or(TRACER_DEFAULT_SCHEDULED_DELAY_MS),
        )
    }
}

#[derive(Debug, Serialize, Clone, TypedBuilder, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

impl<'de> Deserialize<'de> for RetryConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RetryConfigHelper {
            max_retries: Option<u32>,
            initial_delay_ms: Option<u64>,
            max_delay_ms: Option<u64>,
        }

        let helper = RetryConfigHelper::deserialize(deserializer)?;
        println!(
            "Deserializing RetryConfig: max_retries={:?}, initial_delay_ms={:?}, max_delay_ms={:?}",
            helper.max_retries, helper.initial_delay_ms, helper.max_delay_ms,
        );

        Ok(RetryConfig {
            max_retries: helper.max_retries,
            initial_delay_ms: helper.initial_delay_ms,
            max_delay_ms: helper.max_delay_ms,
        })
    }
}

impl RetryConfig {
    pub fn max_retries(&self) -> u32 {
        let retries = self.max_retries.unwrap_or(TRACER_DEFAULT_RETRY_COUNT);
        debug!("Getting max_retries: {}", retries);
        retries
    }

    pub fn initial_delay(&self) -> Duration {
        let delay = Duration::from_millis(
            self.initial_delay_ms
                .unwrap_or(TRACER_DEFAULT_RETRY_INITIAL_DELAY_MS),
        );
        debug!("Getting initial_delay: {:?}", delay);
        delay
    }

    pub fn max_delay(&self) -> Duration {
        let delay = Duration::from_millis(
            self.max_delay_ms
                .unwrap_or(TRACER_DEFAULT_RETRY_MAX_DELAY_MS),
        );
        debug!("Getting max_delay: {:?}", delay);
        delay
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
    let res = env::var("RUN_MODE")
        .map(|enum_str| ExecutionEnvironment::from_str(enum_str.as_str()).unwrap_or_default())
        .unwrap_or_else(|_| ExecutionEnvironment::Local);
    println!("RUN_MODE={res}");
    res
}

impl Settings<'_> {
    /// Creates a new instance of `Settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created or deserialized.
    pub fn init_conf<'de, T: Deserialize<'de> + std::fmt::Debug>(&self) -> Result<T, ConfigError> {
        println!(
            "Initializing configuration with prefix: {}",
            self.env_prefix
        );
        if let Some(path) = self.path {
            println!("Using config file: {path}");
        }

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
