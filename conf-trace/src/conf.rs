use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

const TRACER_MAX_QUEUE_SIZE: usize = 4096;
const TRACER_MAX_EXPORT_BATCH_SIZE: usize = 512;
const TRACER_MAX_CONCURRENT_EXPORTS: usize = 4;

lazy_static::lazy_static! {
    pub(crate) static ref ENVIRONMENT: ExecutionEnvironment = mode();
    static ref TRACER_SCHEDULED_DELAY: Duration = Duration::from_millis(1000);
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
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
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
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

    /// All the following settings are optional.
    /// The endpoint of the tracing system. If it is not set, tracing will be redirected to stdout.
    #[builder(default, setter(strip_option))]
    endpoint: Option<String>,

    /// Batch configuration.
    /// If this is set, the tracing system will not batch the spans before exporting them.
    #[builder(default, setter(strip_option))]
    bacth: Option<BatchConf>,
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
        &self.bacth
    }
}

#[derive(Default, Display, Deserialize, Serialize, Clone, EnumString, AsRefStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ExecutionEnvironment {
    #[default]
    Local,
    #[strum(serialize = "dev")]
    Development,
    Stage,
    #[strum(serialize = "prod")]
    Production,
    #[cfg(test)]
    Test,
}

#[derive(TypedBuilder)]
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

impl<'a> Settings<'a> {
    /// Creates a new instance of `Settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created or deserialized.
    pub fn init_conf<'de, T: Deserialize<'de>>(&self) -> Result<T, ConfigError> {
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
        let mut s = Config::builder()
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
            s = s.add_source(File::with_name(path).required(true))
        };

        let s = s.add_source(env_conf).build()?;

        let settings: T = s.try_deserialize()?;

        Ok(settings)
    }
}
