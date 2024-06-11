use std::env;
use std::str::FromStr;

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

lazy_static::lazy_static! {
    pub static ref ENVIRONMENT: Mode = mode();
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder, Default)]
pub struct Tracing {
    service_name: String,
    endpoint: String,
}

impl Tracing {
    /// Returns the service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Default, Display, Deserialize, Serialize, Clone, EnumString, AsRefStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum Mode {
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

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct ContractFee {
    pub amount: u64,
    pub denom: String,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct SignKeyConfig {
    pub mnemonic: Option<String>,
    pub bip32: Option<String>,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct BlockchainConfig {
    pub addresses: Vec<String>,
    pub contract: String,
    pub fee: ContractFee,
    pub signkey: SignKeyConfig,
}

/// Three timeouts that controls the polling logic
/// to fetch results from the core.
/// All times are in seconds.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct TimeoutTriple {
    /// The time to wait before starting to poll.
    pub initial_wait_time: u64,
    /// The time to wait between polling.
    pub retry_interval: u64,
    /// How many times to poll before giving up.
    pub max_poll_count: u64,
}

impl TimeoutTriple {
    pub fn new(initial_wait_time: u64, retry_interval: u64, max_poll_count: u64) -> Self {
        Self {
            initial_wait_time,
            retry_interval,
            max_poll_count,
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TimeoutConfig {
    pub channel_timeout: u64,
    pub crs: TimeoutTriple,
    pub keygen: TimeoutTriple,
    pub preproc: TimeoutTriple,
    pub decryption: TimeoutTriple,
    pub reencryption: TimeoutTriple,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            channel_timeout: 60,
            // 2 hours
            crs: TimeoutTriple::new(60, 60, 120),
            // 20 hours, wait 5 hours first, then poll for the next 15 hours
            keygen: TimeoutTriple::new(18000, 15000, 150),
            // 20 hours, wait 5 hours first, then poll for the next 15 hours
            preproc: TimeoutTriple::new(18000, 15000, 150),
            // 2 minutes
            decryption: TimeoutTriple::new(10, 5, 24),
            // 2 minutes
            reencryption: TimeoutTriple::new(10, 5, 24),
        }
    }
}

impl TimeoutConfig {
    /// These are the testing defaults, used for testing parameters.
    pub fn testing_default() -> Self {
        Self {
            channel_timeout: 60,
            crs: TimeoutTriple::new(1, 5, 50),
            keygen: TimeoutTriple::new(1, 5, 50),
            preproc: TimeoutTriple::new(1, 5, 50),
            decryption: TimeoutTriple::new(1, 5, 50),
            reencryption: TimeoutTriple::new(1, 5, 50),
        }
    }

    /// These are the mocking/dummy defaults, used when the core is a dummy.
    pub fn mocking_default() -> Self {
        Self {
            channel_timeout: 60,
            crs: TimeoutTriple::new(1, 1, 10),
            keygen: TimeoutTriple::new(1, 1, 10),
            preproc: TimeoutTriple::new(1, 1, 10),
            decryption: TimeoutTriple::new(1, 1, 10),
            reencryption: TimeoutTriple::new(1, 1, 10),
        }
    }
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct OracleConfig {
    pub addresses: Vec<String>,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct ConnectorConfig {
    pub tick_interval_secs: u64,
    pub storage_path: String,
    pub tracing: Option<Tracing>,
    pub blockchain: BlockchainConfig,
    pub core: CoreConfig,
    pub oracle: OracleConfig,
}

impl BlockchainConfig {
    pub fn grpc_addresses(&self) -> Vec<&str> {
        self.addresses.iter().map(|s| s.as_str()).collect()
    }
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone, Default)]
pub struct CoreConfig {
    pub addresses: Vec<String>,
    pub timeout_config: TimeoutConfig,
}

impl CoreConfig {
    pub fn addresses(&self) -> Vec<&str> {
        self.addresses.iter().map(|s| s.as_str()).collect()
    }
}

#[derive(TypedBuilder)]
pub struct Settings<'a> {
    path: Option<&'a str>,
}

fn mode() -> Mode {
    env::var("RUN_MODE")
        .map(|enum_str| Mode::from_str(enum_str.as_str()).unwrap_or_default())
        .unwrap_or_else(|_| Mode::Local)
}

impl<'a> Settings<'a> {
    /// Creates a new instance of `Settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created or deserialized.
    pub fn init_conf<'de, T: Deserialize<'de>>(&self) -> Result<T, ConfigError> {
        let mut s = Config::builder()
            .add_source(File::with_name("config/default").required(cfg!(not(test))))
            .add_source(File::with_name("config/asc-connector").required(false))
            .add_source(
                File::with_name(&format!("config/asc-connector-{}", *ENVIRONMENT)).required(false),
            )
            .add_source(File::with_name("/etc/config/asc-connector.toml").required(false));

        if let Some(path) = self.path {
            s = s.add_source(File::with_name(path).required(false))
        };

        let s = s
            .add_source(
                config::Environment::default()
                    .prefix("ASC_CONN")
                    .separator("_")
                    .list_separator(","),
            )
            .build()?;

        let settings: T = s.try_deserialize()?;

        Ok(settings)
    }
}

pub mod telemetry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_config() {
        let conf: ConnectorConfig = Settings::builder()
            .path(Some("config/default"))
            .build()
            .init_conf()
            .unwrap();

        assert_eq!(conf.tick_interval_secs, 3);
        assert_eq!(conf.storage_path, "./temp/events.toml");

        // core configs
        assert_eq!(conf.core.addresses, vec!["http://localhost:8080"]);
        assert_eq!(conf.core.timeout_config.channel_timeout, 60);
        assert_eq!(
            conf.core.timeout_config.decryption,
            TimeoutTriple {
                initial_wait_time: 10,
                retry_interval: 5,
                max_poll_count: 24,
            }
        );

        // blockchain configs
        assert_eq!(conf.blockchain.addresses, vec!["http://localhost:9090"]);
        assert_eq!(conf.blockchain.fee.amount, 100000);
        assert_eq!(conf.blockchain.fee.denom, "ucosm");
    }
}
