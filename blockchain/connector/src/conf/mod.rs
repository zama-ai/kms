use std::env;
use std::str::FromStr;

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

lazy_static::lazy_static! {
    pub static ref ENVIRONMENT: Mode = mode();
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
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

#[derive(TypedBuilder, Deserialize, Serialize, Clone)]
pub struct ContractFee {
    pub amount: u64,
    pub coin_denom: String,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone)]
pub struct BlockchainConfig {
    pub grpc_addresses: Vec<String>,
    pub contract_address: String,
    pub fee: ContractFee,
    pub mnemonic_wallet: Option<String>,
    pub bip32_private_key: Option<String>,
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone)]
pub struct ConnectorConfig {
    pub tick_interval_secs: u64,
    pub storage_path: String,
    pub tracing: Option<Tracing>,
    pub blockchain: BlockchainConfig,
    pub coordinator: CoordinatorConfig,
}

impl BlockchainConfig {
    pub fn grpc_addresses(&self) -> Vec<&str> {
        self.grpc_addresses.iter().map(|s| s.as_str()).collect()
    }
}

#[derive(TypedBuilder, Deserialize, Serialize, Clone)]
pub struct CoordinatorConfig {
    pub addresses: Vec<String>,
    pub n_parties: u64,
}

impl CoordinatorConfig {
    pub fn coordinator_addresses(&self) -> Vec<&str> {
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
                    .separator("_"),
            )
            .build()?;

        let settings: T = s.try_deserialize()?;

        Ok(settings)
    }
}

pub mod telemetry;
