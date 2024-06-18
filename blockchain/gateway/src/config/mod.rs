use std::env;
use std::str::FromStr;

use config::{Config, ConfigError, File};
use ethers::types::H160;
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

lazy_static::lazy_static! {
    pub(crate) static ref ENVIRONMENT: ExecutionEnvironment = mode();
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString, Display)]
pub enum KmsMode {
    #[strum(serialize = "centralized")]
    #[serde(rename = "centralized")]
    Centralized,
    #[strum(serialize = "threshold")]
    #[serde(rename = "threshold")]
    Threshold,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString)]
pub enum ListenerType {
    #[strum(serialize = "FHEVM_V1")]
    #[serde(rename = "FHEVM_V1")]
    Fhevm1,
    #[strum(serialize = "FHEVM_V1_1")]
    #[serde(rename = "FHEVM_V1_1")]
    Fhevm1_1,
    #[strum(serialize = "COPROCESSOR")]
    #[serde(rename = "COPROCESSOR")]
    Coprocessor,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct EthereumConfig {
    pub listener_type: ListenerType,
    pub wss_url: String,
    pub fhe_lib_address: H160,
    pub relayer_address: H160,
    pub oracle_predeploy_address: H160,
    pub test_async_decrypt_address: H160,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct KmsConfig {
    pub tendermint_node_addr: String,
    pub contract_address: String,
    pub mnemonic: String,
    pub address: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct GatewayConfig {
    pub debug: bool,
    pub mode: KmsMode,
    pub ethereum: EthereumConfig,
    pub kms: KmsConfig,
    pub tracing: Option<Tracing>,
}

#[derive(TypedBuilder)]
pub struct Settings<'a> {
    path: Option<&'a str>,
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
        let mut s = Config::builder()
            .add_source(File::with_name("config/gateway").required(cfg!(not(test))))
            .add_source(File::with_name("config/default").required(false))
            .add_source(
                File::with_name(&format!("config/gateway-{}", *ENVIRONMENT)).required(false),
            )
            .add_source(File::with_name("/etc/config/gateway.toml").required(false));

        if let Some(path) = self.path {
            s = s.add_source(File::with_name(path).required(false))
        };

        let s = s
            .add_source(
                config::Environment::default()
                    .prefix("GATEWAY")
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
    fn test_gateway_config() {
        let gateway_config: GatewayConfig = Settings::builder()
            .path(Some("config/gateway"))
            .build()
            .init_conf()
            .unwrap();
        assert!(!gateway_config.debug);
        assert_eq!(gateway_config.mode, KmsMode::Centralized);
        assert_eq!(
            gateway_config.ethereum.listener_type,
            ListenerType::Fhevm1_1
        );
        assert_eq!(gateway_config.ethereum.wss_url, "ws://localhost:8546");
        assert_eq!(
            gateway_config.ethereum.fhe_lib_address,
            H160::from_str("000000000000000000000000000000000000005d").unwrap()
        );
        assert_eq!(
            gateway_config.ethereum.relayer_address,
            H160::from_str("97F272ccfef4026A1F3f0e0E879d514627B84E69").unwrap()
        );
        assert_eq!(
            gateway_config.ethereum.oracle_predeploy_address,
            H160::from_str("c8c9303Cd7F337fab769686B593B87DC3403E0ce").unwrap()
        );
        assert_eq!(
            gateway_config.ethereum.test_async_decrypt_address,
            H160::from_str("99F460504563579922352932A42172B3c04a1420").unwrap()
        );
        assert_eq!(
            gateway_config.kms.tendermint_node_addr,
            "http://localhost:26657"
        );
        assert_eq!(
            gateway_config.kms.contract_address,
            "wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d"
        );
        assert_eq!(
            gateway_config.kms.mnemonic,
            "whisper stereo great helmet during hollow nominee skate frown daughter donor pool ozone few find risk cigar practice essay sketch rhythm novel dumb host"
        );
        assert_eq!(gateway_config.kms.address, "http://localhost:9090");
        assert_eq!(
            gateway_config.kms.key_id,
            "04a1aa8ba5e95fb4dc42e06add00b0c2ce3ea424"
        );
    }
}
