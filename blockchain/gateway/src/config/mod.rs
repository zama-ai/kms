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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString)]
pub enum BaseGasPrice {
    #[strum(serialize = "eip1559_max_priority_fee_per_gas")]
    #[serde(rename = "eip1559_max_priority_fee_per_gas")]
    Eip1559MaxPriorityFeePerGas,

    #[strum(serialize = "current_gas_price")]
    #[serde(rename = "current_gas_price")]
    CurrentGasPrice,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct EthereumConfig {
    pub listener_type: ListenerType,
    pub wss_url: String,
    pub http_url: String,
    pub fhe_lib_address: H160,
    pub oracle_predeploy_address: H160,
    pub test_async_decrypt_address: H160,
    pub coprocessor_url: String,
    pub relayer_key: String,
    pub gas_price: Option<u64>,
    pub gas_limit: Option<u64>,
    pub base_gas: BaseGasPrice,
    pub gas_escalator_increase: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct KmsConfig {
    pub contract_address: String,
    pub mnemonic: String,
    pub address: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct StorageConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct GatewayConfig {
    pub debug: bool,
    pub api_url: String,
    pub mode: KmsMode,
    pub ethereum: EthereumConfig,
    pub kms: KmsConfig,
    pub storage: StorageConfig,
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
                    .separator("__"),
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
        let env_conf: [(&str, Option<&str>); 18] = [
            ("GATEWAY__DEBUG", None),
            ("GATEWAY__MODE", None),
            ("GATEWAY__ETHEREUM__LISTENER_TYPE", None),
            ("GATEWAY__ETHEREUM__WSS_URL", None),
            ("GATEWAY__ETHEREUM__HTTP_URL", None),
            ("GATEWAY__ETHEREUM__FHE_LIB_ADDRESS", None),
            ("GATEWAY__ETHEREUM__RELAYER_ADDRESS", None),
            ("GATEWAY__ETHEREUM__ORACLE_PREDEPLOY_ADDRESS", None),
            ("GATEWAY__ETHEREUM__TEST_ASYNC_DECRYPT_ADDRESS", None),
            ("GATEWAY__ETHEREUM__RELAYER_KEY", None),
            ("GATEWAY__ETHEREUM__GAS_PRICE", None),
            ("GATEWAY__ETHEREUM__GAS_LIMIT", None),
            ("GATEWAY__ETHEREUM__BASE_GAS", None),
            ("GATEWAY__ETHEREUM__GAS_ESCALATOR_INCREASE", None),
            ("GATEWAY__KMS__CONTRACT_ADDRESS", None),
            ("GATEWAY__KMS__MNEMONIC", None),
            ("GATEWAY__KMS__ADDRESS", None),
            ("GATEWAY__KMS__KEY_ID", None),
        ];
        temp_env::with_vars(env_conf, || {
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
            assert_eq!(gateway_config.ethereum.http_url, "http://localhost:8545");
            assert_eq!(
                gateway_config.ethereum.fhe_lib_address,
                H160::from_str("000000000000000000000000000000000000005d").unwrap()
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
                gateway_config.ethereum.relayer_key,
                "7ec931411ad75a7c201469a385d6f18a325d4923f9f213bd882bbea87e160b67"
            );
            assert_eq!(gateway_config.ethereum.gas_price, None);
            assert_eq!(gateway_config.ethereum.gas_limit, Some(5_000_000));
            assert_eq!(
                gateway_config.ethereum.base_gas,
                BaseGasPrice::Eip1559MaxPriorityFeePerGas
            );
            assert_eq!(gateway_config.ethereum.gas_escalator_increase, 20);
            assert_eq!(
                gateway_config.kms.contract_address,
                "wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d"
            );
            assert_eq!(
            gateway_config.kms.mnemonic,
            "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open"
        );
            assert_eq!(gateway_config.kms.address, "http://localhost:9090");
            assert_eq!(
                gateway_config.kms.key_id,
                "408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
            );
        });
    }

    #[test]
    fn test_gateway_config_with_overwrite_env() {
        let env_conf = [
            ("GATEWAY__DEBUG", Some("true")),
            ("GATEWAY__MODE", Some("threshold")),
            ("GATEWAY__ETHEREUM__LISTENER_TYPE", Some("FHEVM_V1")),
            (
                "GATEWAY__ETHEREUM__WSS_URL",
                Some("ws://test_with_var:8546"),
            ),
            (
                "GATEWAY__ETHEREUM__HTTP_URL",
                Some("http://test_with_var:8545"),
            ),
            (
                "GATEWAY__ETHEREUM__FHE_LIB_ADDRESS",
                Some("000000000000000000000000000000000000005e"),
            ),
            (
                "GATEWAY__ETHEREUM__RELAYER_ADDRESS",
                Some("97F272ccfef4026A1F3f0e0E879d514627B84E68"),
            ),
            (
                "GATEWAY__ETHEREUM__ORACLE_PREDEPLOY_ADDRESS",
                Some("c8c9303Cd7F337fab769686B593B87DC3403E0cd"),
            ),
            (
                "GATEWAY__ETHEREUM__TEST_ASYNC_DECRYPT_ADDRESS",
                Some("99F460504563579922352932A42172B3c04a1400"),
            ),
            (
                "GATEWAY__ETHEREUM__RELAYER_KEY",
                Some("1095a3b5efa0cbd54b9c840e3881fa62d74b793d01f091c292ce916cb2e7757a"),
            ),
            ("GATEWAY__ETHEREUM__GAS_PRICE", Some("1000000000")),
            ("GATEWAY__ETHEREUM__GAS_LIMIT", Some("5000000")),
            (
                "GATEWAY__ETHEREUM__BASE_GAS",
                Some("eip1559_max_priority_fee_per_gas"),
            ),
            ("GATEWAY__ETHEREUM__GAS_ESCALATOR_INCREASE", Some("35")),
            (
                "GATEWAY__KMS__CONTRACT_ADDRESS",
                Some("wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4f"),
            ),
            (
                "GATEWAY__KMS__MNEMONIC",
                Some("some mnemonic for testing purpose only"),
            ),
            ("GATEWAY__KMS__ADDRESS", Some("http://test_with_var:9091")),
            (
                "GATEWAY__KMS__KEY_ID",
                Some("408d8cbaa51dece7f782fe04ba0b1c1d017b1088"),
            ),
        ];
        temp_env::with_vars(env_conf, || {
            let gateway_config: GatewayConfig = Settings::builder()
                .path(Some("config/gateway"))
                .build()
                .init_conf()
                .unwrap();
            assert!(gateway_config.debug);
            assert_eq!(gateway_config.mode, KmsMode::Threshold);
            assert_eq!(gateway_config.ethereum.listener_type, ListenerType::Fhevm1);
            assert_eq!(gateway_config.ethereum.wss_url, "ws://test_with_var:8546");
            assert_eq!(
                gateway_config.ethereum.http_url,
                "http://test_with_var:8545"
            );
            assert_eq!(
                gateway_config.ethereum.fhe_lib_address,
                H160::from_str("000000000000000000000000000000000000005e").unwrap()
            );
            assert_eq!(
                gateway_config.ethereum.oracle_predeploy_address,
                H160::from_str("c8c9303Cd7F337fab769686B593B87DC3403E0cd").unwrap()
            );
            assert_eq!(
                gateway_config.ethereum.test_async_decrypt_address,
                H160::from_str("99F460504563579922352932A42172B3c04a1400").unwrap()
            );
            assert_eq!(
                gateway_config.ethereum.relayer_key,
                "1095a3b5efa0cbd54b9c840e3881fa62d74b793d01f091c292ce916cb2e7757a"
            );
            assert_eq!(gateway_config.ethereum.gas_price, Some(1_000_000_000));
            assert_eq!(gateway_config.ethereum.gas_limit, Some(5_000_000));
            assert_eq!(
                gateway_config.ethereum.base_gas,
                BaseGasPrice::Eip1559MaxPriorityFeePerGas
            );
            assert_eq!(gateway_config.ethereum.gas_escalator_increase, 35);
            assert_eq!(
                gateway_config.kms.contract_address,
                "wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4f"
            );
            assert_eq!(
                gateway_config.kms.mnemonic,
                "some mnemonic for testing purpose only"
            );
            assert_eq!(gateway_config.kms.address, "http://test_with_var:9091");
            assert_eq!(
                gateway_config.kms.key_id,
                "408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
            );
        });
    }
}
