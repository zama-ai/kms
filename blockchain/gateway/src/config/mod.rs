use conf_trace::conf::{Settings, Tracing};
use conf_trace::telemetry::init_tracing;
use ethers::types::H160;
use events::{HexVector, HexVectorList};
use kms_blockchain_connector::conf::ConnectorConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::{Display, EnumString};
use typed_builder::TypedBuilder;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString, Display)]
pub enum KmsMode {
    #[strum(serialize = "centralized")]
    #[serde(rename = "centralized")]
    Centralized,
    #[strum(serialize = "threshold")]
    #[serde(rename = "threshold")]
    Threshold,
}

/// Enum to indicate whether we are in Native or Coprocessor case
///
///__NOTE__: For ease of implementation of mock strucures, this structure
/// derives [`Default`] arbitrarily set to[`ListenerType::FhevmNative`].
#[derive(Default, Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString)]
pub enum ListenerType {
    #[default]
    #[strum(serialize = "FHEVM_NATIVE")]
    #[serde(rename = "FHEVM_NATIVE")]
    FhevmNative,
    #[strum(serialize = "COPROCESSOR")]
    #[serde(rename = "COPROCESSOR")]
    Coprocessor,
}

/// In the case a verify proven ct request
/// the gateway is responsible to
/// process the response it received from KMS BC
/// (and Coprocessor if any) into this struct for
/// the client to use
#[derive(Default, Debug, Serialize, Deserialize, TypedBuilder)]
pub struct VerifyProvenCtResponseToClient {
    // Whether Native or Coprocessor
    #[builder(setter(into))]
    pub listener_type: ListenerType,
    // Signature from KMS attesting validity of the proven ciphertext
    #[builder(setter(into))]
    pub kms_signatures: Vec<Vec<u8>>,
    // If Coprocesor, signature attesting correct storage
    #[builder(default, setter(into))]
    pub proof_of_storage: Vec<u8>,
    // If Coprocessor, handles to the ciphertexts
    // each inner vec is a single handle (32 byte array)
    #[builder(default, setter(into))]
    pub handles: Vec<Vec<u8>>,
}

/// An entry containing all URL and signature info for a key or CRS.
#[derive(Debug, TypedBuilder, Serialize, Deserialize)]
pub struct KeyUrlInfo {
    // The ID/handle of the key or CRS.
    data_id: HexVector,
    // The enum choice of parameters used for the key or CRS. TODO should maybe import ParamChoice
    param_choice: i32,
    // List of URLs to fetch the data element from.
    urls: Vec<String>,
    // List of signatures for the data element.
    signatures: HexVectorList,
}

impl KeyUrlInfo {
    pub fn data_id(&self) -> &HexVector {
        &self.data_id
    }

    pub fn param_choice(&self) -> i32 {
        self.param_choice
    }

    pub fn urls(&self) -> &Vec<String> {
        &self.urls
    }

    pub fn signatures(&self) -> &HexVectorList {
        &self.signatures
    }
}

/// Struct containing information about a single conceptual key (and hence ID)
#[derive(Debug, TypedBuilder, Serialize, Deserialize)]
pub struct FheKeyUrlInfo {
    // Info about the public key used for FHE encryption.
    fhe_public_key: KeyUrlInfo,
    // Info about the public key used for FHE computation.
    fhe_server_key: KeyUrlInfo,
}

impl FheKeyUrlInfo {
    pub fn fhe_public_key(&self) -> &KeyUrlInfo {
        &self.fhe_public_key
    }

    pub fn fhe_server_key(&self) -> &KeyUrlInfo {
        &self.fhe_server_key
    }
}

/// Struct containing information about a single conceptual verification key.
/// There is exactly one of these for each KMS server.
#[derive(Debug, TypedBuilder, Serialize, Deserialize)]
pub struct VerfKeyUrlInfo {
    // The ID of the verification key.
    key_id: HexVector,
    // The integer ID of the server who owns the key.
    server_id: u32,
    // The URL where the verification key can be found.
    verf_public_key_url: String,
    // The URL where the Ethereum associated address can be found.
    verf_public_key_address: String,
}

impl VerfKeyUrlInfo {
    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn server_id(&self) -> u32 {
        self.server_id
    }

    pub fn verf_public_key_url(&self) -> &str {
        &self.verf_public_key_url
    }

    pub fn verf_public_key_address(&self) -> &str {
        &self.verf_public_key_address
    }
}

#[derive(TypedBuilder)]
pub struct KeyUrlValues {
    data_id: HexVector,
}

impl KeyUrlValues {
    pub fn data_id(&self) -> &HexVector {
        &self.data_id
    }
}

#[derive(Debug, TypedBuilder, Serialize, Deserialize)]
pub struct KeyUrlResponseValues {
    // All the FHE public key info from this gateway and associated ASC.
    fhe_key_info: Vec<FheKeyUrlInfo>,
    // All the CRS info from this gateway and associated ASC.
    // The map maps the max_amount_of_bits a given CRS supports to the CRS information.
    // For now we assume there is only one CRS per max_amount_of_bits.
    crs: HashMap<u32, KeyUrlInfo>,
    // The public verification information for the KMS servers.
    // The vector will conatin one entry for each KMS server.
    verf_public_key: Vec<VerfKeyUrlInfo>,
}

impl KeyUrlResponseValues {
    pub fn fhe_key_info(&self) -> &Vec<FheKeyUrlInfo> {
        &self.fhe_key_info
    }

    pub fn crs(&self) -> &HashMap<u32, KeyUrlInfo> {
        &self.crs
    }

    pub fn verf_public_key(&self) -> &Vec<VerfKeyUrlInfo> {
        &self.verf_public_key
    }
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
    pub chain_id: u64,
    // EIP712 application salt representend as a hex encoding
    pub eip712_salt: Option<String>,
    pub listener_type: ListenerType,
    pub wss_url: String,
    pub coprocessor_api_key: String,
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
    pub kmsverifier_name: String,
    pub kmsverifier_version: String,
    pub kmsverifier_vc_address: H160,
    pub acl_address: H160,
    pub reenc_domain_name: String,
    pub reenc_domain_version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct KmsConfig {
    pub contract_address: String,
    pub mnemonic: String,
    pub address: String,
    pub key_id: String, //TODO: remove this field as part of https://github.com/zama-ai/fhevm/issues/548
    pub public_storage: HashMap<u32, String>,
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

impl GatewayConfig {
    pub(crate) fn parse_chain_id(&self) -> primitive_types::U256 {
        let chain_id_be = self.ethereum.chain_id.to_be_bytes();
        let mut chain_id_bytes = vec![0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&chain_id_be);

        primitive_types::U256::from_big_endian(&chain_id_bytes)
    }

    pub(crate) fn parse_eip712_salt(&self) -> Option<Vec<u8>> {
        self.ethereum
            .eip712_salt
            .clone()
            .map(|salt| hex::decode(salt).expect("Failed to decode EIP712 salt from hex string"))
    }
}

pub fn init_conf_gateway(config_file: &str) -> anyhow::Result<GatewayConfig> {
    Settings::builder()
        .path(config_file)
        .env_prefix("GATEWAY")
        .build()
        .init_conf()
        .map_err(|e| e.into())
}

pub fn init_conf_with_trace_gateway(config_file: &str) -> anyhow::Result<GatewayConfig> {
    let conf = init_conf_gateway(config_file)?;
    let tracing = conf
        .tracing
        .clone()
        .unwrap_or_else(|| Tracing::builder().service_name("gateway").build());
    init_tracing(tracing)?;
    Ok(conf)
}

pub fn init_conf_with_trace_connector(config_file: &str) -> anyhow::Result<ConnectorConfig> {
    kms_blockchain_connector::conf::init_conf(config_file)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_gateway_config() {
        let env_conf: [(&str, Option<&str>); 27] = [
            ("GATEWAY__DEBUG", None),
            ("GATEWAY__MODE", None),
            ("GATEWAY__ETHEREUM__CHAIN_ID", None),
            ("GATEWAY__ETHEREUM__LISTENER_TYPE", None),
            ("GATEWAY__ETHEREUM__WSS_URL", None),
            ("GATEWAY__ETHEREUM__HTTP_URL", None),
            ("GATEWAY__ETHEREUM__FHE_LIB_ADDRESS", None),
            ("GATEWAY__ETHEREUM__COPROCESSOR_API_KEY", None),
            ("GATEWAY__ETHEREUM__RELAYER_ADDRESS", None),
            ("GATEWAY__ETHEREUM__ORACLE_PREDEPLOY_ADDRESS", None),
            ("GATEWAY__ETHEREUM__TEST_ASYNC_DECRYPT_ADDRESS", None),
            ("GATEWAY__ETHEREUM__RELAYER_KEY", None),
            ("GATEWAY__ETHEREUM__GAS_PRICE", None),
            ("GATEWAY__ETHEREUM__GAS_LIMIT", None),
            ("GATEWAY__ETHEREUM__BASE_GAS", None),
            ("GATEWAY__ETHEREUM__GAS_ESCALATOR_INCREASE", None),
            ("GATEWAY__ETHEREUM__KMSVERIFIER_NAME", None),
            ("GATEWAY__ETHEREUM__KMSVERIFIER_VERSION", None),
            ("GATEWAY__ETHEREUM__KMSVERIFIER_VC_ADDRESS", None),
            ("GATEWAY__ETHEREUM__REENC_DOMAIN_NAME", None),
            ("GATEWAY__ETHEREUM__REENC_DOMAIN_VERSION", None),
            ("GATEWAY__ETHEREUM__ACL_ADDRESS", None),
            ("GATEWAY__KMS__CONTRACT_ADDRESS", None),
            ("GATEWAY__KMS__MNEMONIC", None),
            ("GATEWAY__KMS__ADDRESS", None),
            ("GATEWAY__KMS__KEY_ID", None),
            ("GATEWAY__KMS__CRS_IDS", None),
        ];

        temp_env::with_vars(env_conf, || {
            let gateway_config: GatewayConfig = init_conf_gateway("config/gateway").unwrap();
            assert!(!gateway_config.debug);
            assert_eq!(gateway_config.mode, KmsMode::Centralized);
            assert_eq!(gateway_config.ethereum.chain_id, 12345);
            assert_eq!(
                gateway_config.ethereum.kmsverifier_vc_address,
                H160::from_str("208de73316e44722e16f6ddff40881a3e4f86104").unwrap()
            );
            assert_eq!(gateway_config.ethereum.kmsverifier_name, "KMSVerifier");
            assert_eq!(gateway_config.ethereum.kmsverifier_version, "1");
            assert_eq!(
                gateway_config.ethereum.reenc_domain_name,
                "Authorization token"
            );
            assert_eq!(gateway_config.ethereum.reenc_domain_version, "1");
            assert_eq!(
                gateway_config.ethereum.acl_address,
                H160::from_str("339ece85b9e11a3a3aa557582784a15d7f82aaf2").unwrap()
            );
            assert_eq!(
                gateway_config.ethereum.listener_type,
                ListenerType::Coprocessor
            );
            assert_eq!(gateway_config.ethereum.wss_url, "ws://localhost:8746");
            assert_eq!(gateway_config.ethereum.http_url, "http://localhost:8745");
            assert_eq!(
                gateway_config.ethereum.fhe_lib_address,
                H160::from_str("000000000000000000000000000000000000005d").unwrap()
            );
            assert_eq!(
                gateway_config.ethereum.coprocessor_api_key,
                "a1503fb6-d79b-4e9e-826d-44cf262f3e05"
            );
            assert_eq!(
                gateway_config.ethereum.oracle_predeploy_address,
                H160::from_str("096b4679d45fb675d4e2c1e4565009cec99a12b1").unwrap()
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
                "wasm1yyca08xqdgvjz0psg56z67ejh9xms6l436u8y58m82npdqqhmmtqas0cl7"
            );
            assert_eq!(
                gateway_config.kms.mnemonic,
                "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open"
            );
            assert_eq!(gateway_config.kms.address, "http://localhost:9090");
        });
    }

    #[test]
    fn test_gateway_config_with_overwrite_env() {
        let env_conf = [
            ("GATEWAY__DEBUG", Some("true")),
            ("GATEWAY__MODE", Some("threshold")),
            ("GATEWAY__ETHEREUM__CHAIN_ID", Some("42")),
            ("GATEWAY__ETHEREUM__LISTENER_TYPE", Some("FHEVM_NATIVE")),
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
                "GATEWAY__ETHEREUM__COPROCESSOR_API_KEY",
                Some("api-key-env"),
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
            ("GATEWAY__ETHEREUM__KMSVERIFIER_NAME", Some("name")),
            ("GATEWAY__ETHEREUM__KMSVERIFIER_VERSION", Some("1")),
            ("GATEWAY__ETHEREUM__REENC_DOMAIN_NAME", Some("rname")),
            ("GATEWAY__ETHEREUM__REENC_DOMAIN_VERSION", Some("1")),
            (
                "GATEWAY__ETHEREUM__KMSVERIFIER_VC_ADDRESS",
                Some("66f9664f97F2b50F62D13eA064982f936dE76657"),
            ),
            (
                "GATEWAY__ETHEREUM__ACL_ADDRESS",
                Some("66f9664f97F2b50F62D13eA064982f936dE76657"),
            ),
        ];
        temp_env::with_vars(env_conf, || {
            let gateway_config: GatewayConfig = init_conf_gateway("config/gateway").unwrap();
            assert!(gateway_config.debug);
            assert_eq!(gateway_config.mode, KmsMode::Threshold);
            assert_eq!(gateway_config.ethereum.chain_id, 42);
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
                gateway_config.ethereum.kmsverifier_vc_address,
                H160::from_str("66f9664f97F2b50F62D13eA064982f936dE76657").unwrap()
            );
            assert_eq!(gateway_config.ethereum.kmsverifier_name, "name");
            assert_eq!(gateway_config.ethereum.kmsverifier_version, "1");
            assert_eq!(gateway_config.ethereum.reenc_domain_name, "rname");
            assert_eq!(gateway_config.ethereum.reenc_domain_version, "1");
            assert_eq!(
                gateway_config.ethereum.acl_address,
                H160::from_str("66f9664f97F2b50F62D13eA064982f936dE76657").unwrap()
            );
        });
    }
}
