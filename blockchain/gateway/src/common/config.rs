use anyhow::{Error, Result};
use config::Config;
use ethers::prelude::*;
use std::fmt;
use std::str::FromStr;

static CONFIG: Lazy<Config> = Lazy::new(|| {
    Config::builder()
        .add_source(config::File::with_name("config/gateway"))
        .add_source(config::Environment::with_prefix("GATEWAY"))
        .build()
        .unwrap()
});

#[derive(Debug)]
pub(crate) enum ListenerType {
    Fhevm1,
    Fhevm1_1,
    Coprocessor,
}

// Implement the FromStr trait for ListenerType
impl FromStr for ListenerType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FHEVM_V1" => Ok(ListenerType::Fhevm1),
            "FHEVM_V1_1" => Ok(ListenerType::Fhevm1_1),
            "COPROCESSOR" => Ok(ListenerType::Coprocessor),
            _ => Err(anyhow::anyhow!("Invalid ListenerType: {}", s)),
        }
    }
}

// Implement the Display trait for ListenerType (optional, for better error messages)
impl fmt::Display for ListenerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ListenerType::Fhevm1 => write!(f, "Fhevm1"),
            ListenerType::Fhevm1_1 => write!(f, "Fhevm1_1"),
            ListenerType::Coprocessor => write!(f, "Coprocessor"),
        }
    }
}

pub(crate) fn listener_type() -> ListenerType {
    CONFIG.get_string("listener_type").unwrap().parse().unwrap()
}

pub enum Mode {
    Centralized,
    Threshold,
}

impl FromStr for Mode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "centralized" => Ok(Mode::Centralized),
            "threshold" => Ok(Mode::Threshold),
            _ => Err(anyhow::anyhow!("Invalid Mode: {}", s)),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Mode::Centralized => write!(f, "Centralized"),
            Mode::Threshold => write!(f, "Threshold"),
        }
    }
}

pub fn mode() -> Mode {
    CONFIG.get_string("mode").unwrap().parse().unwrap()
}

pub fn trace_level() -> tracing::Level {
    let bind: String = CONFIG.get("trace_level").unwrap();
    bind.parse().unwrap()
}

pub fn debug_mode() -> bool {
    CONFIG.get_bool("debug").unwrap()
}

pub fn ethereum_wss_url() -> String {
    CONFIG.get("ethereum_wss_url").unwrap()
}

pub fn fhe_lib_address() -> H160 {
    let bind: String = CONFIG.get("fhe_lib_address").unwrap();
    H160::from_str(&bind).unwrap()
}

pub fn tendermint_node_addr() -> String {
    CONFIG.get("tendermint_node_addr").unwrap()
}

pub fn relayer_address() -> H160 {
    let bind: String = CONFIG.get("relayer_address").unwrap();
    H160::from_str(&bind).unwrap()
}

pub fn oracle_predeploy_address() -> H160 {
    let bind: String = CONFIG.get("oracle_predeploy_address").unwrap();
    H160::from_str(&bind).unwrap()
}

pub fn test_async_decrypt_address() -> H160 {
    let bind: String = CONFIG.get("test_async_decrypt_address").unwrap();
    H160::from_str(&bind).unwrap()
}

pub fn kms_contract_address() -> String {
    CONFIG.get("kms_contract_address").unwrap()
}

pub fn kms_mnemonic() -> String {
    CONFIG.get("kms_mnemonic").unwrap()
}

pub fn kms_address() -> String {
    CONFIG.get("kms_address").unwrap()
}

pub fn kms_key_id() -> String {
    CONFIG.get("kms_key_id").unwrap()
}
