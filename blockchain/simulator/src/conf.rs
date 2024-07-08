use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct SimConfig {
    pub addresses: Vec<String>,
    pub contract: String,
    pub mnemonic: String,
}
