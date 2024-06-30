use crate::blockchain::ciphertext_provider::k256::ecdsa::SigningKey;
use crate::config::{EthereumConfig, ListenerType};
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{BlockId, Bytes as EthersBytes, TransactionRequest};
use events::kms::FheType;
use hex;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

// Trait to define the interface for getting ciphertext
// SignerMiddleware<Provider<Http>, Wallet<SigningKey>>
#[async_trait]
pub trait CiphertextProvider: Send {
    async fn get_ciphertext(
        &self,
        client: &Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)>;
}

// Implementation for FHEVM_V1
struct Fhevm1CiphertextProvider {
    config: EthereumConfig,
}

#[async_trait]
impl CiphertextProvider for Fhevm1CiphertextProvider {
    async fn get_ciphertext(
        &self,
        client: &Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)> {
        let mut input = hex::decode("e4b808cb000000000000000000000000")?;
        input.extend_from_slice(self.config.oracle_predeploy_address.as_bytes());
        input.extend_from_slice(&ct_handle);

        let call = TransactionRequest {
            from: Some(self.config.oracle_predeploy_address),
            to: Some(ethers::types::NameOrAddress::Address(
                self.config.fhe_lib_address,
            )),
            data: Some(EthersBytes::from(input)),
            ..Default::default()
        };
        let tx: TypedTransaction = call.into();

        let response = client.call(&tx, block_id).await?;
        Ok((response.to_vec(), FheType::from(ct_handle[30])))
    }
}

// Implementation for FHEVM_V1_1
struct Fhevm1_1CiphertextProvider {
    config: EthereumConfig,
}

#[async_trait]
impl CiphertextProvider for Fhevm1_1CiphertextProvider {
    async fn get_ciphertext(
        &self,
        client: &Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)> {
        tracing::info!(
            "Getting ciphertext for ct_handle: {:?}",
            hex::encode(ct_handle.clone())
        );
        let mut input = hex::decode("ff627e77")?;
        input.extend_from_slice(&ct_handle);

        let call = TransactionRequest {
            from: Some(self.config.oracle_predeploy_address),
            to: Some(ethers::types::NameOrAddress::Address(
                self.config.fhe_lib_address,
            )),
            data: Some(EthersBytes::from(input)),
            ..Default::default()
        };
        let tx: TypedTransaction = call.into();
        let response = client.call(&tx, block_id).await?;
        Ok((response.to_vec(), FheType::from(ct_handle[30])))
    }
}

// Implementation for Coprocessor
#[derive(Serialize, Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    id: u64,
    result: RpcResult,
}

#[derive(Serialize, Deserialize)]
struct RpcResult {
    ciphertext: String,
    #[serde(rename = "type")]
    result_type: u64,
}

struct CoprocessorCiphertextProvider {
    config: EthereumConfig,
}

#[async_trait]
impl CiphertextProvider for CoprocessorCiphertextProvider {
    async fn get_ciphertext(
        &self,
        _client: &Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        _block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)> {
        // Create a reqwest client
        let client = reqwest::Client::new();
        let handle = vec![format!("0x{}", hex::encode(ct_handle.clone()))];
        // Create the JSON payload
        let payload = json!({
            "method": "eth_getCiphertextByHandle",
            "params": handle,
            "id": 1,
            "jsonrpc": "2.0"
        });

        // Make the POST request
        let response = client
            .post(&self.config.coprocessor_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let rpc_response: RpcResponse = response.json().await?;

        // Extract the ciphertext and decode from hex to Vec<u8>
        let ciphertext_hex = rpc_response.result.ciphertext.trim_start_matches("0x");
        let ciphertext_bytes = hex::decode(ciphertext_hex)?;
        Ok((ciphertext_bytes, FheType::from(ct_handle[30])))
    }
}

impl From<EthereumConfig> for Box<dyn CiphertextProvider> {
    fn from(config: EthereumConfig) -> Self {
        match config.listener_type {
            ListenerType::Fhevm1 => Box::new(Fhevm1CiphertextProvider { config }),
            ListenerType::Fhevm1_1 => Box::new(Fhevm1_1CiphertextProvider { config }),
            ListenerType::Coprocessor => Box::new(CoprocessorCiphertextProvider { config }),
        }
    }
}
