pub mod common {
    tonic::include_proto!("fhevm.common");
}

pub mod coprocessor {
    tonic::include_proto!("fhevm.coprocessor");
}

use crate::blockchain::ciphertext_provider::k256::ecdsa::SigningKey;
use crate::config::{EthereumConfig, ListenerType};
use anyhow::Context;
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{BlockId, Bytes as EthersBytes, TransactionRequest};
use events::kms::FheType;
use hex;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;

use coprocessor::fhevm_coprocessor_client::FhevmCoprocessorClient;
use coprocessor::GetCiphertextBatch;
use std::str::FromStr;
use tonic::metadata::MetadataValue;

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

// Implementation for FHEVM_V1_1
struct FhevmNativeCiphertextProvider {
    config: EthereumConfig,
}

#[async_trait]
impl CiphertextProvider for FhevmNativeCiphertextProvider {
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
        // Set up the gRPC client
        let mut client = FhevmCoprocessorClient::connect(self.config.coprocessor_url.clone())
            .await
            .context("Failed to connect to gRPC server")?;

        // Authorization token
        let api_key = &self.config.coprocessor_api_key;
        let api_key_header = format!("bearer {}", api_key);

        // Prepare the request with the ciphertext handle
        let mut request = tonic::Request::new(GetCiphertextBatch {
            handles: vec![ct_handle.clone()],
        });

        // Add the authorization header to the request
        request.metadata_mut().append(
            "authorization",
            MetadataValue::from_str(&api_key_header)
                .context("Failed to set authorization metadata")?,
        );

        tracing::info!(
            "Sending gRPC request for ct_handle: {:?}",
            hex::encode(ct_handle.clone())
        );

        // Make the gRPC call and process the response
        let response = client
            .get_ciphertexts(request)
            .await
            .context("Failed to fetch ciphertexts from the server")?;

        // Check if the response contains data
        let output = response.get_ref();
        if output.responses.is_empty() {
            tracing::error!("No responses found in the gRPC response.");
            anyhow::bail!("No responses found in the gRPC response.");
        }

        let first_response = &output.responses[0];
        if let Some(ciphertext) = &first_response.ciphertext {
            let ciphertext_bytes = ciphertext.ciphertext_bytes.clone();
            let c_type: u8 = ciphertext.ciphertext_type.try_into()?;

            tracing::info!(
                "Ciphertext bytes (first 5): {:?}",
                &ciphertext_bytes[0..5.min(ciphertext_bytes.len())]
            );
            tracing::info!("Ciphertext type: {}", c_type);

            Ok((ciphertext_bytes, FheType::from(c_type)))
        } else {
            tracing::error!("Ciphertext is missing in the response.");
            anyhow::bail!("Ciphertext is missing in the response.");
        }
    }
}

impl From<EthereumConfig> for Box<dyn CiphertextProvider> {
    fn from(config: EthereumConfig) -> Self {
        match config.listener_type {
            ListenerType::FhevmNative => Box::new(FhevmNativeCiphertextProvider { config }),
            ListenerType::Coprocessor => Box::new(CoprocessorCiphertextProvider { config }),
        }
    }
}
