pub mod common {
    tonic::include_proto!("fhevm.common");
}

pub mod coprocessor {
    tonic::include_proto!("fhevm.coprocessor");
}

use crate::blockchain::ciphertext_provider::k256::ecdsa::SigningKey;
use crate::config::{EthereumConfig, ListenerType, VerifyProvenCtResponseToClient};
use crate::events::manager::ApiVerifyProvenCtValues;
use anyhow::Context;
use async_trait::async_trait;
use coprocessor::fhevm_coprocessor_client::FhevmCoprocessorClient;
use coprocessor::{GetCiphertextBatch, InputToUpload, InputUploadBatch, InputUploadResponse};
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{BlockId, Bytes as EthersBytes, TransactionRequest};
use events::kms::FheType;
use events::HexVectorList;
use hex;
use kms_common::{retry::LoopErr, retry_fatal_loop};
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tonic::metadata::MetadataValue;

// Trait to define the interface for getting ciphertext
#[async_trait]
pub(crate) trait CiphertextProvider: Send + Sync {
    async fn get_ciphertext(
        &self,
        client: Arc<Box<dyn InternalMiddleware>>,
        ct_handle: Vec<u8>,
        block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)>;

    async fn put_ciphertext(
        &self,
        event: &ApiVerifyProvenCtValues,
        kms_signatures: HexVectorList,
    ) -> anyhow::Result<VerifyProvenCtResponseToClient>;
}

// This is wrapper around real and fake SignerMiddleware
// to avoid lifetime issues when making Provider<T> generic.
// It has Send + Sync marker traits because SignerMiddleware
// implements ethers::providers::Middleware which also has Send + Sync.
#[async_trait]
pub(crate) trait InternalMiddleware: Send + Sync {
    async fn call(&self, tx: &TypedTransaction, block: Option<BlockId>) -> anyhow::Result<Bytes>;

    async fn get_chainid(&self) -> anyhow::Result<U256>;
}

pub(crate) struct RealMiddleware {
    pub(crate) inner: SignerMiddleware<Provider<Http>, Wallet<SigningKey>>,
}

pub(crate) struct MockMiddleware {
    pub(crate) inner: SignerMiddleware<Provider<MockProvider>, Wallet<SigningKey>>,
}

#[async_trait]
impl InternalMiddleware for RealMiddleware {
    async fn call(&self, tx: &TypedTransaction, block: Option<BlockId>) -> anyhow::Result<Bytes> {
        self.inner
            .call(tx, block)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn get_chainid(&self) -> anyhow::Result<U256> {
        self.inner
            .provider()
            .get_chainid()
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[async_trait]
impl InternalMiddleware for MockMiddleware {
    async fn call(&self, tx: &TypedTransaction, block: Option<BlockId>) -> anyhow::Result<Bytes> {
        self.inner
            .call(tx, block)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn get_chainid(&self) -> anyhow::Result<U256> {
        // This needs to match what's in gateway config file for tests to pass
        // [48, 57] in big endian corresponds to the integer 12345
        Ok(U256::from_big_endian(&[48, 57]))
    }
}

// Implementation for FHEVM_V1_1
struct FhevmNativeCiphertextProvider {
    config: EthereumConfig,
}

#[async_trait]
impl CiphertextProvider for FhevmNativeCiphertextProvider {
    async fn get_ciphertext(
        &self,
        client: Arc<Box<dyn InternalMiddleware>>,
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

    /// In the Native case, there's nothing to do,
    /// the ciphertexst is already on chain
    async fn put_ciphertext(
        &self,
        _event: &ApiVerifyProvenCtValues,
        kms_signatures: HexVectorList,
    ) -> anyhow::Result<VerifyProvenCtResponseToClient> {
        Ok(VerifyProvenCtResponseToClient::builder()
            .kms_signatures(kms_signatures)
            .listener_type(ListenerType::FhevmNative)
            .build())
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
    #[allow(clippy::assign_op_pattern)]
    async fn get_ciphertext(
        &self,
        _client: Arc<Box<dyn InternalMiddleware>>,
        ct_handle: Vec<u8>,
        _block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)> {
        let ct_handle_as_hex = hex::encode(ct_handle.clone());

        let attempt = AtomicUsize::new(0);

        // Authorization token
        let api_key = &self.config.coprocessor_api_key;
        let api_key_header = format!("bearer {}", api_key);

        retry_fatal_loop!(
            || async {
                let current_attempt = attempt.fetch_add(1, Ordering::SeqCst) + 1;
                tracing::info!(
                    "fetching ciphertext for handle {}: attempt #{}",
                    &ct_handle_as_hex,
                    current_attempt
                );

                // Set up the gRPC client
                let mut client =
                    FhevmCoprocessorClient::connect(self.config.coprocessor_url.clone())
                        .await
                        .map_err(|e| LoopErr::transient(e.into()))?;

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

                // Make the gRPC call and process the response
                let response = client
                    .get_ciphertexts(request)
                    .await
                    .map_err(|e| LoopErr::transient(e.into()))?;

                // Check if the response contains data
                let output = response.get_ref();
                if output.responses.is_empty() {
                    return Err(LoopErr::fatal(anyhow::anyhow!(
                        "No responses found in the gRPC response."
                    )));
                }

                let first_response = &output.responses[0];
                if let Some(ciphertext) = &first_response.ciphertext {
                    let ciphertext_bytes = ciphertext.ciphertext_bytes.clone();
                    let c_type: u8 = ciphertext.ciphertext_type.try_into().map_err(|_| {
                        LoopErr::fatal(anyhow::anyhow!("Could not convert ciphertext type to u8"))
                    })?;

                    tracing::info!(
                        "Ciphertext bytes (first 5): {:?}",
                        &ciphertext_bytes[0..5.min(ciphertext_bytes.len())]
                    );
                    tracing::info!("Ciphertext type: {}", c_type);

                    Ok((ciphertext_bytes, FheType::from(c_type)))
                } else {
                    Err(LoopErr::fatal(anyhow::anyhow!(
                        "No responses found in the gRPC response."
                    )))
                }
            },
            self.config.get_ciphertext_retry.factor,
            self.config.get_ciphertext_retry.max_retries,
            TimeoutStrategy::Exponential
        )
        .map_err(|error| match error {
            LoopErr::Termination(inner_error) => inner_error,
            LoopErr::Fatal(inner_error) => inner_error,
            LoopErr::Transient(inner_error) => inner_error,
        })
    }

    /// In the Coprocessor case, we need
    /// to send a request to the Coprocessor
    /// to store the ciphertext and receive back the proof
    /// and the handles
    async fn put_ciphertext(
        &self,
        event: &ApiVerifyProvenCtValues,
        kms_signatures: HexVectorList,
    ) -> anyhow::Result<VerifyProvenCtResponseToClient> {
        // Set up the gRPC client
        let mut client = FhevmCoprocessorClient::connect(self.config.coprocessor_url.clone())
            .await
            .context("Failed to connect to gRPC server")?;

        // Authorization token
        let api_key = &self.config.coprocessor_api_key;
        let api_key_header = format!("bearer {}", api_key);

        let input_ciphertexts = convert_proven_ct_to_copro_input(event, &kms_signatures);
        // Prepare the request with the input ciphertexts
        let mut request = tonic::Request::new(InputUploadBatch { input_ciphertexts });

        // Add the authorization header to the request
        request.metadata_mut().append(
            "authorization",
            MetadataValue::from_str(&api_key_header)
                .context("Failed to set authorization metadata")?,
        );

        tracing::info!("Sending gRPC request for input ctxt to Coprocessor");

        // Make the gRPC call and process the response
        let response = client
            .upload_inputs(request)
            .await
            .context("Failed to put ciphertexts from the server")?;

        // Check if the response contains data
        let output = response.get_ref();
        if output.upload_responses.is_empty() {
            tracing::error!("No responses found in the gRPC response.");
            anyhow::bail!("No responses found in the gRPC response.");
        }

        process_response_from_copro_to_client(output, kms_signatures)
    }
}

fn convert_proven_ct_to_copro_input(
    event: &ApiVerifyProvenCtValues,
    kms_signatures: &HexVectorList,
) -> Vec<InputToUpload> {
    //Note: for now the GW only ever expects ciphertext to be sent one at a time for input
    vec![InputToUpload {
        input_payload: event.ct_proof.0.clone(),
        contract_address: event.contract_address.clone(),
        user_address: event.caller_address.clone(),
        signatures: kms_signatures.clone().into(),
    }]
}

fn process_response_from_copro_to_client(
    upload_response: &InputUploadResponse,
    kms_signatures: HexVectorList,
) -> anyhow::Result<VerifyProvenCtResponseToClient> {
    //Here also for now we always expect a single response
    if upload_response.upload_responses.len() != 1 {
        tracing::error!("Multiple response from Coprocessor InputUpload");
        anyhow::bail!("Multiple response from Coprocessor InputUpload");
    }
    let response = &upload_response.upload_responses[0];
    let handles: Vec<Vec<u8>> = response
        .input_handles
        .iter()
        .map(|handle| handle.handle.clone())
        .collect();
    let proof_of_storage = response.eip712_signature.clone();
    let verify_proven_ct_response_builder = VerifyProvenCtResponseToClient::builder()
        .kms_signatures(kms_signatures)
        .handles(handles)
        .proof_of_storage(proof_of_storage)
        .listener_type(ListenerType::Coprocessor);

    Ok(verify_proven_ct_response_builder.build())
}

impl From<EthereumConfig> for Box<dyn CiphertextProvider> {
    fn from(config: EthereumConfig) -> Self {
        match config.listener_type {
            ListenerType::FhevmNative => Box::new(FhevmNativeCiphertextProvider { config }),
            ListenerType::Coprocessor => Box::new(CoprocessorCiphertextProvider { config }),
        }
    }
}

pub(crate) struct DummyCiphertextProvider;

#[async_trait]
impl CiphertextProvider for DummyCiphertextProvider {
    async fn get_ciphertext(
        &self,
        _client: Arc<Box<dyn InternalMiddleware>>,
        _ct_handle: Vec<u8>,
        _block_id: Option<BlockId>,
    ) -> anyhow::Result<(Vec<u8>, FheType)> {
        Ok((b"get_ciphertext".into(), FheType::Ebool))
    }

    // An address ending by "7" is considered unknown for testing purpose
    async fn put_ciphertext(
        &self,
        event: &ApiVerifyProvenCtValues,
        kms_signatures: HexVectorList,
    ) -> anyhow::Result<VerifyProvenCtResponseToClient> {
        let last_char = &event.contract_address[event.contract_address.len() - 1..];
        if last_char == "7" {
            return Err(anyhow::anyhow!("Unknown contact address."));
        }
        let verify_proven_ct_response_builder = VerifyProvenCtResponseToClient::builder()
            .kms_signatures(kms_signatures)
            .listener_type(ListenerType::Coprocessor);

        Ok(verify_proven_ct_response_builder.build())
    }
}
