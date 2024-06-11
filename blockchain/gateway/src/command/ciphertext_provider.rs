use crate::command::ciphertext_provider::k256::ecdsa::SigningKey;
use crate::common::config::fhe_lib_address;
use crate::common::config::listener_type;
use crate::common::config::oracle_predeploy_address;
use crate::common::config::ListenerType;
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{BlockId, Bytes as EthersBytes, TransactionRequest};
use hex;
use std::error::Error;
use std::sync::Arc;

// Trait to define the interface for getting ciphertext
#[async_trait]
pub trait CiphertextProvider: Send {
    async fn get_ciphertext(
        &self,
        client: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        block_number: u64,
    ) -> Result<Bytes, Box<dyn Error>>;
}

// Implementation for FHEVM_V1
struct Fhevm1CiphertextProvider;

#[async_trait]
impl CiphertextProvider for Fhevm1CiphertextProvider {
    async fn get_ciphertext(
        &self,
        client: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        block_number: u64,
    ) -> Result<Bytes, Box<dyn Error>> {
        let mut input = hex::decode("e4b808cb000000000000000000000000")?;
        input.extend_from_slice(oracle_predeploy_address().as_bytes());
        input.extend_from_slice(&ct_handle);

        let call = TransactionRequest {
            from: Some(oracle_predeploy_address()),
            to: Some(ethers::types::NameOrAddress::Address(fhe_lib_address())),
            data: Some(EthersBytes::from(input)),
            ..Default::default()
        };
        let tx: TypedTransaction = call.into();

        let response = client.call(&tx, Some(BlockId::from(block_number))).await?;
        Ok(response)
    }
}

// Implementation for FHEVM_V1_1
struct Fhevm1_1CiphertextProvider;

#[async_trait]
impl CiphertextProvider for Fhevm1_1CiphertextProvider {
    async fn get_ciphertext(
        &self,
        client: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        ct_handle: Vec<u8>,
        block_number: u64,
    ) -> Result<Bytes, Box<dyn Error>> {
        let mut input = hex::decode("ff627e77")?;
        input.extend_from_slice(&ct_handle);

        let call = TransactionRequest {
            from: Some(oracle_predeploy_address()),
            to: Some(ethers::types::NameOrAddress::Address(fhe_lib_address())),
            data: Some(EthersBytes::from(input)),
            ..Default::default()
        };
        let tx: TypedTransaction = call.into();

        let response = client.call(&tx, Some(BlockId::from(block_number))).await?;
        Ok(response)
    }
}

// Implementation for Coprocessor
struct CoprocessorCiphertextProvider;

#[async_trait]
impl CiphertextProvider for CoprocessorCiphertextProvider {
    async fn get_ciphertext(
        &self,
        _client: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        _ct_handle: Vec<u8>,
        _block_number: u64,
    ) -> Result<Bytes, Box<dyn Error>> {
        todo!("Implement CoprocessorCiphertextProvider")
    }
}

// Function to get the appropriate ciphertext provider based on the listener type
pub fn get() -> Box<dyn CiphertextProvider> {
    match listener_type() {
        ListenerType::Fhevm1 => Box::new(Fhevm1CiphertextProvider),
        ListenerType::Fhevm1_1 => Box::new(Fhevm1_1CiphertextProvider),
        ListenerType::Coprocessor => Box::new(CoprocessorCiphertextProvider),
    }
}
