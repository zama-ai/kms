use std::ops::{Deref, DerefMut};

use alloy_sol_types::Eip712Domain;
use anyhow::anyhow;
use bech32::{self, FromBase32};
use bincode::deserialize;
use bytes::Bytes;
use clap::Parser;
use conf_trace::conf::Settings;
use cosmwasm_std::Event;
use dashmap::DashMap;
use ethers::abi::Token;
use ethers::types::{Address, U256};
use events::kms::{CrsGenValues, TransactionId, ZkpValues};
use events::kms::{
    DecryptValues, FheType, InsecureKeyGenValues, KeyGenPreprocValues, KeyGenValues, KmsEvent,
    KmsMessage, KmsOperation, OperationValue,
};
use events::HexVector;
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest, ProtoCoin};
use kms_blockchain_client::query_client::{
    ContractQuery, EventQuery, QueryClient, QueryClientBuilder, QueryContractRequest,
};
use kms_lib::client::assemble_metadata_alloy;
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::util::key_setup::test_tools::{
    compute_compressed_cipher_from_stored_key, compute_zkp_from_stored_key_and_serialize,
    TypedPlaintext,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumString};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use typed_builder::TypedBuilder;

#[derive(Serialize, Clone, Default, Debug)]
pub struct SimulatorConfig {
    pub s3_endpoint: String,
    pub crs_id: String,
    pub key_id: String,
    pub key_folder: String,
    pub validator_addresses: Vec<String>,
    pub http_validator_endpoints: Vec<String>,
    pub kv_store_address: String,
    pub contract: String,
    pub mnemonic: String,
    pub faucet_address: String,
}

fn parse_contract_address(
    contract_address: &String,
    validator_tcp_endpoint: &str,
) -> Result<String, Box<dyn std::error::Error + 'static>> {
    if contract_address == "latest" {
        return Ok(get_latest_deployed_contract_address(
            validator_tcp_endpoint,
        )?);
    }
    // Implement your custom parsing logic here
    Ok(contract_address.to_string())
}

impl<'de> Deserialize<'de> for SimulatorConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Clone, Default, Debug)]
        pub struct SimulatorConfigBuffer {
            pub s3_endpoint: String,
            pub crs_id: String,
            pub key_id: String,
            pub key_folder: String,
            pub validator_addresses: Vec<String>,
            pub http_validator_endpoints: Vec<String>,
            pub kv_store_address: String,
            pub contract: String,
            pub mnemonic: String,
            pub faucet_address: String,
        }

        let temp = SimulatorConfigBuffer::deserialize(deserializer)?;

        let contract_address =
            parse_contract_address(&temp.contract, &temp.http_validator_endpoints[0])
                .unwrap_or_default();

        Ok(SimulatorConfig {
            s3_endpoint: temp.s3_endpoint,
            crs_id: temp.crs_id,
            key_id: temp.key_id,
            key_folder: temp.key_folder,
            validator_addresses: temp.validator_addresses,
            http_validator_endpoints: temp.http_validator_endpoints,
            kv_store_address: temp.kv_store_address,
            contract: contract_address,
            mnemonic: temp.mnemonic,
            faucet_address: temp.faucet_address,
        })
    }
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("Invalid conversion from Token")]
    InvalidConversion,
    #[error("Value exceeds 4 bits")]
    Uint4Overflow,
}

// Define a custom trait for converting to Token
pub trait TokenizableFrom {
    fn to_token(self) -> Token;
}

// Define a custom trait for converting from Token
pub trait TryTokenizable: Sized {
    type Error;

    fn from_token(token: Token) -> Result<Self, Self::Error>;
}

// Define the custom Uint4 type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U4(u8);

impl U4 {
    pub fn new(value: u8) -> Result<Self, &'static str> {
        if value <= 0x0F {
            Ok(U4(value))
        } else {
            Err("Value exceeds 4 bits")
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

impl TokenizableFrom for U4 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self.value()))
    }
}

impl TryTokenizable for U4 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            let value_as_u8 = value.as_u32() as u8;
            if value_as_u8 <= 0x0F {
                Ok(U4(value_as_u8))
            } else {
                Err(ConversionError::Uint4Overflow)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

macro_rules! impl_tokenizable {
    // Simple types (bool, U256, Address)
    ($type:ty, $token_variant:ident) => {
        impl TokenizableFrom for $type {
            fn to_token(self) -> Token {
                Token::$token_variant(self.into())
            }
        }

        impl TryTokenizable for $type {
            type Error = ConversionError;

            fn from_token(token: Token) -> Result<Self, Self::Error> {
                if let Token::$token_variant(value) = token {
                    Ok(value)
                } else {
                    Err(ConversionError::InvalidConversion)
                }
            }
        }
    };

    // Integer types (u8, u16, u32, u64, u128)
    ($type:ty, $max:expr) => {
        impl TokenizableFrom for $type {
            fn to_token(self) -> Token {
                Token::Uint(U256::from(self))
            }
        }

        impl TryTokenizable for $type {
            type Error = ConversionError;

            fn from_token(token: Token) -> Result<Self, Self::Error> {
                if let Token::Uint(value) = token {
                    if value <= U256::from($max) {
                        Ok(value.as_u128() as $type)
                    } else {
                        Err(ConversionError::InvalidConversion)
                    }
                } else {
                    Err(ConversionError::InvalidConversion)
                }
            }
        }
    };
}

// Implement to token for the following objects
impl_tokenizable!(bool, Bool);
impl_tokenizable!(U256, Uint);
impl_tokenizable!(Address, Address);
impl_tokenizable!(u8, u8::MAX);
impl_tokenizable!(u16, u16::MAX);
impl_tokenizable!(u32, u32::MAX);
impl_tokenizable!(u64, u64::MAX);
impl_tokenizable!(u128, u128::MAX);

// CLI arguments
#[derive(Debug, Parser)]
pub struct Nothing {}

#[derive(Debug, Parser)]
pub struct CryptExecute {
    #[clap(long, short = 'e')]
    pub to_encrypt: u8,
}

#[derive(Debug, Parser)]
pub struct KeyGenExecute {
    #[clap(long, short = 'i')]
    pub preproc_id: String,
}

#[derive(Debug, Parser)]
pub struct ZkpExecute {
    #[clap(long, short = 'e')]
    pub to_encrypt: u8,
    pub crs_id: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Debug, Parser, Clone)]
pub struct Query {
    #[clap(long, short = 't')]
    pub txn_id: String,
    #[clap(long, short = 'o')]
    pub kms_operation: KmsOperation,
}

#[derive(Debug, Parser)]
pub enum Command {
    PreprocKeyGen(Nothing),
    KeyGen(KeyGenExecute),
    InsecureKeyGen(Nothing),
    Decrypt(CryptExecute),
    ReEncrypt(CryptExecute),
    QueryContract(Query),
    CrsGen(Nothing),
    Zkp(ZkpExecute),
    DoNothing(Nothing),
}

#[derive(Debug, Parser)]
pub struct Config {
    #[clap(long, short = 'f')]
    pub file_conf: Option<String>,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder)]
pub struct KmsConfig {
    pub contract_address: String,
    pub mnemonic: String,
    pub address: String,
    pub key_id: String,
    pub mode: KmsMode,
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
// Plaintext being in another crate we wrap it here to implement dereferencing
struct PlaintextWrapper(Plaintext);

impl Deref for PlaintextWrapper {
    type Target = Plaintext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PlaintextWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<PlaintextWrapper> for Token {
    type Error = String;

    fn try_from(ptxt: PlaintextWrapper) -> Result<Self, Self::Error> {
        let fhe_type: FheType = FheType::from_str_name(ptxt.fhe_type().as_str_name());
        let res = match fhe_type {
            FheType::Ebool => ptxt.as_bool().to_token(),
            FheType::Euint4 => ptxt.as_u4().to_token(),
            FheType::Euint8 => ptxt.as_u8().to_token(),
            FheType::Euint16 => ptxt.as_u16().to_token(),
            FheType::Euint32 => ptxt.as_u32().to_token(),
            FheType::Euint64 => ptxt.as_u64().to_token(),
            FheType::Euint128 => ptxt.as_u128().to_token(),
            FheType::Euint160 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u160().copy_to_be_byte_slice(cake.as_mut_slice());
                ethers::types::Address::from_slice(&cake[12..]).to_token()
            }
            FheType::Euint256 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u256().copy_to_be_byte_slice(cake.as_mut_slice());
                U256::from_big_endian(&cake).to_token()
            }
            FheType::Euint512 => {
                todo!("Implement Euint512")
            }
            FheType::Euint1024 => {
                todo!("Implement Euint1024")
            }
            FheType::Euint2048 => {
                let mut cake = vec![0u8; 256];
                ptxt.as_u2048().copy_to_be_byte_slice(cake.as_mut_slice());
                let token = Token::Bytes(cake);
                tracing::info!(
                    "🍰 Euint2048 Token: {:#?}, ",
                    hex::encode(
                        token
                            .clone()
                            .into_bytes()
                            .expect("Token resulted in None bytes.")
                    )
                );
                token
            }
            FheType::Unknown => return Err("Invalid ciphertext type".to_string()),
        };
        Ok(res)
    }
}

fn get_latest_deployed_contract_address(
    validator_tcp_endpoint: &str,
) -> Result<String, anyhow::Error> {
    // Get list of deployed contracts
    // TODO: make sure that when more than 100 contracts are deployed (pagination limit)
    // the function still works fine
    // TODO: Double check that this works properly: for some reason it didn't find the contract
    let output = std::process::Command::new("wasmd")
        .args([
            "query",
            "wasm",
            "list-code",
            "--output",
            "json",
            "--node",
            validator_tcp_endpoint,
        ])
        .output()?;

    // Parse the JSON output
    let json: Value = serde_json::from_slice(&output.stdout)?;

    // Extract the last code ID
    let code_infos = json["code_infos"].as_array().expect("Empty code info");
    let last_code_id = code_infos.last().expect("Empty code infos")["code_id"]
        .as_str()
        .expect("code id is none");

    tracing::info!("Last Code ID: {}", last_code_id);

    // Execute the second command with the last code ID
    let contract_list_output = std::process::Command::new("wasmd")
        .args([
            "query",
            "wasm",
            "list-contract-by-code",
            last_code_id,
            "--output",
            "json",
            "--node",
            validator_tcp_endpoint,
        ])
        .output()?;

    // Parse the JSON output of the second command
    let contract_list_json: Value = serde_json::from_slice(&contract_list_output.stdout)?;

    tracing::info!("{:?}", contract_list_json);

    // Extract the last contract address
    let contracts = contract_list_json["contracts"]
        .as_array()
        .expect("Contracts list is empty.");
    if let Some(last_contract) = contracts.last() {
        let contract_address = last_contract.as_str().expect("last contact is none");
        tracing::info!("Last Contract Address: {}", contract_address);
        Ok(contract_address.to_string())
    } else {
        tracing::error!("No contracts found for the last code ID");
        Err(anyhow!("No contracts found for the last code ID"))
    }
}

pub fn to_event(event: &cosmos_proto::messages::tendermint::abci::Event) -> Event {
    let mut result = Event::new(event.r#type.clone());
    for attribute in event.attributes.iter() {
        let key = attribute.key.clone();
        let value = attribute.value.clone();
        result = result.add_attribute(key, value);
    }
    result
}

#[retrying::retry(stop=(attempts(5)|duration(30)),wait=fixed(1))]
async fn wait_for_transaction(
    responders: Arc<DashMap<TransactionId, oneshot::Sender<KmsEvent>>>,
    txn_id: &TransactionId,
) -> Result<KmsEvent, anyhow::Error> {
    let (tx, rx) = oneshot::channel();
    tracing::info!("🤠🤠🤠 Waiting for transaction: {:?}", txn_id);
    responders.insert(txn_id.clone(), tx);
    rx.await.map_err(|e| anyhow::anyhow!(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub async fn encrypt_and_prove(
    to_encrypt: u8,
    domain: &Eip712Domain,
    contract_address: &alloy_primitives::Address,
    acl_address: &alloy_primitives::Address,
    client_address: &alloy_primitives::Address,
    crs_id: &str,
    key_id: &str,
    keys_folder: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
    let metadata = assemble_metadata_alloy(
        contract_address,
        client_address,
        acl_address,
        &domain.chain_id.unwrap(),
    );

    tracing::info!(
        "attempting to create zkp using materials from {:?}",
        keys_folder
    );
    let msgs = vec![TypedPlaintext::U8(to_encrypt)];
    Ok(compute_zkp_from_stored_key_and_serialize(
        Some(keys_folder),
        msgs,
        key_id,
        crs_id,
        &metadata,
    )
    .await)
}

pub async fn encrypt(
    to_encrypt: u8,
    key_id: &str,
    keys_folder: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
    let typed_to_encrypt = TypedPlaintext::U8(to_encrypt);

    let ptxt = typed_to_encrypt.to_plaintext();
    let fhe_type: FheType = FheType::from_str_name(ptxt.fhe_type().as_str_name());
    tracing::info!("FheType: {:#?}", fhe_type);
    let res = match fhe_type {
        FheType::Ebool => ptxt.as_bool().to_token(),
        FheType::Euint4 => ptxt.as_u4().to_token(),
        FheType::Euint8 => ptxt.as_u8().to_token(),
        FheType::Euint16 => ptxt.as_u16().to_token(),
        FheType::Euint32 => ptxt.as_u32().to_token(),
        FheType::Euint64 => ptxt.as_u64().to_token(),
        FheType::Euint128 => ptxt.as_u128().to_token(),
        FheType::Euint160 => {
            let mut cake = vec![0u8; 32];
            ptxt.as_u160().copy_to_be_byte_slice(cake.as_mut_slice());
            ethers::types::Address::from_slice(&cake[12..]).to_token()
        }
        FheType::Euint256 => {
            let mut cake = vec![0u8; 32];
            ptxt.as_u256().copy_to_be_byte_slice(cake.as_mut_slice());
            U256::from_big_endian(&cake).to_token()
        }
        FheType::Euint512 => {
            todo!("Implement Euint512")
        }
        FheType::Euint1024 => {
            todo!("Implement Euint1024")
        }
        FheType::Euint2048 => {
            let mut cake = vec![0u8; 256];
            ptxt.as_u2048().copy_to_be_byte_slice(cake.as_mut_slice());
            let token = Token::Bytes(cake);
            tracing::info!(
                "🍰 Euint2048 Token: {:#?}, ",
                hex::encode(
                    token
                        .clone()
                        .into_bytes()
                        .expect("Token resulted in empty bytes.")
                )
            );
            token
        }
        FheType::Unknown => {
            todo!("Implement Unknown")
        }
    };
    tracing::info!(
        "Starting plaintext: {:?}, {:?}, {:?}, {:?}",
        res,
        ptxt,
        fhe_type,
        typed_to_encrypt
    );

    let (cipher, _) =
        compute_compressed_cipher_from_stored_key(Some(keys_folder), typed_to_encrypt, key_id)
            .await;
    Ok(cipher)
}

pub async fn store_cipher(
    cipher: &Vec<u8>,
    kv_store_address: &String,
) -> Result<String, anyhow::Error> {
    let response = reqwest::Client::new()
        .post(format!("{}/store", kv_store_address))
        .body(hex::encode(cipher))
        .send()
        .await;

    match response {
        Ok(result) => {
            if result.status() != 200 {
                return Err(anyhow!(
                    "Failed to store ciphertext {}",
                    result.text().await?
                ));
            }
            let handle = result.text().await?;
            Ok(handle)
        }
        Err(error) => Err(anyhow!("Failed to store ciphertext: {}", error)),
    }
}

async fn execute_contract(
    client: &Client,
    query_client: &QueryClient,
    value: OperationValue,
) -> anyhow::Result<Vec<KmsEvent>> {
    let request = ExecuteContractRequest::builder()
        .message(KmsMessage::builder().value(value).build())
        .gas_limit(3_100_000)
        .funds(vec![ProtoCoin::builder()
            // Arbitrary value -> how do we get the proper value the first time?
            .amount(64_000_000)
            .denom("ucosm".to_string())
            .build()])
        .build();

    let response = client.execute_contract(request).await?;

    let resp;
    const MAX_ITER: u64 = 20;
    let mut counter: u64 = 0;
    loop {
        tracing::info!("Querying client for tx hash: {:?}...", response.txhash);
        let query_response = query_client.query_tx(response.txhash.clone()).await?;
        if let Some(qr) = query_response {
            resp = qr;
            break;
        } else {
            tracing::info!("Waiting 1 second for transaction to be included in a block.");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            if counter == MAX_ITER {
                return Err(anyhow::anyhow!(
                    "Max-iteration ({}) reached waiting for transaction to be included in a block",
                    MAX_ITER,
                ));
            }
        }
        counter += 1;
    }

    tracing::info!("Filtering events");
    resp.events
        .iter()
        .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
        .map(to_event)
        .map(<Event as TryInto<KmsEvent>>::try_into)
        .collect::<Result<Vec<KmsEvent>, _>>()
}

pub async fn execute_crsgen_contract(
    client: &Client,
    query_client: &QueryClient,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    let crsgen_value = OperationValue::CrsGen(CrsGenValues {});

    let evs = execute_contract(client, query_client, crsgen_value).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_insecure_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    let insecure_keygen_value = OperationValue::InsecureKeyGen(InsecureKeyGenValues {});

    let evs = execute_contract(client, query_client, insecure_keygen_value).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_preproc_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    let preproc_value = OperationValue::KeyGenPreproc(KeyGenPreprocValues {});

    let evs = execute_contract(client, query_client, preproc_value).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
    preproc_id: HexVector,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    // TODO we need to first do a pre-processing execute
    let keygen_value = OperationValue::KeyGen(KeyGenValues::new(preproc_id));

    let evs = execute_contract(client, query_client, keygen_value).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_zkp_contract(
    client: &Client,
    query_client: &QueryClient,
    to_encrypt: u8,
    crs_id: &str,
    key_id: &str,
    keys_folder: &Path,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    // These are some random addresses used to create a valid input/zk request
    let verifying_contract = alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657");
    let contract_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
    let acl_address = alloy_primitives::address!("01da6bf26964af9d7eed9e03e53415d37aa960ff");
    let client_address = alloy_primitives::address!("b5d85CBf7cB3EE0D56b3bB207D5Fc4B82f43F511");

    let dummy_domain = alloy_sol_types::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: verifying_contract,
    );

    let proven_ct = encrypt_and_prove(
        to_encrypt,
        &dummy_domain,
        &contract_address,
        &acl_address,
        &client_address,
        crs_id,
        key_id,
        keys_folder,
    )
    .await?;

    let kv_store_address = client
        .kv_store_address
        .clone()
        .expect("KV-Store address is None.");
    let handle = store_cipher(&proven_ct, &kv_store_address).await?;
    tracing::info!("📦 Stored ciphertext, handle: {}", handle);
    let handle_bytes = hex::decode(handle)?;

    let zkp_value = OperationValue::Zkp(ZkpValues::new(
        hex::decode(crs_id)?,
        hex::decode(key_id)?,
        contract_address.to_string(),
        client_address.to_string(),
        handle_bytes,
        acl_address.to_string(),
        dummy_domain.name.unwrap().to_string(),
        dummy_domain.version.unwrap().to_string(),
        dummy_domain.chain_id.unwrap().to_be_bytes_vec(),
        dummy_domain.verifying_contract.unwrap().to_string(),
        vec![],
    ));

    let evs = execute_contract(client, query_client, zkp_value).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_decryption_contract(
    to_encrypt: u8,
    client: &Client,
    query_client: &QueryClient,
    key_id: &str,
    keys_folder: &Path,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    let cipher = encrypt(to_encrypt, key_id, keys_folder).await?;
    let kv_store_address = client
        .kv_store_address
        .clone()
        .expect("KV-Store address is None.");
    let handle = store_cipher(&cipher, &kv_store_address).await?;
    tracing::info!("📦 Stored ciphertext, handle: {}", handle);
    let handle_bytes = hex::decode(handle)?;

    let value = OperationValue::Decrypt(DecryptValues::new(
        hex::decode(key_id)?,
        vec![handle_bytes.clone()],
        vec![FheType::Euint8],
        Some(vec![vec![5_u8; 32]]),
        1,
        "0xFFda6bf26964af9D7eed9e03e53415D37Aa960ee".to_string(),
        "eip712name".to_string(),
        "version".to_string(),
        vec![6; 32],
        "0x00dA6BF26964af9D7EED9e03E53415d37aa960EE".to_string(),
        vec![],
    ));

    let evs = execute_contract(client, query_client, value).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn query_contract(
    sim_config: &SimulatorConfig,
    query: Query,
    query_client: &QueryClient,
) -> Result<Vec<Plaintext>, Box<dyn std::error::Error + 'static>> {
    let txn_id = HexVector::from_hex(&query.txn_id)?;
    let ev = KmsEvent::builder()
        .operation(query.kms_operation)
        .txn_id(txn_id)
        .build();

    tracing::info!("contract address: {:?}", sim_config.contract);
    let query_req = ContractQuery::GetOperationsValue(EventQuery::builder().event(ev).build());
    let request = QueryContractRequest::builder()
        .contract_address(sim_config.contract.clone())
        .query(query_req)
        .build();
    let value: Vec<OperationValue> = query_client.query_contract(request).await?;

    let mut results = Vec::new();
    for x in value.iter() {
        match x {
            OperationValue::DecryptResponse(decrypt) => {
                let payload: DecryptionResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(decrypt.payload()).as_slice(),
                )?;
                for (idx, pt) in payload.plaintexts.iter().enumerate() {
                    let actual_pt: Plaintext = deserialize(pt)?;
                    results.push(actual_pt.clone());
                    tracing::info!(
                        "Decrypt Result #{idx}: Plaintext Decrypted = {:?}.",
                        actual_pt
                    );
                    tracing::info!(
                        "Decrypt Result: Plaintext Decrypted {:?} {:?}",
                        actual_pt,
                        actual_pt.as_u8(), // We know that we have u8 here but we should automatically
                                           // detect it
                    );
                }
            }
            OperationValue::InsecureKeyGenResponse(response) => {
                tracing::info!(
                    "Received InsecureKeyGenResponse with request ID {}, pk digest {}, pk signature {}, server key digest {}, server key signature {}",
                    response.request_id().to_hex(),
                    response.public_key_digest(),
                    response.public_key_signature().to_hex(),
                    response.server_key_digest(),
                    response.server_key_signature().to_hex(),
                );
            }
            OperationValue::CrsGenResponse(response) => {
                tracing::info!(
                    "Received CrsGenResponse with request ID {}, digest {} and signature {}",
                    response.request_id(),
                    response.digest(),
                    response.signature().to_hex(),
                );
            }
            _ => tracing::info!("Got response {:?} but it's not handled", x),
        };
    }

    Ok(results)
}

pub fn cosmos_to_eth_address(cosmos_address: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Decode the bech32 address
    let (_, data, _) = bech32::decode(cosmos_address)?;
    let decoded = Vec::<u8>::from_base32(&data)?;
    if decoded.len() != 20 {
        return Err("Unexpected decoded length".into());
    }
    // Take the last 20 bytes
    let eth_address = format!("0x{}", hex::encode(decoded));

    Ok(eth_address)
}

fn join_vars(args: &[&str]) -> String {
    args.iter()
        .filter(|&s| !s.is_empty())
        .cloned()
        .collect::<Vec<&str>>()
        .join("/")
}

// TODO: handle auth
// TODO: add option to either use local  key or remote key
pub async fn fetch_key(
    endpoint: &str,
    folder: &str,
    key_id: &str,
) -> Result<Bytes, Box<dyn std::error::Error + 'static>> {
    let object_key = key_id.to_string();
    // Construct the URL
    let url = join_vars(&[endpoint, folder, object_key.as_str()]);

    // If URL we fetch it
    if url.starts_with("http") {
        // Make the request
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await?;

        if response.status().is_success() {
            let bytes = response.bytes().await?;
            tracing::info!("Successfully downloaded {} bytes", bytes.len());
            // Here you can process the bytes as needed
            Ok(bytes)
        } else {
            let response_status = response.status();
            let response_content = response.text().await?;
            tracing::error!("Error: {}", response_status);
            tracing::error!("Response: {}", response_content);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Couldn't fetch key from endpoint\nStatus: {}\nResponse: {}",
                    response_status, response_content
                ),
            )))
        }
    } else {
        let key_path = Path::new(endpoint).join(key_id);
        match fs::read(&key_path) {
            Ok(content) => Ok(Bytes::from(content)),
            Err(..) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Couldn't fetch key from file\n{:?}", key_path,),
            ))),
        }
    }
}

pub fn write_bytes_to_file(folder_path: &Path, filename: &str, data: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(folder_path)?;
    let path = std::path::absolute(folder_path.join(filename))?;
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

pub async fn call_faucet(
    faucet_url: &str,
    wallet_address: &str,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    let mut map = HashMap::new();
    map.insert("denom", "ucosm");
    map.insert("address", wallet_address);
    map.insert("body", "json");
    let response = reqwest::Client::new()
        .post(format!("{}/credit", faucet_url))
        .json(&map)
        .send()
        .await;

    match response {
        Ok(result) => match result.status().as_u16() {
            200 => Ok(()),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Call to faucet failed:\n{}", result.text().await?),
            ))),
        },
        Err(err) => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Call to faucet failed\n{}", err),
        ))),
    }
}

pub fn setup_logging() {
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "simulator.log");
    let file_and_stdout = file_appender.and(std::io::stdout);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(file_and_stdout)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
}

async fn check_contract(
    node_url: &str,
    contract_address: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Returns true if the contract can be found in-chain, else false
    let client = reqwest::Client::new();

    // Construct the ABCI query
    let query_path = "store/wasm/key".to_string();
    let query_data = hex::encode(contract_address.as_bytes());

    // Prepare the request body
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "abci_query",
        "params": {
            "path": query_path,
            "data": query_data,
            "prove": false
        }
    });

    // Send the request
    let response: Value = client
        .post(node_url)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    tracing::info!("Response: {:?}", response);

    // Check if the contract exists
    let result = response["result"]["response"]["value"].as_str();

    Ok(result.is_some() && !result.expect("Result is None").is_empty())
}

// TODO: Incompatible with "latest" in the configuration
// make it compatible and update the configuration accordingly
pub async fn wait_for_contract_to_be_deployed(
    node_url: &str,
    contract_address: &str,
    max_retries: u64,
    time_to_wait: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    for retry_index in 0..max_retries {
        match check_contract(node_url, contract_address).await {
            Ok(_) => {
                tracing::info!("Contract {:?} found", contract_address);
                return Ok(());
            }
            Err(error) => {
                if retry_index > max_retries {
                    return Err(error);
                }
                tracing::info!("{:?}", error);
            }
        }
        tracing::info!("Waiting {:?} for contract to be deployed", time_to_wait);
        tokio::time::sleep(time_to_wait).await;
    }

    Err("Timeout waiting for contract to be deployed".into())
}

async fn fetch_key_and_write_to_file(
    destination_prefix: &Path,
    sim_conf: &SimulatorConfig,
    name: &str,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    // Fetch pub-key from storage and dump it for later use
    // TODO: handle local file
    let key_id = if name == "CRS" {
        &sim_conf.crs_id
    } else {
        &sim_conf.key_id
    };

    let folder = destination_prefix.join("PUB").join(name);
    let content = fetch_key(
        &sim_conf.s3_endpoint,
        &format!("{}/{}", sim_conf.key_folder, name),
        key_id,
    )
    .await?;
    let _ = write_bytes_to_file(&folder, key_id, content.as_ref());
    Ok(())
}

pub async fn main_from_config(
    path_to_config: &str,
    command: &Command,
    destination_prefix: &Path,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    tracing::info!("starting command: {:?}", command);
    let sim_conf: SimulatorConfig = Settings::builder()
        .path(path_to_config)
        .env_prefix("SIMULATOR")
        .build()
        .init_conf()?;

    fetch_key_and_write_to_file(destination_prefix, &sim_conf, "PublicKey").await?;
    fetch_key_and_write_to_file(destination_prefix, &sim_conf, "PublicKeyMetadata").await?;
    fetch_key_and_write_to_file(destination_prefix, &sim_conf, "ServerKey").await?;
    fetch_key_and_write_to_file(destination_prefix, &sim_conf, "CRS").await?;
    // fetch_key_and_write_to_file(destination_prefix, &sim_conf, "VerfAddress").await?;
    // fetch_key_and_write_to_file(destination_prefix, &sim_conf, "VerfKey").await?;

    // Build KMS Client
    let validator_addresses = sim_conf
        .validator_addresses
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<&str>>();

    let client: Client = ClientBuilder::builder()
        .kv_store_address(Some(sim_conf.kv_store_address.as_str()))
        .grpc_addresses(validator_addresses.clone())
        .contract_address(&sim_conf.contract)
        .mnemonic_wallet(Some(&sim_conf.mnemonic.clone()))
        .build()
        .try_into()?;

    // TODO: merge both clients
    let query_client: QueryClient = QueryClientBuilder::builder()
        .grpc_addresses(validator_addresses.clone())
        .build()
        .try_into()?;

    wait_for_contract_to_be_deployed(
        sim_conf.http_validator_endpoints[0].as_str(),
        &sim_conf.contract,
        120,
        std::time::Duration::from_secs(1),
    )
    .await?;

    // Log account address
    let cosmwasm_address = client.get_account_address()?;
    tracing::info!("Client address (cosm): {:?}", cosmwasm_address);
    let eth_format_address = cosmos_to_eth_address(&cosmwasm_address)?;
    tracing::info!("Client address (eth): {:?}", eth_format_address);
    let account = client.query_account().await;
    tracing::info!("{:?}", account);

    // Log wallet amount before doing anything
    let wallet_amount_before = client.get_wallet_amount(None).await?;
    tracing::info!("Wallet amount: {:}", wallet_amount_before);

    // TODO: stop here if insufficient gas and/or query faucet if setup
    // TODO: add optional faucet configuration in config file

    // Launch command
    // TODO: adding re-encryption support
    let mut max_iter = 10;
    // Execute the proper command
    let kms_event: anyhow::Result<Option<KmsEvent>> = match command {
        Command::Decrypt(ex) => Ok(Some(
            execute_decryption_contract(
                ex.to_encrypt,
                &client,
                &query_client,
                &sim_conf.key_id,
                destination_prefix,
            )
            .await?,
        )),
        Command::QueryContract(q) => {
            let query_result = query_contract(&sim_conf, q.clone(), &query_client).await?;
            tracing::info!("Query result: {:?}", query_result);
            Ok(None)
        }
        Command::DoNothing(Nothing {}) => {
            tracing::info!("Nothing to do.");
            Ok(None)
        }
        Command::PreprocKeyGen(Nothing {}) => Ok(Some(
            execute_preproc_keygen_contract(&client, &query_client).await?,
        )),
        Command::KeyGen(ex) => {
            let preproc_id = HexVector::from_hex(&ex.preproc_id)?;
            Ok(Some(
                execute_keygen_contract(&client, &query_client, preproc_id).await?,
            ))
        }
        Command::InsecureKeyGen(Nothing {}) => Ok(Some(
            execute_insecure_keygen_contract(&client, &query_client).await?,
        )),
        Command::CrsGen(Nothing {}) => {
            // the actual CRS ceremony takes time
            max_iter = 20;
            Ok(Some(execute_crsgen_contract(&client, &query_client).await?))
        }
        Command::Zkp(ZkpExecute {
            to_encrypt,
            crs_id,
            key_id,
        }) => Ok(Some({
            let crs_id = crs_id.as_ref().unwrap_or(&sim_conf.crs_id);
            let key_id = key_id.as_ref().unwrap_or(&sim_conf.key_id);
            execute_zkp_contract(
                &client,
                &query_client,
                *to_encrypt,
                crs_id,
                key_id,
                destination_prefix,
            )
            .await?
        })),
        _ => Err(anyhow!("Command: {:?} not supported yet", command)),
    };
    let kms_event = kms_event?;

    // If needed we wait for the response
    let time_to_wait = 10; // in seconds
    if let Some(event) = kms_event {
        tracing::info!("Event operation: {:?}", event.operation);
        // Only execute contract results is an event not being None
        // in this case we wait for the decryption response
        let q = Query {
            txn_id: event.txn_id.to_hex(),
            kms_operation: event.operation.to_response()?,
        };
        for n in 1..=max_iter {
            // TODO: add check that the value is the same as the expected one
            // TODO: this is only valid for a decryption response, it should be more generic
            match query_contract(&sim_conf, q.clone(), &query_client).await {
                Ok(results) => {
                    tracing::info!("Results: {:?}", results);
                    break;
                }
                Err(e) => {
                    tracing::info!(
                        "Got error \"{e}\", waiting {time_to_wait} seconds for the response to be posted to the blockchain.",
                    );
                    std::thread::sleep(std::time::Duration::from_secs(time_to_wait));
                }
            }

            // Max-iter reached
            if n == max_iter {
                return Err(anyhow!(
                    "Never reached the response for command {:?} using config {}.",
                    command,
                    path_to_config
                )
                .into());
            }
        }
    }

    // Check wallet amount after operations
    let wallet_amount_after = client.get_wallet_amount(None).await?;
    tracing::info!("Wallet amount: {:}", wallet_amount_after);
    tracing::info!(
        "The whole operation costed: {:}",
        wallet_amount_before - wallet_amount_after
    );
    Ok(())
}
