/// Simulator library
///
/// This library implements most functionnalities to interact with a KMS ASC.
/// This library also includes an associated CLI.
use aes_prng::AesRng;
use alloy_signer::{Signature, SignerSync};
use alloy_sol_types::{Eip712Domain, SolStruct};
use anyhow::anyhow;
use bech32::{self, FromBase32};
use bytes::Bytes;
use clap::Parser;
use conf_trace::conf::Settings;
use core::str;
use cosmwasm_std::Event;
use dashmap::DashMap;
use ethers::abi::Token;
use ethers::types::{Address, U256};
use events::kms::{
    CrsGenValues, DecryptValues, Eip712Values, FheType, InsecureKeyGenValues, KeyGenPreprocValues,
    KeyGenValues, KmsCoreConf, KmsEvent, KmsMessage, KmsOperation, OperationValue, ReencryptValues,
    TransactionId, VerifyProvenCtValues,
};
use events::HexVector;
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest, ProtoCoin};
use kms_blockchain_client::query_client::{
    ContractQuery, EventQuery, QueryClient, QueryClientBuilder, QueryContractRequest,
};
use kms_lib::client::{assemble_metadata_alloy, ParsedReencryptionRequest};
use kms_lib::consts::{DEFAULT_PARAM, SIGNING_KEY_ID, TEST_PARAM};
use kms_lib::cryptography::central_kms::gen_sig_keys;
use kms_lib::cryptography::internal_crypto_types::{PrivateEncKey, PublicEncKey, PublicSigKey};
use kms_lib::cryptography::signcryption::{
    ephemeral_encryption_key_generation, hash_element, Reencrypt,
};
use kms_lib::kms::{
    DecryptionResponsePayload, Eip712DomainMsg, ReencryptionResponse, ReencryptionResponsePayload,
};
use kms_lib::rpc::rpc_types::{
    compute_external_pubdata_message_hash, compute_pt_message_hash, protobuf_to_alloy_domain,
    Plaintext, PubDataType,
};
use kms_lib::storage::{FileStorage, StorageReader, StorageType};
use kms_lib::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, compute_compressed_cipher_from_stored_key,
    compute_proven_ct_from_stored_key_and_serialize, TypedPlaintext,
};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Once;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumString};
use tfhe::named::Named;
use tfhe::Versionize;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use typed_builder::TypedBuilder;

// TODO: remove hard coded values -> should be either cli arguments or configuration
const EIP712_NAME: &str = "eip712_name";
const EIP712_VERSION: &str = "1.0.4";
const EIP712_CONTRACT: &str = "0x00dA6BF26964af9D7EED9e03E53415d37aa960EE";
static EIP712_CHAIN_ID: &[u8] = &[
    42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
static EIP712_SALT: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

#[derive(Serialize, Clone, Default, Debug)]
pub struct SimulatorConfig {
    /// S3 endpoint from which to fetch keys
    /// NOTE: We should probably move away from that and use the key-url
    pub s3_endpoint: Option<String>,
    /// Key folder where to store the keys
    pub object_folder: Vec<String>,
    /// Validator addresses (only one supported for now)
    pub validator_addresses: Vec<String>,
    /// HTTP validator endpoint (length should match)
    pub http_validator_endpoints: Vec<String>,
    /// Key-value store endpoint
    pub kv_store_address: String,
    /// ASC contract address
    pub contract: String,
    /// Mnemonic of the user wallet to use
    pub mnemonic: String,
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
            pub s3_endpoint: Option<String>,
            pub object_folder: Vec<String>,
            pub validator_addresses: Vec<String>,
            pub http_validator_endpoints: Vec<String>,
            pub kv_store_address: String,
            pub contract: String,
            pub mnemonic: String,
        }

        let temp = SimulatorConfigBuffer::deserialize(deserializer)?;

        let contract_address =
            parse_contract_address(&temp.contract, &temp.http_validator_endpoints[0])
                .unwrap_or_default();

        Ok(SimulatorConfig {
            s3_endpoint: temp.s3_endpoint,
            object_folder: temp.object_folder,
            validator_addresses: temp.validator_addresses,
            http_validator_endpoints: temp.http_validator_endpoints,
            kv_store_address: temp.kv_store_address,
            contract: contract_address,
            mnemonic: temp.mnemonic,
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
pub struct NoParameters {}

#[derive(Debug, Parser)]
pub struct CipherParameters {
    /// Value to encrypt for later re-encryption/decryption
    #[clap(long, short = 'e')]
    pub to_encrypt: u8,
    /// Flag to activate ciphertext compression
    #[clap(long, short = 'c', default_value_t = false)]
    pub compressed: bool,
    /// CRS identifier to use
    #[clap(long, short = 'r')]
    pub crs_id: String,
    /// Key identifier to use for decryption/re-encryption purposes
    #[clap(long, short = 'k')]
    pub key_id: String,
}

#[derive(Debug, Parser)]
pub struct KeyGenParameters {
    #[clap(long, short = 'i')]
    pub preproc_id: String,
}

#[derive(Debug, Parser)]
pub struct CrsParameters {
    #[clap(long, short = 'm')]
    pub max_num_bits: u32,
}

#[derive(Debug, Parser)]
pub struct VerifyProvenCtParameters {
    #[clap(long, short = 'e')]
    pub to_encrypt: u8,
    pub crs_id: String,
    pub key_id: String,
}

#[derive(Debug, Parser, Clone)]
pub struct Query {
    #[clap(long, short = 't')]
    pub txn_id: String,
    #[clap(long, short = 'o')]
    pub kms_operation: KmsOperation,
}

#[derive(Debug, Parser)]
pub struct GetFundsParameters {
    /// Faucet address
    pub faucet_address: String,
}

#[derive(Debug, Parser)]
pub enum SimulatorCommand {
    PreprocKeyGen(NoParameters),
    GetFunds(GetFundsParameters),
    KeyGen(KeyGenParameters),
    InsecureKeyGen(NoParameters),
    Decrypt(CipherParameters),
    ReEncrypt(CipherParameters),
    QueryContract(Query),
    CrsGen(CrsParameters),
    VerifyProvenCt(VerifyProvenCtParameters),
    DoNothing(NoParameters),
}

#[derive(Debug, Parser)]
pub struct Config {
    #[clap(long, short = 'f')]
    pub file_conf: Option<String>,
    #[clap(subcommand)]
    pub command: SimulatorCommand,
    // TODO: expose a log-level instead
    #[clap(long, short = 'l')]
    pub logs: bool,
    #[clap(long, default_value = "20")]
    pub max_iter: u64,
    #[clap(long, short = 'a', default_value_t = false)]
    pub expect_all_responses: bool,
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
        "attempting to create proven ct using materials from {:?}",
        keys_folder
    );
    let msgs = vec![TypedPlaintext::U8(to_encrypt)];
    Ok(compute_proven_ct_from_stored_key_and_serialize(
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
    compressed: Option<bool>,
) -> Result<(Vec<u8>, Plaintext), Box<dyn std::error::Error + 'static>> {
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

    tracing::debug!(
        "attempting to create ct using materials from {:?}",
        keys_folder
    );

    let cipher: Vec<u8>;
    if compressed.unwrap_or(false) {
        (cipher, _) =
            compute_compressed_cipher_from_stored_key(Some(keys_folder), typed_to_encrypt, key_id)
                .await;
    } else {
        (cipher, _) =
            compute_cipher_from_stored_key(Some(keys_folder), typed_to_encrypt, key_id).await;
    }

    Ok((cipher, ptxt))
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
    max_iter: Option<u64>,
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

    let max_iter: u64 = max_iter.unwrap_or(20);
    let resp;
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
            if counter == max_iter {
                return Err(anyhow::anyhow!(
                    "Max-iteration ({}) reached waiting for transaction to be included in a block",
                    max_iter,
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
    max_amount_of_bits: u32,
) -> Result<(KmsEvent, CrsGenValues), Box<dyn std::error::Error + 'static>> {
    let cv = CrsGenValues::new(
        max_amount_of_bits,
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        EIP712_CHAIN_ID.to_vec(),
        EIP712_CONTRACT.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?;

    let evs = execute_contract(
        client,
        query_client,
        OperationValue::CrsGen(cv.clone()),
        None,
    )
    .await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, cv))
}

pub async fn execute_insecure_key_gen_contract(
    client: &Client,
    query_client: &QueryClient,
) -> Result<(KmsEvent, InsecureKeyGenValues), Box<dyn std::error::Error + 'static>> {
    let ikv = InsecureKeyGenValues::new(
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        EIP712_CHAIN_ID.to_vec(),
        EIP712_CONTRACT.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?;

    let insecure_key_gen_value = OperationValue::InsecureKeyGen(ikv.clone());

    let evs = execute_contract(client, query_client, insecure_key_gen_value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, ikv))
}

pub async fn execute_preproc_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    let preproc_value = OperationValue::KeyGenPreproc(KeyGenPreprocValues {});

    let evs = execute_contract(client, query_client, preproc_value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
    preproc_id: HexVector,
) -> Result<(KmsEvent, KeyGenValues), Box<dyn std::error::Error + 'static>> {
    // TODO we need to first do a pre-processing execute
    let kv = KeyGenValues::new(
        preproc_id,
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        EIP712_CHAIN_ID.to_vec(),
        EIP712_CONTRACT.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?;
    let keygen_value = OperationValue::KeyGen(kv.clone());

    let evs = execute_contract(client, query_client, keygen_value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, kv))
}

pub async fn execute_verify_proven_ct_contract(
    client: &Client,
    query_client: &QueryClient,
    to_encrypt: u8,
    crs_id: &str,
    key_id: &str,
    keys_folder: &Path,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    // These are some random addresses used to create a valid verify proven ciphertext request
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

    let value = OperationValue::VerifyProvenCt(VerifyProvenCtValues::new(
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
        Some(EIP712_SALT.to_vec()),
    )?);

    let evs = execute_contract(client, query_client, value, None).await?;
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
    compressed: Option<bool>,
) -> Result<(KmsEvent, Plaintext, DecryptValues), Box<dyn std::error::Error + 'static>> {
    let (cipher, ptxt) = encrypt(to_encrypt, key_id, keys_folder, compressed).await?;
    let kv_store_address = client
        .kv_store_address
        .clone()
        .expect("KV-Store address is None.");
    let handle = store_cipher(&cipher, &kv_store_address).await?;
    tracing::info!("📦 Stored ciphertext, handle: {}", handle);
    let handle_bytes = hex::decode(handle)?;

    let dv = DecryptValues::new(
        hex::decode(key_id)?,
        vec![handle_bytes.clone()],
        vec![FheType::Euint8],
        Some(vec![vec![5_u8; 32]]),
        1,
        "0xFFda6bf26964af9D7eed9e03e53415D37Aa960ee".to_string(),
        "some_proof".to_string(),
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        EIP712_CHAIN_ID.to_vec(),
        EIP712_CONTRACT.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?;

    let evs = execute_contract(
        client,
        query_client,
        OperationValue::Decrypt(dv.clone()),
        None,
    )
    .await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, ptxt, dv))
}

pub async fn execute_reencryption_contract(
    to_encrypt: u8,
    client: &Client,
    query_client: &QueryClient,
    key_id: &str,
    keys_folder: &Path,
    kms_core_conf: KmsCoreConf,
    compressed: Option<bool>,
) -> Result<
    (
        KmsEvent,
        Plaintext,
        ParsedReencryptionRequest,
        kms_lib::client::Client,
        Eip712Domain,
        PublicEncKey,
        PrivateEncKey,
    ),
    Box<dyn std::error::Error + 'static>,
> {
    //NOTE: I(Titouan) believe we don't really even care
    //given how we'll use the client
    let params = match kms_core_conf.param_choice() {
        events::kms::FheParameter::Default => DEFAULT_PARAM,
        events::kms::FheParameter::Test => TEST_PARAM,
    };

    let dummy_external_ciphertext_handle = vec![0_u8, 32];
    let (cipher, ptxt) = encrypt(to_encrypt, key_id, keys_folder, compressed).await?;
    let kv_store_address = client
        .kv_store_address
        .clone()
        .expect("KV-Store address is None.");
    let handle = store_cipher(&cipher, &kv_store_address).await?;
    tracing::info!("📦 Stored ciphertext, handle: {}", handle);
    let handle_bytes = hex::decode(handle)?;

    //Client address needs to be a alloy_primitives::Address
    // Generate a new wallet with a random private key
    let (sig_pk, sig_sk) = gen_sig_keys(&mut AesRng::seed_from_u64(1));
    let client_address = alloy_primitives::Address::from_public_key(sig_pk.pk());

    //enc_key needs to be a bincode serialized PublicEncKey, which is
    //a wrapper around a crypto_box::PublicKey
    let (enc_pk, enc_sk) = ephemeral_encryption_key_generation(&mut AesRng::seed_from_u64(1));
    let serialized_enc_key = bincode::serialize(&enc_pk).unwrap();

    //signature is an alloy_primitives::Signature on Eip Domain and encryption key
    //using client address as public key
    let acl_addres = "acl_address".to_string();
    let eip712_verifying_contract =
        alloy_primitives::Address::from_str("0000000000000000000000000000000000000111").unwrap();
    let chain_id = alloy_primitives::U256::try_from_be_slice(&[6]).unwrap();

    let domain = alloy_sol_types::Eip712Domain::new(
        Some(EIP712_NAME.into()),
        Some(EIP712_VERSION.into()),
        Some(chain_id),
        Some(eip712_verifying_contract),
        Some(alloy_primitives::FixedBytes::from_slice(EIP712_SALT)),
    );

    let message = Reencrypt {
        publicKey: alloy_primitives::Bytes::copy_from_slice(&serialized_enc_key),
    };

    let message_hash = message.eip712_signing_hash(&domain);
    let signer = alloy_signer_local::PrivateKeySigner::from_signing_key(sig_sk.sk().clone());

    let signature = signer.sign_hash_sync(&message_hash).unwrap();

    //ciphertext digest is SHA3 of the ctxt
    let ciphertext_digest = hash_element(&cipher);

    let value = OperationValue::Reencrypt(ReencryptValues::new(
        signature.as_bytes().to_vec(),
        1,
        client_address.to_checksum(None),
        serialized_enc_key.clone(),
        FheType::Euint8,
        hex::decode(key_id)?,
        dummy_external_ciphertext_handle,
        handle_bytes,
        ciphertext_digest.clone(),
        acl_addres,
        "some_proof".to_string(),
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        chain_id.to_be_bytes::<32>().to_vec(),
        eip712_verifying_contract.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?);

    //Also create a copy of the request for reconstruction later on
    let parsed_request = ParsedReencryptionRequest::new(
        signature,
        client_address,
        serialized_enc_key,
        ciphertext_digest,
        eip712_verifying_contract,
    );

    // Finally, create a kms-core client for reconstruction later on.
    // NOTE: The wasm code that deals with reencryption on the browser side
    // also uses the client.
    let verf_keys = if kms_core_conf.is_centralized() {
        let storage = FileStorage::new_centralized(Some(keys_folder), StorageType::PUB).unwrap();
        let url = storage
            .compute_url(
                &SIGNING_KEY_ID.to_string().to_lowercase(),
                &PubDataType::VerfKey.to_string(),
            )
            .unwrap();
        tracing::info!("{:?}", url);
        let verf_key: PublicSigKey = storage.read_data(&url).await.unwrap();
        vec![verf_key]
    } else {
        let num_kms_parties = kms_core_conf.parties.len();
        let mut res = Vec::new();
        for i in 1..=num_kms_parties {
            let storage =
                FileStorage::new_threshold(Some(keys_folder), StorageType::PUB, i).unwrap();
            let url = storage
                .compute_url(
                    &SIGNING_KEY_ID.to_string().to_lowercase(),
                    &PubDataType::VerfKey.to_string(),
                )
                .unwrap();
            let verf_key: PublicSigKey = match storage.read_data(&url).await {
                Ok(key) => key,
                Err(e) => panic!("Error reading file at {}: {}", url, e),
            };
            res.push(verf_key);
        }
        res
    };

    let mut kms_client =
        kms_lib::client::Client::new(verf_keys, client_address, Some(sig_sk), params);
    kms_client.convert_to_addresses();

    let evs = execute_contract(client, query_client, value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, ptxt, parsed_request, kms_client, domain, enc_pk, enc_sk))
}

pub async fn query_contract(
    sim_config: &SimulatorConfig,
    query: Query,
    query_client: &QueryClient,
) -> Result<Vec<OperationValue>, Box<dyn std::error::Error + 'static>> {
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
    let values: Vec<OperationValue> = query_client.query_contract(request).await?;
    Ok(values)
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
pub async fn fetch_object(
    endpoint: &str,
    folder: &str,
    object_id: &str,
) -> Result<Bytes, Box<dyn std::error::Error + 'static>> {
    let object_key = object_id.to_string();
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
        let key_path = Path::new(endpoint).join(folder).join(object_id);
        match fs::read(&key_path) {
            Ok(content) => Ok(Bytes::from(content)),
            Err(error) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Couldn't fetch key from file {:?} from error: {:?}",
                    key_path, error
                ),
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

static INIT: Once = Once::new();

pub fn init_logging() {
    INIT.call_once(setup_logging)
}

pub fn setup_logging() {
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "simulator.log");
    let file_and_stdout = file_appender.and(std::io::stdout);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(file_and_stdout)
        .with_ansi(false)
        .json()
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

/// This fetches material which is global
/// i.e. everything related to CRS and FHE public materials
async fn fetch_global_key_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    object_id: &str,
    object_name: &str,
    object_folder: &str,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    // Fetch pub-key from storage and dump it for later use
    let folder = destination_prefix.join("PUB").join(object_name);
    let content = fetch_object(
        s3_endpoint,
        &format!("{}/{}", object_folder, object_name),
        object_id,
    )
    .await?;
    let _ = write_bytes_to_file(&folder, object_id, content.as_ref());
    Ok(())
}

/// This fetches material which is local
/// i.e. everything related to parties verification keys
async fn fetch_local_key_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    object_id: &str,
    object_name: &str,
    object_folder: &[String],
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    // Fetch pub-key from storage and dump it for later use
    if object_folder.len() == 1 {
        fetch_global_key_and_write_to_file(
            destination_prefix,
            s3_endpoint,
            object_id,
            object_name,
            object_folder.first().unwrap(),
        )
        .await
    } else {
        for (party_idx, folder_name) in object_folder.iter().enumerate() {
            let folder = destination_prefix
                .join(format!("PUB-p{}", party_idx + 1))
                .join(object_name);
            let content = fetch_object(
                s3_endpoint,
                &format!("{}/{}", folder_name, object_name),
                object_id,
            )
            .await?;
            let _ = write_bytes_to_file(&folder, object_id, content.as_ref());
        }
        Ok(())
    }
}

/// This fetches the kms ethereum address from local storage
async fn fetch_kms_addresses(
    sim_conf: &SimulatorConfig,
    kms_core_conf: &KmsCoreConf,
) -> Result<Vec<alloy_primitives::Address>, Box<dyn std::error::Error + 'static>> {
    // TODO: handle local file
    let key_id = &SIGNING_KEY_ID.to_string();

    let mut addr_bytes = Vec::new();
    if kms_core_conf.is_centralized() {
        let content = fetch_object(
            &sim_conf
                .s3_endpoint
                .clone()
                .expect("s3 endpoint should be provided"),
            &format!(
                "{}/{}",
                sim_conf.object_folder.first().unwrap(),
                "VerfAddress"
            ),
            key_id,
        )
        .await?;
        addr_bytes.push(content);
    } else {
        for folder_name in sim_conf.object_folder.iter() {
            let content = fetch_object(
                &sim_conf
                    .s3_endpoint
                    .clone()
                    .expect("s3 endpoint should be provided"),
                &format!("{}/{}", folder_name, "VerfAddress"),
                key_id,
            )
            .await?;
            addr_bytes.push(content);
        }
    }

    // turn bytes read into Address type
    let kms_addrs: Vec<_> = addr_bytes
        .iter()
        .map(|x| {
            alloy_primitives::Address::from_str(str::from_utf8(x).unwrap_or_else(|_| {
                panic!("cannot convert address bytes into UTF-8 string: {:?}", x)
            }))
            .unwrap_or_else(|_| panic!("invalid ethereum address: {:?}", x))
        })
        .collect();

    Ok(kms_addrs)
}

async fn wait_for_response(
    event: KmsEvent,
    query_client: &QueryClient,
    sim_conf: &SimulatorConfig,
    max_iter: u64,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<OperationValue>> {
    let time_to_wait = 10; // in seconds
    tracing::info!("Event operation: {:?}", event.operation);
    let q = Query {
        txn_id: event.txn_id.to_hex(),
        kms_operation: event.operation.to_response()?,
    };
    for _ in 1..=max_iter {
        match query_contract(sim_conf, q.clone(), query_client).await {
            Ok(results) => {
                if results.len() != num_expected_responses {
                    tracing::info!(
                    "Got {} responses, but expecting {}. Waiting {time_to_wait} seconds for the other responses to be posted to the blockchain.", results.len(), num_expected_responses,
                );
                    std::thread::sleep(std::time::Duration::from_secs(time_to_wait));
                } else {
                    tracing::info!("Results: {:?}", results);
                    return Ok(results);
                }
            }
            Err(e) => {
                tracing::info!(
                    "Got error \"{e}\", waiting {time_to_wait} seconds for the response to be posted to the blockchain.",
                );
                std::thread::sleep(std::time::Duration::from_secs(time_to_wait));
            }
        }
    }
    Err(anyhow!(
        "Never reached the response for operation {:?}.",
        event.operation
    ))
}

/// check that the external signature on the CRS or pubkey is valid
fn _check_ext_pubdata_signature<D: Serialize + Versionize + Named>(
    data: &D,
    external_sig: &[u8],
    vals: impl Eip712Values,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // this reverses the call to `signature.as_bytes()` that we use for serialization
    let sig = Signature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0)?;

    let edm = Eip712DomainMsg {
        name: vals.eip712_name().to_string(),
        version: vals.eip712_version().to_string(),
        chain_id: vals.eip712_chain_id().into(),
        verifying_contract: vals.eip712_verifying_contract().to_string(),
        salt: vals.eip712_salt().map(|v| v.0.to_owned()),
    };
    let domain = protobuf_to_alloy_domain(&edm)?;

    tracing::debug!("ext. signature bytes: {:x?}", external_sig);
    tracing::debug!("ext. signature: {:?}", sig);
    tracing::debug!("EIP-712 domain: {:?}", domain);

    let hash = compute_external_pubdata_message_hash(data, &domain)?;

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("reconstructed address: {}", addr);

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!(
            "External crs/pubkey signature verification failed!"
        ))
    }
}

/// check that the external signature on the decryption result(s) is valid
fn check_ext_pt_signature(
    external_sig: &[u8],
    pts: Vec<Vec<u8>>,
    decrypt_vals: &DecryptValues,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // this reverses the call to `signature.as_bytes()` that we use for serialization
    let sig = Signature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0)?;

    let edm = Eip712DomainMsg {
        name: decrypt_vals.eip712_name().to_string(),
        version: decrypt_vals.eip712_version().to_string(),
        chain_id: decrypt_vals.eip712_chain_id().into(),
        verifying_contract: decrypt_vals.eip712_verifying_contract().to_string(),
        salt: decrypt_vals.eip712_salt().map(|v| v.0.to_owned()),
    };
    let domain = protobuf_to_alloy_domain(&edm)?;

    let acl_address = alloy_primitives::Address::from_str(decrypt_vals.acl_address())?;
    let plaintexts: Vec<Plaintext> = pts
        .iter()
        .map(|pt| bincode::deserialize::<Plaintext>(pt))
        .collect::<Result<Vec<_>, _>>()?;

    // unpack the HexVectorList
    let external_handles = match decrypt_vals.external_handles() {
        Some(hex_list) => hex_list
            .0
            .iter()
            .map(|hex_vector| Some(hex_vector.0.clone())) // Convert each HexVector to Some(Vec<u8>)
            .collect(),
        None => Vec::new(), // If it's None, return an empty Vec
    };

    tracing::debug!("ext. signature bytes: {:x?}", external_sig);
    tracing::debug!("ext. signature: {:?}", sig);
    tracing::debug!("EIP-712 domain: {:?}", domain);
    tracing::debug!("ACL addres: {:?}", acl_address);
    tracing::debug!("PTs: {:?}", plaintexts);
    tracing::debug!("ext. handles: {:?}", external_handles);

    let hash = compute_pt_message_hash(external_handles, &plaintexts, domain, acl_address);

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("reconstructed address: {}", addr);

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!("External PT signature verification failed!"))
    }
}

fn process_decrypt_responses(
    responses: Vec<OperationValue>, // one response per party
    expected_answer: Plaintext,
    request: DecryptValues,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for x in responses.into_iter() {
        match x {
            OperationValue::DecryptResponse(decrypt) => {
                let payload: DecryptionResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(decrypt.payload()).as_slice(),
                )?;

                check_ext_pt_signature(
                    payload.external_signature(),
                    payload.plaintexts.clone(),
                    &request,
                    kms_addrs,
                )?;

                for (idx, pt) in payload.plaintexts.iter().enumerate() {
                    let actual_pt: Plaintext = bincode::deserialize(pt)?;
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
            _ => {
                tracing::error!("Found something else than DecryptResponse in decryption pipeline.")
            }
        }
    }

    for result in results {
        //For now we only support euint8
        debug_assert_eq!(expected_answer.fhe_type(), kms_lib::kms::FheType::Euint8);
        assert_eq!(expected_answer.fhe_type(), result.fhe_type());
        assert_eq!(expected_answer.as_u8(), result.as_u8());
    }

    tracing::info!("Decryption response successfully processed.");
    Ok(())
}

fn process_reencrypt_responses(
    responses: Vec<OperationValue>,
    expected_answer: Plaintext,
    request: ParsedReencryptionRequest,
    kms_client: kms_lib::client::Client,
    domain: Eip712Domain,
    enc_pk: PublicEncKey,
    enc_sk: PrivateEncKey,
) -> anyhow::Result<()> {
    tracing::info!("Found {} responses!", responses.len());
    let mut reenc_responses: Vec<ReencryptionResponse> = Vec::new();
    for response in responses {
        if let OperationValue::ReencryptResponse(resp) = response {
            let payload: ReencryptionResponsePayload = bincode::deserialize(
                <&HexVector as Into<Vec<u8>>>::into(resp.payload()).as_slice(),
            )?;
            let signature = resp.signature().0.clone();

            reenc_responses.push(ReencryptionResponse {
                signature,
                payload: Some(payload),
            });
        }
    }

    let result = kms_client.process_reencryption_resp(
        &request,
        &domain,
        &reenc_responses,
        &enc_pk,
        &enc_sk,
    )?;

    tracing::info!("Reconstructed {:?}", result);

    //For now we only support euint8
    debug_assert_eq!(expected_answer.fhe_type(), kms_lib::kms::FheType::Euint8);
    assert_eq!(expected_answer.fhe_type(), result.fhe_type());
    assert_eq!(expected_answer.as_u8(), result.as_u8());

    Ok(())
}

pub async fn main_from_config(
    path_to_config: &str,
    command: &SimulatorCommand,
    destination_prefix: &Path,
    max_iter: Option<u64>,
    expect_all_responses: bool,
) -> Result<Option<Vec<OperationValue>>, Box<dyn std::error::Error + 'static>> {
    tracing::info!("Path to config: {:?}", path_to_config);
    tracing::info!("starting command: {:?}", command);
    let sim_conf: SimulatorConfig = Settings::builder()
        .path(path_to_config)
        .env_prefix("SIMULATOR")
        .build()
        .init_conf()?;

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

    tracing::info!("Client address: {}", client.contract_address.to_string());
    tracing::info!("Contract address: {}", sim_conf.contract);

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

    //Retrieve params from ASC
    let request = QueryContractRequest::builder()
        .contract_address(client.contract_address.to_string())
        .query(ContractQuery::GetKmsCoreConf {})
        .build();
    let kms_core_conf: KmsCoreConf = query_client.query_contract(request).await?;
    if !kms_core_conf.is_conformant() {
        return Err(anyhow!("Kms Core configuration is not conformant!").into());
    }

    let mut return_value: Option<Vec<OperationValue>> = None;
    match command {
        SimulatorCommand::Decrypt(cipher_params) | SimulatorCommand::ReEncrypt(cipher_params) => {
            // Fetch all objects associated with TFHE keys
            for object_name in ["PublicKey", "PublicKeyMetadata", "ServerKey"] {
                fetch_global_key_and_write_to_file(
                    destination_prefix,
                    sim_conf
                        .s3_endpoint
                        .clone()
                        .expect("S3 endpoint should be provided")
                        .as_str(),
                    &cipher_params.key_id,
                    object_name,
                    sim_conf.object_folder.first().unwrap(),
                )
                .await?;
            }

            // Fetch objects associated with Signature keys
            for object_name in ["VerfAddress", "VerfKey"] {
                fetch_local_key_and_write_to_file(
                    destination_prefix,
                    sim_conf
                        .s3_endpoint
                        .clone()
                        .expect("S3 endpoint should be provided")
                        .as_str(),
                    &SIGNING_KEY_ID.to_string(),
                    object_name,
                    &sim_conf.object_folder,
                )
                .await?;
            }

            // Fetch CRS
            fetch_global_key_and_write_to_file(
                destination_prefix,
                sim_conf
                    .s3_endpoint
                    .clone()
                    .expect("S3 endpoint should be provided")
                    .as_str(),
                &cipher_params.crs_id,
                "CRS",
                sim_conf.object_folder.first().unwrap(),
            )
            .await?;
        }
        _ => {}
    }

    let kms_addrs = fetch_kms_addresses(&sim_conf, &kms_core_conf).await?;

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

    let max_iter = max_iter.unwrap_or(20);
    let num_parties = kms_core_conf.parties.len();

    // Execute the proper command
    match command {
        SimulatorCommand::Decrypt(cipher_params) => {
            let (event, ptxt, decrypt_values) = execute_decryption_contract(
                cipher_params.to_encrypt,
                &client,
                &query_client,
                &cipher_params.key_id,
                destination_prefix,
                Some(cipher_params.compressed),
            )
            .await?;
            return_value = Some(
                wait_for_response(
                    event,
                    &query_client,
                    &sim_conf,
                    max_iter,
                    if expect_all_responses {
                        num_parties
                    } else {
                        kms_core_conf.response_count_for_majority_vote()
                    },
                )
                .await?,
            );
            process_decrypt_responses(
                return_value
                    .clone()
                    .expect("Return value of decryption shouldn't be None"),
                ptxt,
                decrypt_values,
                &kms_addrs,
            )
            .unwrap();
        }
        SimulatorCommand::ReEncrypt(cipher_params) => {
            let (event, ptxt, request, kms_client, domain, enc_pk, enc_sk) =
                execute_reencryption_contract(
                    cipher_params.to_encrypt,
                    &client,
                    &query_client,
                    &cipher_params.key_id,
                    destination_prefix,
                    kms_core_conf.clone(),
                    Some(cipher_params.compressed),
                )
                .await?;
            return_value = Some(
                wait_for_response(
                    event,
                    &query_client,
                    &sim_conf,
                    max_iter,
                    if expect_all_responses {
                        num_parties
                    } else {
                        kms_core_conf.response_count_for_reconstruction()
                    },
                )
                .await?,
            );
            process_reencrypt_responses(
                return_value
                    .clone()
                    .expect("Return value of re-encryption shouldn't be None"),
                ptxt,
                request,
                kms_client,
                domain,
                enc_pk,
                enc_sk,
            )
            .unwrap();
        }

        SimulatorCommand::PreprocKeyGen(NoParameters {}) => {
            unimplemented!(
                "We only support InsecureKeyGen for now, thus no preprocessing required."
            )
            //let event = execute_preproc_keygen_contract(&client, &query_client).await?;
            ////Do nothing with the response (for now ?)
            //let _responses = wait_for_response(event, &query_client, &sim_conf, max_iter).await?;
        }
        SimulatorCommand::KeyGen(_ex) => {
            unimplemented!("We only support InsecureKeyGen for now.")
            //let preproc_id = HexVector::from_hex(&ex.preproc_id)?;
            //let event = execute_keygen_contract(&client, &query_client, preproc_id).await?;
            ////Do nothing with the response (for now ?)
            //let _responses = wait_for_response(event, &query_client, &sim_conf, max_iter).await?;
        }
        SimulatorCommand::InsecureKeyGen(NoParameters {}) => {
            let (event, _insecure_keygen_vals) =
                execute_insecure_key_gen_contract(&client, &query_client).await?;
            let responses = wait_for_response(
                event,
                &query_client,
                &sim_conf,
                max_iter,
                if expect_all_responses {
                    num_parties
                } else {
                    kms_core_conf.response_count_for_majority_vote()
                },
            )
            .await?;
            return_value = Some(responses.clone());
            for response in responses {
                if let OperationValue::KeyGenResponse(response) = &response {
                    tracing::info!(
                            "Received KeyGenResponse with request ID {}, pk digest {}, pk signature {}, server key digest {}, server key signature {}",
                            response.request_id().to_hex(),
                            response.public_key_digest(),
                            response.public_key_signature().to_hex(),
                            response.server_key_digest(),
                            response.server_key_signature().to_hex(),
                        );

                    // TODO fetch generated public key and corresponding key info (containing external signature)

                    // TODO verify external signature
                    // check_ext_pubdata_signature(
                    //     pubkey,
                    //     pk_info.external_signature,
                    //     &insecure_keygen_vals,
                    //     &kms_addrs,
                    // )?;
                } else {
                    panic!("Receive response {:?} during InsecureKeyGen", response)
                }
            }
        }
        SimulatorCommand::CrsGen(CrsParameters { max_num_bits }) => {
            // the actual CRS ceremony takes time
            let (event, _crs_values) =
                execute_crsgen_contract(&client, &query_client, *max_num_bits).await?;
            let responses = wait_for_response(
                event,
                &query_client,
                &sim_conf,
                max_iter,
                if expect_all_responses {
                    num_parties
                } else {
                    kms_core_conf.response_count_for_majority_vote()
                },
            )
            .await?;
            return_value = Some(responses.clone());

            for response in responses {
                if let OperationValue::CrsGenResponse(response) = &response {
                    tracing::info!(
                        "Received CrsGenResponse with request ID {}, digest {} and signature {}",
                        response.request_id(),
                        response.digest(),
                        response.signature().to_hex(),
                    );

                    //TODO fetch CRS and CRS-info (containing external signature)

                    // TODO verify external signature
                    // check_ext_pubdata_signature(
                    //     crs,
                    //     crs_info.external_signature,
                    //     &crs_vals,
                    //     &kms_addrs,
                    // )?;
                } else {
                    panic!("Receive response {:?} during CrsGen", response)
                }
            }
        }
        SimulatorCommand::VerifyProvenCt(VerifyProvenCtParameters {
            to_encrypt,
            crs_id,
            key_id,
        }) => {
            let event = execute_verify_proven_ct_contract(
                &client,
                &query_client,
                *to_encrypt,
                crs_id,
                key_id,
                destination_prefix,
            )
            .await?;
            //Do nothing with the response (for now ?)
            return_value = Some(
                wait_for_response(
                    event,
                    &query_client,
                    &sim_conf,
                    max_iter,
                    if expect_all_responses {
                        num_parties
                    } else {
                        kms_core_conf.response_count_for_majority_vote()
                    },
                )
                .await?,
            );
        }
        SimulatorCommand::QueryContract(q) => {
            return_value = Some(query_contract(&sim_conf, q.clone(), &query_client).await?);
            // tracing::info!("Query result: {:?}", return_value);
        }
        SimulatorCommand::GetFunds(faucet_params) => {
            call_faucet(
                faucet_params.faucet_address.as_str(),
                &client.get_account_address()?,
            )
            .await?;
        }
        SimulatorCommand::DoNothing(NoParameters {}) => {
            tracing::info!("Nothing to do.");
        }
    };

    // Check wallet amount after operations
    let wallet_amount_after = client.get_wallet_amount(None).await?;
    tracing::info!("Wallet amount: {:}", wallet_amount_after);
    tracing::info!(
        "The whole operation costed: {:}",
        wallet_amount_before - wallet_amount_after
    );

    Ok(return_value)
}
