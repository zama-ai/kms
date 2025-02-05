/// Simulator library
///
/// This library implements most functionnalities to interact with a KMS ASC.
/// This library also includes an associated CLI.
use aes_prng::AesRng;
use alloy_primitives::PrimitiveSignature;
use alloy_signer::SignerSync;
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
    CrsGenValues, DecryptValues, Eip712Values, FheParameter, FheType, InsecureCrsGenValues,
    InsecureKeyGenValues, KeyGenPreprocValues, KeyGenValues, KmsEvent, KmsMessage, KmsOperation,
    OperationValue, ReencryptValues, TransactionId, VerifyProvenCtValues,
};
use events::HexVector;
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest, ProtoCoin};
use kms_blockchain_client::query_client::{
    AscQuery, CscQuery, EventQuery, QueryClient, QueryClientBuilder,
};
use kms_common::{retry_loop, DecryptionMode};
use kms_grpc::kms::v1::{
    DecryptionResponsePayload, Eip712DomainMsg, ReencryptionResponse, ReencryptionResponsePayload,
    TypedPlaintext,
};
use kms_grpc::rpc_types::{
    hash_element, protobuf_to_alloy_domain, PubDataType, Reencrypt, SIGNING_KEY_ID,
};
use kms_lib::client::{assemble_metadata_alloy, ParsedReencryptionRequest};
use kms_lib::consts::{DEFAULT_PARAM, TEST_PARAM};
use kms_lib::cryptography::internal_crypto_types::{PrivateEncKey, PublicEncKey, PublicSigKey};
use kms_lib::cryptography::signcryption::ephemeral_encryption_key_generation;
use kms_lib::engine::base::{
    compute_external_pubdata_message_hash, compute_pt_message_hash, gen_sig_keys,
};
use kms_lib::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, compute_compressed_cipher_from_stored_key,
    compute_proven_ct_from_stored_key_and_serialize, load_crs_from_storage, load_pk_from_storage,
    load_server_key_from_storage, TestingPlaintext,
};
use kms_lib::vault::storage::{file::FileStorage, StorageReader, StorageType};
use rand::SeedableRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
    /// Address of the ASC
    pub asc_address: String,
    /// Mnemonic of the user wallet to use
    pub mnemonic: String,
    /// Address of the CSC
    pub csc_address: String,
    /// The decryption mode used for reencryption reconstruction in threshold mode
    pub decryption_mode: Option<DecryptionMode>,
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
            pub asc_address: String,
            pub mnemonic: String,
            pub csc_address: String,
            pub decryption_mode: Option<DecryptionMode>,
        }

        let temp = SimulatorConfigBuffer::deserialize(deserializer)?;

        let asc_address =
            parse_contract_address(&temp.asc_address, &temp.http_validator_endpoints[0])
                .unwrap_or_default();

        Ok(SimulatorConfig {
            s3_endpoint: temp.s3_endpoint,
            object_folder: temp.object_folder,
            validator_addresses: temp.validator_addresses,
            http_validator_endpoints: temp.http_validator_endpoints,
            kv_store_address: temp.kv_store_address,
            asc_address,
            mnemonic: temp.mnemonic,
            csc_address: temp.csc_address,
            decryption_mode: temp.decryption_mode,
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

/// Parse a string as hex string. The string can optionally start with "0x". Odd-length strings will be padded with a leading zero.
pub fn parse_hex(arg: &str) -> anyhow::Result<Vec<u8>> {
    // Remove "0x" or "0X" prefix if present
    let arg = arg.strip_prefix("0x").unwrap_or(arg);
    let hex_str = arg.strip_prefix("0X").unwrap_or(arg);

    // Handle odd-length hex strings by padding with leading zero
    let hex_str = if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    Ok(hex::decode(hex_str)?)
}

#[derive(Debug, Parser)]
pub struct CipherParameters {
    /// Value that we want to encrypt and request a decryption/re-encryption.
    /// The value will be converted from a little endian hex string to a `Vec<u8>`.
    #[clap(long, short = 'e')]
    pub to_encrypt: String,
    /// Data type of `to_encrypt`.
    /// Expected one of ebool, euint4, ..., euint2048
    #[clap(long, short = 'd')]
    pub data_type: FheType,
    /// Boolean to activate ciphertext compression or not.
    #[clap(long, short = 'p', default_value_t = false)]
    pub compressed: bool,
    /// CRS identifier to use
    #[clap(long, short = 'c')]
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
    /// Value that we want to encrypt and request a decryption/re-encryption.
    /// The value will be converted from a little endian hex string to a `Vec<u8>`.
    #[clap(long, short = 'e')]
    pub to_encrypt: String,
    /// Data type of `to_encrypt`.
    /// Expected one of ebool, euint4, ..., euint2048
    #[clap(long, short = 'd')]
    pub data_type: FheType,
    /// CRS identifier to use
    #[clap(long, short = 'c')]
    pub crs_id: String,
    /// Key identifier to use for decryption/re-encryption purposes
    #[clap(long, short = 'k')]
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
    InsecureCrsGen(CrsParameters),
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
    #[clap(long, default_value = "200")]
    pub max_iter: u64,
    #[clap(long, short = 'a', default_value_t = false)]
    pub expect_all_responses: bool,
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
struct PlaintextWrapper(TypedPlaintext);

impl Deref for PlaintextWrapper {
    type Target = TypedPlaintext;

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
        let fhe_type: FheType = FheType::from(ptxt.fhe_type());
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
                let mut cake = vec![0u8; 64];
                ptxt.as_u512().copy_to_be_byte_slice(cake.as_mut_slice());
                let token = Token::Bytes(cake);
                tracing::info!(
                    "🍰 Euint512 Token: {:#?}, ",
                    hex::encode(
                        token
                            .clone()
                            .into_bytes()
                            .expect("Token resulted in None bytes.")
                    )
                );
                token
            }
            FheType::Euint1024 => {
                let mut cake = vec![0u8; 128];
                ptxt.as_u1024().copy_to_be_byte_slice(cake.as_mut_slice());
                let token = Token::Bytes(cake);
                tracing::info!(
                    "🍰 Euint1024 Token: {:#?}, ",
                    hex::encode(
                        token
                            .clone()
                            .into_bytes()
                            .expect("Token resulted in None bytes.")
                    )
                );
                token
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

pub struct DecryptionParams<'a> {
    to_encrypt: Vec<u8>,
    data_type: FheType,
    key_id: &'a str,
    keys_folder: &'a Path,
    compressed: Option<bool>,
}

pub struct VerifyProvenCtParams<'a> {
    to_encrypt: Vec<u8>,
    data_type: FheType,
    crs_id: &'a str,
    key_id: &'a str,
    keys_folder: &'a Path,
}

pub struct ReencryptionParams<'a> {
    ct_config: CiphertextConfig,
    key_id: &'a str,
    keys_folder: &'a Path,
    fhe_parameter: FheParameter,
    num_parties: usize,
    decryption_mode: Option<DecryptionMode>,
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

#[allow(dead_code, clippy::assign_op_pattern)]
async fn wait_for_transaction(
    responders: Arc<DashMap<TransactionId, oneshot::Sender<KmsEvent>>>,
    txn_id: &TransactionId,
) -> Result<KmsEvent, anyhow::Error> {
    retry_loop!(
        || async {
            let (tx, rx) = oneshot::channel();
            tracing::info!("🤠🤠🤠 Waiting for transaction: {:?}", txn_id);
            responders.insert(txn_id.clone(), tx);
            rx.await.map_err(|e| anyhow::anyhow!(e.to_string()))
        },
        1000,
        5
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn encrypt_and_prove(
    to_encrypt: Vec<u8>,
    data_type: FheType,
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

    let msgs = vec![TestingPlaintext::from(TypedPlaintext {
        bytes: to_encrypt,
        fhe_type: data_type as i32,
    })];

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
    to_encrypt: Vec<u8>,
    fhe_type: FheType,
    key_id: &str,
    keys_folder: &Path,
    compressed: Option<bool>,
) -> Result<(Vec<u8>, TypedPlaintext), Box<dyn std::error::Error + 'static>> {
    if to_encrypt.len() != fhe_type.bits().div_ceil(8) {
        tracing::warn!("Byte length of value to encrypt ({}) does not match FHE type ({}) and will be padded/truncated.", to_encrypt.len(), fhe_type);
    }

    let ptxt = TypedPlaintext {
        bytes: to_encrypt,
        fhe_type: fhe_type as i32,
    };

    let typed_to_encrypt = TestingPlaintext::from(ptxt.clone());

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
            let mut cake = vec![0u8; 64];
            ptxt.as_u512().copy_to_be_byte_slice(cake.as_mut_slice());
            let token = Token::Bytes(cake);
            tracing::info!(
                "🍰 Euint512 Token: {:#?}, ",
                hex::encode(
                    token
                        .clone()
                        .into_bytes()
                        .expect("Token resulted in empty bytes.")
                )
            );
            token
        }
        FheType::Euint1024 => {
            let mut cake = vec![0u8; 128];
            ptxt.as_u1024().copy_to_be_byte_slice(cake.as_mut_slice());
            let token = Token::Bytes(cake);
            tracing::info!(
                "🍰 Euint1024 Token: {:#?}, ",
                hex::encode(
                    token
                        .clone()
                        .into_bytes()
                        .expect("Token resulted in empty bytes.")
                )
            );
            token
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
            panic!("Unknown FheType to encrypt")
        }
    };
    tracing::info!(
        "Encrypting plaintext: {:?}, {:?}, {:?}, {:?}",
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
    contract_address: String,
    value: OperationValue,
    max_iter: Option<u64>,
) -> anyhow::Result<Vec<KmsEvent>> {
    let request = ExecuteContractRequest::builder()
        .contract_address(contract_address)
        .message(KmsMessage::builder().value(value).build())
        .gas_limit(3_100_000)
        .funds(vec![ProtoCoin::builder()
            // Arbitrary value -> how do we get the proper value the first time?
            .amount(64_000_000)
            .denom("ucosm".to_string())
            .build()])
        .build();

    let response = client.execute_contract(request).await?;
    let resp: Result<_, anyhow::Error> = retry_loop!(
        || async {
            tracing::info!("Querying client for tx hash: {:?}...", response.txhash);
            let query_response = query_client.query_tx(response.txhash.clone()).await?;
            if let Some(qr) = query_response {
                anyhow::Ok(qr)
            } else {
                let msg = ("Waiting for transaction to be included in a block").to_string();
                tracing::info!(msg);
                Err(anyhow::anyhow!(msg))
            }
        },
        1000,                   // Sleep for 1 second
        max_iter.unwrap_or(30)  // Try at most 30 times
    );

    tracing::info!("Filtering events");
    resp?
        .events
        .iter()
        .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
        .map(to_event)
        .map(<Event as TryInto<KmsEvent>>::try_into)
        .collect::<Result<Vec<KmsEvent>, _>>()
}

pub async fn execute_crsgen_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
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
        asc_address,
        OperationValue::CrsGen(cv.clone()),
        None,
    )
    .await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, cv))
}

pub async fn execute_insecure_crsgen_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
    max_amount_of_bits: u32,
) -> Result<(KmsEvent, InsecureCrsGenValues), Box<dyn std::error::Error + 'static>> {
    let cv = InsecureCrsGenValues::new(
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
        asc_address,
        OperationValue::InsecureCrsGen(cv.clone()),
        None,
    )
    .await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, cv))
}

pub async fn execute_insecure_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
) -> Result<(KmsEvent, InsecureKeyGenValues), Box<dyn std::error::Error + 'static>> {
    let ikv = InsecureKeyGenValues::new(
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        EIP712_CHAIN_ID.to_vec(),
        EIP712_CONTRACT.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?;

    let insecure_key_gen_value = OperationValue::InsecureKeyGen(ikv.clone());

    let evs = execute_contract(
        client,
        query_client,
        asc_address,
        insecure_key_gen_value,
        None,
    )
    .await?;
    let ev = evs[0].clone();

    tracing::info!("InsecureKeyGen TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, ikv))
}

pub async fn execute_preproc_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    let preproc_value = OperationValue::KeyGenPreproc(KeyGenPreprocValues {});

    let evs = execute_contract(client, query_client, asc_address, preproc_value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("Preproc TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_keygen_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
    preproc_id: HexVector,
) -> Result<(KmsEvent, KeyGenValues), Box<dyn std::error::Error + 'static>> {
    let kv = KeyGenValues::new(
        preproc_id,
        EIP712_NAME.to_string(),
        EIP712_VERSION.to_string(),
        EIP712_CHAIN_ID.to_vec(),
        EIP712_CONTRACT.to_string(),
        Some(EIP712_SALT.to_vec()),
    )?;
    let keygen_value = OperationValue::KeyGen(kv.clone());

    let evs = execute_contract(client, query_client, asc_address, keygen_value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("KeyGen TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, kv))
}

pub async fn execute_verify_proven_ct_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
    verify_proven_ct_params: VerifyProvenCtParams<'_>,
) -> Result<KmsEvent, Box<dyn std::error::Error + 'static>> {
    // These are some random addresses used to create a valid verify proven ciphertext request
    let verifying_contract = alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657");
    let contract_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
    let acl_address = alloy_primitives::address!("01da6bf26964af9d7eed9e03e53415d37aa960ff");
    let client_address = alloy_primitives::address!("b5d85CBf7cB3EE0D56b3bB207D5Fc4B82f43F511");
    let VerifyProvenCtParams {
        to_encrypt,
        data_type,
        crs_id,
        key_id,
        keys_folder,
    } = verify_proven_ct_params;
    let dummy_domain = alloy_sol_types::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: verifying_contract,
    );

    let proven_ct = encrypt_and_prove(
        to_encrypt,
        data_type,
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

    let evs = execute_contract(client, query_client, asc_address, value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok(ev)
}

pub async fn execute_decryption_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
    decryption_params: DecryptionParams<'_>,
) -> Result<(KmsEvent, TypedPlaintext, DecryptValues), Box<dyn std::error::Error + 'static>> {
    let DecryptionParams {
        to_encrypt,
        data_type,
        key_id,
        keys_folder,
        compressed,
    } = decryption_params;
    let (cipher, ptxt) = encrypt(to_encrypt, data_type, key_id, keys_folder, compressed).await?;
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
        vec![data_type],
        Some(vec![vec![5_u8; 32]]),
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
        asc_address,
        OperationValue::Decrypt(dv.clone()),
        None,
    )
    .await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, ptxt, dv))
}

pub struct CiphertextConfig {
    pub clear_value: Vec<u8>,
    pub data_type: FheType,
    pub compressed: Option<bool>,
}

pub async fn execute_reencryption_contract(
    client: &Client,
    query_client: &QueryClient,
    asc_address: String,
    reencryption_params: ReencryptionParams<'_>,
) -> Result<
    (
        KmsEvent,
        TypedPlaintext,
        ParsedReencryptionRequest,
        kms_lib::client::Client,
        Eip712Domain,
        PublicEncKey,
        PrivateEncKey,
    ),
    Box<dyn std::error::Error + 'static>,
> {
    let ReencryptionParams {
        ct_config,
        key_id,
        keys_folder,
        fhe_parameter,
        num_parties,
        decryption_mode,
    } = reencryption_params;
    //NOTE: I(Titouan) believe we don't really even care
    //given how we'll use the client
    let params = match fhe_parameter {
        events::kms::FheParameter::Default => DEFAULT_PARAM,
        events::kms::FheParameter::Test => TEST_PARAM,
    };

    // TODO(1968)
    tracing::info!(
        "[1968] reenc sim ct_config: {:?}, {:?}, {:?}",
        hex::encode(&ct_config.clear_value),
        ct_config.data_type,
        ct_config.compressed,
    );

    let (cipher, ptxt) = encrypt(
        ct_config.clear_value,
        ct_config.data_type,
        key_id,
        keys_folder,
        ct_config.compressed,
    )
    .await?;

    // TODO(1968)
    tracing::info!(
        "[1968] reenc sim ct: {:?}, ptxt bytes: {:?}, ptxt type: {:?}",
        hex::encode(&cipher),
        hex::encode(&ptxt.bytes),
        ptxt.fhe_type,
    );

    let dummy_external_ciphertext_handle = vec![0_u8, 32];
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

    // TODO(1968)
    tracing::info!(
        "[1968] reenc sim enc_pk {enc_pk:?}, in bytes: {}",
        hex::encode(&serialized_enc_key)
    );

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

    let signature = alloy_primitives::PrimitiveSignature::try_from(
        signer.sign_hash_sync(&message_hash)?.as_bytes().as_slice(),
    )?;

    //ciphertext digest is SHA3 of the ctxt
    let ciphertext_digest = hash_element(&cipher);

    let value = OperationValue::Reencrypt(ReencryptValues::new(
        signature.as_bytes().to_vec(),
        client_address.to_checksum(None),
        serialized_enc_key.clone(),
        ct_config.data_type,
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
    // If centralized (ie there is only one party)
    let verf_keys = if num_parties == 1 {
        let storage = FileStorage::new(Some(keys_folder), StorageType::PUB, None).unwrap();
        let url = storage
            .compute_url(
                &SIGNING_KEY_ID.to_string().to_lowercase(),
                &PubDataType::VerfKey.to_string(),
            )
            .unwrap();
        tracing::info!("storage URL: {:?}", url);
        let verf_key: PublicSigKey = storage.read_data(&url).await.unwrap();
        vec![verf_key]
    } else {
        let mut res = Vec::new();
        for i in 1..=num_parties {
            let storage = FileStorage::new(Some(keys_folder), StorageType::PUB, Some(i)).unwrap();
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

    let mut kms_client = kms_lib::client::Client::new(
        verf_keys,
        client_address,
        Some(sig_sk),
        params,
        decryption_mode, // This must match what is deployed on core/service (i.e. threshold.decryption_mode in the core config toml)! Can be set in simulator config.
    );

    kms_client.convert_to_addresses();

    let evs = execute_contract(client, query_client, asc_address, value, None).await?;
    let ev = evs[0].clone();

    tracing::info!("TxId: {:?}", ev.txn_id().to_hex(),);
    Ok((ev, ptxt, parsed_request, kms_client, domain, enc_pk, enc_sk))
}

pub fn cosmos_to_eth_address(cosmos_address: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Decode the bech32 address
    let (_, data, _) = bech32::decode(cosmos_address)?;
    let decoded = Vec::<u8>::from_base32(&data)?;
    let decoded_len = decoded.len();
    if decoded_len != 20 {
        return Err(format!(
            "Unexpected decoded length. Should be 20 Bytes but was {decoded_len}."
        )
        .into());
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
pub async fn wait_for_asc_to_be_deployed(
    node_url: &str,
    asc_address: &str,
    max_retries: u64,
    time_to_wait: tokio::time::Duration,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    for retry_index in 0..max_retries {
        match check_contract(node_url, asc_address).await {
            Ok(_) => {
                tracing::info!("Found ASC address: {:?}", asc_address);
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
async fn fetch_global_pub_object_and_write_to_file(
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
        fetch_global_pub_object_and_write_to_file(
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
    is_centralized: bool,
) -> Result<Vec<alloy_primitives::Address>, Box<dyn std::error::Error + 'static>> {
    // TODO: handle local file
    let key_id = &SIGNING_KEY_ID.to_string();

    let mut addr_bytes = Vec::new();
    if is_centralized {
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
            alloy_primitives::Address::parse_checksummed(
                str::from_utf8(x).unwrap_or_else(|_| {
                    panic!("cannot convert address bytes into UTF-8 string: {:?}", x)
                }),
                None,
            )
            .unwrap_or_else(|_| panic!("invalid ethereum address: {:?}", x))
        })
        .collect();

    Ok(kms_addrs)
}

/// Query the CSC
async fn query_csc<T: DeserializeOwned>(
    query_client: &QueryClient,
    sim_conf: &SimulatorConfig,
    contract_query: CscQuery,
) -> Result<T, Box<dyn std::error::Error + 'static>> {
    let values: T = query_client
        .query_csc(sim_conf.csc_address.to_string(), contract_query)
        .await?;
    Ok(values)
}

/// Query the ASC
async fn query_asc<T: DeserializeOwned>(
    query_client: &QueryClient,
    sim_conf: &SimulatorConfig,
    contract_query: AscQuery,
) -> Result<T, Box<dyn std::error::Error + 'static>> {
    let values: T = query_client
        .query_asc(sim_conf.asc_address.to_string(), contract_query)
        .await?;
    Ok(values)
}

/// Get all operation values associated with the given event (operation type + transaction ID)
pub async fn get_values_from_event(
    sim_config: &SimulatorConfig,
    query: Query,
    query_client: &QueryClient,
) -> Result<Vec<OperationValue>, Box<dyn std::error::Error + 'static>> {
    let txn_id = HexVector::from_hex(&query.txn_id)?;
    let event = KmsEvent::builder()
        .operation(query.kms_operation)
        .txn_id(txn_id)
        .build();

    tracing::info!("ASC address: {:?}", sim_config.asc_address);
    let query_req = AscQuery::GetOperationsValuesFromEvent(EventQuery { event });
    query_asc(query_client, sim_config, query_req).await
}

async fn wait_for_response(
    event: KmsEvent,
    query_client: &QueryClient,
    sim_conf: &SimulatorConfig,
    max_iter: u64,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<OperationValue>> {
    let time_to_wait = 5; // in seconds
    tracing::info!("Event operation: {:?}", event.operation);
    let query = Query {
        txn_id: event.txn_id.to_hex(),
        kms_operation: event.operation.to_response()?,
    };
    for _ in 1..=max_iter {
        match get_values_from_event(sim_conf, query.clone(), query_client).await {
            Ok(results) => {
                if results.len() < num_expected_responses {
                    tracing::info!(
                    "Got {} responses, but expecting at least {}. Waiting {time_to_wait} seconds for the other responses to be posted to the blockchain.", results.len(), num_expected_responses,
                );
                    tokio::time::sleep(tokio::time::Duration::from_secs(time_to_wait)).await;
                } else {
                    tracing::info!("Results: {:?}", results);
                    return Ok(results);
                }
            }
            Err(e) => {
                tracing::info!(
                    "Got error \"{e}\", waiting {time_to_wait} seconds for the response to be posted to the blockchain.",
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(time_to_wait)).await;
            }
        }
    }
    Err(anyhow!(
        "Never reached the response for operation {:?}.",
        event.operation
    ))
}

/// check that the external signature on the CRS or pubkey is valid, i.e. was made by one of the supplied addresses
fn check_ext_pubdata_signature<D: Serialize + Versionize + Named>(
    data: &D,
    external_sig: &[u8],
    vals: &impl Eip712Values,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // Deserialize the Signature. It reverses the call to `signature.as_bytes()` that we use for serialization.
    let sig = PrimitiveSignature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

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

/// check that the external signature on the decryption result(s) is valid, i.e. was made by one of the supplied addresses
fn check_ext_pt_signature(
    external_sig: &[u8],
    plaintexts: Vec<TypedPlaintext>,
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
    let sig = PrimitiveSignature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

    let edm = Eip712DomainMsg {
        name: decrypt_vals.eip712_name().to_string(),
        version: decrypt_vals.eip712_version().to_string(),
        chain_id: decrypt_vals.eip712_chain_id().into(),
        verifying_contract: decrypt_vals.eip712_verifying_contract().to_string(),
        salt: decrypt_vals.eip712_salt().map(|v| v.0.to_owned()),
    };
    let domain = protobuf_to_alloy_domain(&edm)?;

    let acl_address =
        alloy_primitives::Address::parse_checksummed(decrypt_vals.acl_address(), None)?;

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
    expected_answer: TypedPlaintext,
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

                for (idx, pt) in payload.plaintexts.into_iter().enumerate() {
                    tracing::info!("Decrypt Result #{idx}: Plaintext Decrypted = {pt:?}.");
                    results.push(pt);
                }
            }
            _ => {
                tracing::error!("Found something else than DecryptResponse in decryption pipeline.")
            }
        }
    }

    let tp_expected = TestingPlaintext::from(expected_answer);
    for result in results {
        assert_eq!(tp_expected, TestingPlaintext::from(result));
    }

    tracing::info!("Decryption response successfully processed.");
    Ok(())
}

fn process_reencrypt_responses(
    responses: Vec<OperationValue>,
    expected_answer: TypedPlaintext,
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

            // TODO(1968)
            tracing::info!(
                "[1968] found a response: ct: {}, fhe_type: {}",
                hex::encode(&payload.signcrypted_ciphertext),
                payload.fhe_type
            );

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

    assert_eq!(
        TestingPlaintext::from(expected_answer),
        TestingPlaintext::from(result)
    );

    tracing::info!("Reencryption response processed successfully.");
    Ok(())
}

async fn fetch_key_and_crs(
    key_id: &str,
    crs_id: &str,
    sim_conf: &SimulatorConfig,
    destination_prefix: &Path,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
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

    fetch_key(key_id, sim_conf, destination_prefix).await?;
    fetch_crs(crs_id, sim_conf, destination_prefix).await?;

    Ok(())
}

/// Fetch all remote objects associated with TFHE keys and store locally for the simulator
async fn fetch_key(
    key_id: &str,
    sim_conf: &SimulatorConfig,
    destination_prefix: &Path,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    tracing::info!("Fetching public key and server key with id {key_id}");
    for object_name in ["PublicKey", "PublicKeyMetadata", "ServerKey"] {
        fetch_global_pub_object_and_write_to_file(
            destination_prefix,
            sim_conf
                .s3_endpoint
                .clone()
                .expect("S3 endpoint should be provided")
                .as_str(),
            key_id,
            object_name,
            sim_conf.object_folder.first().unwrap(),
        )
        .await?;
    }
    Ok(())
}

/// Fetch the remote CRS and store locally for the simulator
async fn fetch_crs(
    crs_id: &str,
    sim_conf: &SimulatorConfig,
    destination_prefix: &Path,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    tracing::info!("Fetching CRS with id {crs_id}");
    fetch_global_pub_object_and_write_to_file(
        destination_prefix,
        sim_conf
            .s3_endpoint
            .clone()
            .expect("S3 endpoint should be provided")
            .as_str(),
        crs_id,
        "CRS",
        sim_conf.object_folder.first().unwrap(),
    )
    .await?;
    Ok(())
}

pub async fn execute_cmd(
    path_to_config: &str,
    command: &SimulatorCommand,
    destination_prefix: &Path,
    max_iter: u64,
    expect_all_responses: bool,
) -> Result<(Option<Vec<OperationValue>>, String), Box<dyn std::error::Error + 'static>> {
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
        .mnemonic_wallet(Some(&sim_conf.mnemonic.clone()))
        .build()
        .try_into()?;

    tracing::info!("ASC address: {}", sim_conf.asc_address);

    // TODO: merge both clients
    let query_client: QueryClient = QueryClientBuilder::builder()
        .grpc_addresses(validator_addresses.clone())
        .build()
        .try_into()?;

    wait_for_asc_to_be_deployed(
        sim_conf.http_validator_endpoints[0].as_str(),
        &sim_conf.asc_address,
        120,
        tokio::time::Duration::from_secs(1),
    )
    .await?;

    match command {
        SimulatorCommand::Decrypt(cipher_params) | SimulatorCommand::ReEncrypt(cipher_params) => {
            fetch_key_and_crs(
                cipher_params.key_id.as_str(),
                cipher_params.crs_id.as_str(),
                &sim_conf,
                destination_prefix,
            )
            .await?;
        }
        SimulatorCommand::VerifyProvenCt(cipher_params) => {
            fetch_key_and_crs(
                cipher_params.key_id.as_str(),
                cipher_params.crs_id.as_str(),
                &sim_conf,
                destination_prefix,
            )
            .await?;
        }
        _ => {}
    }

    // Get the number of parties from the CSC
    let num_parties: usize =
        query_csc(&query_client, &sim_conf, CscQuery::GetNumParties {}).await?;

    // Check if the KMS is centralized (ie, there is only one party)
    let is_centralized = num_parties == 1;

    tracing::info!(
        "Retrieved {} parties: (centralized: {})",
        num_parties,
        is_centralized
    );

    let kms_addrs = fetch_kms_addresses(&sim_conf, is_centralized).await?;

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
    // TODO: add optional faucet configuration in CSC

    // Execute the proper command
    let res = match command {
        SimulatorCommand::Decrypt(cipher_params) => {
            let decryption_params = DecryptionParams {
                to_encrypt: parse_hex(cipher_params.to_encrypt.as_str())?,
                data_type: cipher_params.data_type,
                key_id: &cipher_params.key_id,
                keys_folder: destination_prefix,
                compressed: Some(cipher_params.compressed),
            };
            let (event, ptxt, decrypt_values) = execute_decryption_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
                decryption_params,
            )
            .await?;
            let req_id = event.txn_id.to_hex();

            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                // Get the number of responses needed for a majority vote from the CSC if we accept less
                // responses than the number of parties
                query_csc(
                    &query_client,
                    &sim_conf,
                    CscQuery::GetResponseCountForMajorityVote {},
                )
                .await?
            };
            let return_value = Some(
                wait_for_response(
                    event,
                    &query_client,
                    &sim_conf,
                    max_iter,
                    num_expected_responses,
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
            (return_value, req_id)
        }
        SimulatorCommand::ReEncrypt(cipher_params) => {
            // Get the parameter choice from the CSC
            let fhe_parameter: FheParameter =
                query_csc(&query_client, &sim_conf, CscQuery::GetFheParameter {}).await?;

            let reencryption_params = ReencryptionParams {
                ct_config: CiphertextConfig {
                    clear_value: parse_hex(cipher_params.to_encrypt.as_str())?,
                    compressed: Some(cipher_params.compressed),
                    data_type: cipher_params.data_type,
                },
                key_id: &cipher_params.key_id,
                keys_folder: destination_prefix,
                fhe_parameter,
                num_parties,
                decryption_mode: sim_conf.decryption_mode,
            };
            let (event, ptxt, request, kms_client, domain, enc_pk, enc_sk) =
                execute_reencryption_contract(
                    &client,
                    &query_client,
                    sim_conf.asc_address.to_string(),
                    reencryption_params,
                )
                .await?;
            let req_id = event.txn_id.to_hex();

            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                // Get the number of responses needed for reconstruction from the CSC if we accept less
                // responses than the number of parties
                query_csc(
                    &query_client,
                    &sim_conf,
                    CscQuery::GetResponseCountForReconstruction {},
                )
                .await?
            };
            let return_value = Some(
                wait_for_response(
                    event,
                    &query_client,
                    &sim_conf,
                    max_iter,
                    num_expected_responses,
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
            (return_value, req_id)
        }
        SimulatorCommand::PreprocKeyGen(NoParameters {}) => {
            let event = execute_preproc_keygen_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
            )
            .await?;
            let req_id = event.txn_id.to_hex();
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                // Get the number of responses needed for a majority vote from the CSC if we accept less
                // responses than the number of parties
                query_csc(
                    &query_client,
                    &sim_conf,
                    CscQuery::GetResponseCountForMajorityVote {},
                )
                .await?
            };
            let responses = wait_for_response(
                event,
                &query_client,
                &sim_conf,
                max_iter,
                num_expected_responses,
            )
            .await?;
            let return_value = Some(responses.clone());

            for response in responses {
                if let OperationValue::KeyGenPreprocResponse(response) = &response {
                    tracing::info!(
                        "Received KeyGenPreprocResponse {:?} for request_id {}",
                        response,
                        &req_id
                    );
                } else {
                    panic!("Did not receive CrsGenResponse, got {:?}", response)
                }
            }
            (return_value, req_id)
        }
        SimulatorCommand::KeyGen(KeyGenParameters { preproc_id }) => {
            let preproc_id = HexVector::from_hex(preproc_id)?;
            let (event, keygen_vals) = execute_keygen_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
                preproc_id,
            )
            .await?;
            let req_id = event.txn_id.to_hex();
            let return_value = process_keygen(
                expect_all_responses,
                num_parties,
                max_iter,
                &query_client,
                &sim_conf,
                &kms_addrs,
                destination_prefix,
                event,
                &keygen_vals,
            )
            .await?;
            (return_value, req_id)
        }
        SimulatorCommand::InsecureKeyGen(NoParameters {}) => {
            let (event, insecure_keygen_vals) = execute_insecure_keygen_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
            )
            .await?;
            let req_id = event.txn_id.to_hex();
            let return_value = process_keygen(
                expect_all_responses,
                num_parties,
                max_iter,
                &query_client,
                &sim_conf,
                &kms_addrs,
                destination_prefix,
                event,
                &insecure_keygen_vals,
            )
            .await?;
            (return_value, req_id)
        }
        SimulatorCommand::CrsGen(CrsParameters { max_num_bits }) => {
            let (event, crs_vals) = execute_crsgen_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
                *max_num_bits,
            )
            .await?;
            let req_id = event.txn_id.to_hex();
            let return_value = process_crs(
                expect_all_responses,
                num_parties,
                max_iter,
                &query_client,
                &sim_conf,
                &kms_addrs,
                destination_prefix,
                event,
                &crs_vals,
            )
            .await?;
            (return_value, req_id)
        }
        SimulatorCommand::InsecureCrsGen(CrsParameters { max_num_bits }) => {
            let (event, crs_vals) = execute_insecure_crsgen_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
                *max_num_bits,
            )
            .await?;
            let req_id = event.txn_id.to_hex();
            let return_value = process_crs(
                expect_all_responses,
                num_parties,
                max_iter,
                &query_client,
                &sim_conf,
                &kms_addrs,
                destination_prefix,
                event,
                &crs_vals,
            )
            .await?;
            (return_value, req_id)
        }
        SimulatorCommand::VerifyProvenCt(VerifyProvenCtParameters {
            to_encrypt,
            data_type,
            crs_id,
            key_id,
        }) => {
            let verify_proven_ct_params = VerifyProvenCtParams {
                to_encrypt: parse_hex(to_encrypt.as_str())?,
                data_type: *data_type,
                crs_id: crs_id.as_str(),
                key_id: key_id.as_str(),
                keys_folder: destination_prefix,
            };
            let event = execute_verify_proven_ct_contract(
                &client,
                &query_client,
                sim_conf.asc_address.to_string(),
                verify_proven_ct_params,
            )
            .await?;
            let req_id = event.txn_id.to_hex();
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                // Get the number of responses needed for a majority vote from the CSC if we accept less
                // responses than the number of parties
                query_csc(
                    &query_client,
                    &sim_conf,
                    CscQuery::GetResponseCountForMajorityVote {},
                )
                .await?
            };
            let return_value = Some(
                wait_for_response(
                    event,
                    &query_client,
                    &sim_conf,
                    max_iter,
                    num_expected_responses,
                )
                .await?,
            );
            (return_value, req_id)
        }
        SimulatorCommand::QueryContract(query) => {
            let return_value =
                Some(get_values_from_event(&sim_conf, query.clone(), &query_client).await?);
            (return_value, "".to_string())
        }
        SimulatorCommand::GetFunds(faucet_params) => {
            call_faucet(
                faucet_params.faucet_address.as_str(),
                &client.get_account_address()?,
            )
            .await?;
            (None, "".to_string())
        }
        SimulatorCommand::DoNothing(NoParameters {}) => {
            tracing::info!("Nothing to do.");
            (None, "".to_string())
        }
    };

    // Check wallet amount after operations
    let wallet_amount_after = client.get_wallet_amount(None).await?;
    tracing::info!("Wallet amount: {:}", wallet_amount_after);
    tracing::info!(
        "Whole operation cost was: {:}",
        wallet_amount_before - wallet_amount_after
    );

    tracing::info!("Simulator terminated successfully.");
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
async fn process_keygen(
    expect_all_responses: bool,
    num_parties: usize,
    max_iter: u64,
    query_client: &QueryClient,
    sim_conf: &SimulatorConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    event: KmsEvent,
    keygen_vals: &impl Eip712Values,
) -> Result<Option<Vec<OperationValue>>, Box<dyn std::error::Error + 'static>> {
    let req_id = &event.txn_id.to_hex();
    let num_expected_responses = if expect_all_responses {
        num_parties
    } else {
        // Get the number of responses needed for a majority vote from the CSC if we accept less
        // responses than the number of parties
        query_csc(
            query_client,
            sim_conf,
            CscQuery::GetResponseCountForMajorityVote {},
        )
        .await?
    };
    let responses = wait_for_response(
        event,
        query_client,
        sim_conf,
        max_iter,
        num_expected_responses,
    )
    .await?;

    // Download the generated keys. We do this just once, to save time, assuming that all generated keys are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all keys and compare them.
    fetch_key(req_id, sim_conf, destination_prefix).await?;
    let pk = load_pk_from_storage(Some(destination_prefix), req_id).await;
    let sk = load_server_key_from_storage(Some(destination_prefix), req_id).await;

    let return_value = Some(responses.clone());
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
            assert_eq!(
                req_id,
                &response.request_id().to_string(),
                "Request ID of response does not match the transaction"
            );

            check_ext_pubdata_signature(
                &pk,
                &response.public_key_external_signature().0,
                keygen_vals,
                kms_addrs,
            )?;

            check_ext_pubdata_signature(
                &sk,
                &response.server_key_external_signature().0,
                keygen_vals,
                kms_addrs,
            )?;

            tracing::info!("EIP712 verification of Public Key and Server Key successful.");
        } else {
            panic!("Did not received KeyGenResponse, got {:?}", response)
        }
    }
    Ok(return_value)
}

#[allow(clippy::too_many_arguments)]
async fn process_crs(
    expect_all_responses: bool,
    num_parties: usize,
    max_iter: u64,
    query_client: &QueryClient,
    sim_conf: &SimulatorConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    event: KmsEvent,
    crs_vals: &impl Eip712Values,
) -> Result<Option<Vec<OperationValue>>, Box<dyn std::error::Error + 'static>> {
    let req_id = &event.txn_id.to_hex();

    let num_expected_responses = if expect_all_responses {
        num_parties
    } else {
        // Get the number of responses needed for a majority vote from the CSC if we accept less
        // responses than the number of parties
        query_csc(
            query_client,
            sim_conf,
            CscQuery::GetResponseCountForMajorityVote {},
        )
        .await?
    };
    let responses = wait_for_response(
        event,
        query_client,
        sim_conf,
        max_iter,
        num_expected_responses,
    )
    .await?;
    let return_value = Some(responses.clone());

    // Download the generated CRS. We do this just once, to save time, assuming that all generated CRSes are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all CRSes and compare them.
    fetch_crs(req_id, sim_conf, destination_prefix).await?;
    let crs = load_crs_from_storage(Some(destination_prefix), req_id).await;

    for response in responses {
        if let OperationValue::CrsGenResponse(response) = &response {
            tracing::info!(
                        "Received CrsGenResponse with request ID {}, digest {}, signature {}, and external signature {}",
                        response.request_id(),
                        response.digest(),
                        response.signature().to_hex(),
                        response.external_signature().to_hex(),
                    );
            assert_eq!(
                req_id,
                response.request_id(),
                "Request ID of response does not match the transaction"
            );

            check_ext_pubdata_signature(
                &crs,
                &response.external_signature().0,
                crs_vals,
                kms_addrs,
            )?;

            tracing::info!("EIP712 verification of CRS successful.");
        } else {
            panic!("Did not receive CrsGenResponse, got {:?}", response)
        }
    }

    Ok(return_value)
}

#[cfg(test)]
mod tests {
    use alloy_signer::k256::ecdsa::SigningKey;
    use kms_grpc::kms::v1::RequestId;
    use kms_grpc::rpc_types::{alloy_to_protobuf_domain, PrivDataType};
    use kms_lib::{
        consts::TEST_CENTRAL_CRS_ID,
        cryptography::internal_crypto_types::PrivateSigKey,
        engine::base::compute_external_pubdata_signature,
        util::key_setup::{ensure_central_crs_exists, ensure_central_server_signing_keys_exist},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };
    use tfhe::zk::CompactPkeCrs;

    use super::*;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("00").unwrap(), vec![0u8]);
        assert_eq!(parse_hex("0x00").unwrap(), vec![0u8]);
        assert_eq!(parse_hex("ff").unwrap(), vec![255u8]);
        assert_eq!(parse_hex("0xff").unwrap(), vec![255u8]);
        assert_eq!(parse_hex("0001").unwrap(), vec![0u8, 1u8]);
        assert_eq!(parse_hex("0x1234").unwrap(), vec![18u8, 52u8]);
        assert_eq!(parse_hex("1").unwrap(), vec![1u8]);
        assert_eq!(parse_hex("0x1").unwrap(), vec![1u8]);
    }

    #[test]
    fn test_invalid_hex() {
        assert!(parse_hex("zz").is_err());
        assert!(parse_hex("0xzz").is_err());
        assert!(parse_hex("0x1234g").is_err());
        assert!(parse_hex("0x12345g").is_err());
        assert!(parse_hex("Ox01").is_err()); // leading O instead of 0
    }

    #[tokio::test]
    async fn test_eip712_sigs() {
        let mut pub_storage = RamStorage::new(StorageType::PUB);
        let mut priv_storage = RamStorage::new(StorageType::PRIV);

        // make sure signing keys exist
        ensure_central_server_signing_keys_exist(
            &mut pub_storage,
            &mut priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;

        // compute a small CRS for testing
        ensure_central_crs_exists(
            &mut pub_storage,
            &mut priv_storage,
            TEST_PARAM,
            &TEST_CENTRAL_CRS_ID,
            true,
        )
        .await;
        let crs: CompactPkeCrs = read_versioned_at_request_id(
            &pub_storage,
            &RequestId {
                request_id: TEST_CENTRAL_CRS_ID.to_string(),
            },
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();

        // read generated private signature key, derive public verifcation key and address from it
        let sk: PrivateSigKey = read_versioned_at_request_id(
            &priv_storage,
            &RequestId {
                request_id: SIGNING_KEY_ID.to_string(),
            },
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        let pk = SigningKey::verifying_key(sk.sk());
        let addr = alloy_signer::utils::public_key_to_address(pk);

        // set up a dummy EIP 712 domain
        let domain = alloy_sol_types::eip712_domain!(
            name: "dummy",
            version: "1",
            chain_id: 0,
            verifying_contract: alloy_primitives::Address::ZERO,
            // No salt
        );
        let domain_msg = alloy_to_protobuf_domain(&domain).unwrap();

        // set up the metadata for a CRS generation request message (that is used in the signature generation)
        let vals = CrsGenValues::new(
            32,
            domain_msg.name,
            domain_msg.version,
            domain_msg.chain_id,
            domain_msg.verifying_contract,
            domain_msg.salt,
        )
        .unwrap();

        // sign with EIP712
        let sig = compute_external_pubdata_signature(&sk, &crs, &domain).unwrap();

        // check that the signature verifies and unwraps without error
        check_ext_pubdata_signature(&crs, &sig, &vals, &[addr]).unwrap();

        // check that verification fails for a wrong address
        let wrong_address = alloy_primitives::address!("0EdA6bf26964aF942Eed9e03e53442D37aa960EE");
        assert!(
            check_ext_pubdata_signature(&crs, &sig, &vals, &[wrong_address])
                .unwrap_err()
                .to_string()
                .contains("External crs/pubkey signature verification failed!")
        );

        // check that verification fails for signature that is too short
        let short_sig = [0_u8; 37];
        assert!(
            check_ext_pubdata_signature(&crs, &short_sig, &vals, &[addr])
                .unwrap_err()
                .to_string()
                .contains("Expected external signature of length 65 Bytes, but got 37")
        );

        // check that verification fails for a byte string that is not a signature
        let malformed_sig = [23_u8; 65];
        assert!(
            check_ext_pubdata_signature(&crs, &malformed_sig, &vals, &[addr])
                .unwrap_err()
                .to_string()
                .contains("signature error")
        );

        // check that verification fails for a signature that does not match the message
        let wrong_sig = hex::decode("cf92fe4c0b7c72fd8571c9a6680f2cd7481ebed7a3c8c7c7a6e6eaf27f5654f36100c146e609e39950953602ed73a3c10c1672729295ed8b33009b375813e5801b").unwrap();
        assert!(
            check_ext_pubdata_signature(&crs, &wrong_sig, &vals, &[addr])
                .unwrap_err()
                .to_string()
                .contains("External crs/pubkey signature verification failed!")
        );
    }
}
