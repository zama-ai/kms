/// Core Client library
///
/// This library implements most functionalities to interact with deployed KMS cores.
/// This library also includes an associated CLI.
use aes_prng::AesRng;
use alloy_primitives::Signature;
use alloy_sol_types::{Eip712Domain, SolStruct};
use anyhow::anyhow;
use bytes::Bytes;
use clap::{Args, Parser, Subcommand, ValueEnum};
use core::str;
use kms_grpc::kms::v1::{
    CiphertextFormat, CrsGenResult, FheParameter, KeyGenPreprocResult, KeyGenResult,
    PublicDecryptionRequest, PublicDecryptionResponse, TypedCiphertext, TypedPlaintext,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::{
    protobuf_to_alloy_domain, CrsgenVerification, KeygenVerification, PubDataType,
};
use kms_grpc::{KeyId, RequestId};
use kms_lib::client::{client_wasm::Client, user_decryption_wasm::ParsedUserDecryptionRequest};
use kms_lib::consts::{DEFAULT_PARAM, SIGNING_KEY_ID, TEST_PARAM};
use kms_lib::engine::base::{
    compute_pt_message_hash, hash_sol_struct, safe_serialize_hash_element_versioned,
    DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY,
};
use kms_lib::util::file_handling::{read_element, write_element};
use kms_lib::util::key_setup::ensure_client_keys_exist;
use kms_lib::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, load_crs_from_storage, load_pk_from_storage,
    load_server_key_from_storage, EncryptionConfig, TestingPlaintext,
};
use kms_lib::vault::storage::{file::FileStorage, StorageType};
use kms_lib::DecryptionMode;
use observability::conf::Settings;
use rand::{CryptoRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Once};
use strum_macros::{Display, EnumString};
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompactPublicKey, ServerKey};
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;
use threshold_fhe::hashing::{hash_element, DomainSep};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tonic::transport::Channel;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use validator::{Validate, ValidationError};

const SLEEP_TIME_BETWEEN_REQUESTS_MS: u64 = 500;

/// Retries a function a given number of times with a given interval between retries.
macro_rules! retry {
    ($f:expr, $count:expr, $interval:expr) => {{
        let mut retries = 0;
        let result = loop {
            let result = $f;
            if result.is_ok() {
                break result;
            } else if retries > $count {
                break result;
            }
            retries += 1;
            tokio::time::sleep(tokio::time::Duration::from_millis($interval)).await;
        };
        result
    }};
    ($f:expr) => {
        retry!($f, 5, 100)
    };
}

#[derive(Serialize, Clone, Validate, Default, Debug)]
#[validate(schema(function = validate_core_client_conf))]
pub struct CoreClientConfig {
    /// S3 endpoint from which to fetch keys
    /// NOTE: We should probably move away from that and use the key-url
    #[validate(length(min = 1))]
    pub s3_endpoint: String,
    /// Key folder where to store the keys
    #[validate(length(min = 1))]
    pub object_folder: Vec<String>,
    pub decryption_mode: Option<DecryptionMode>,
    pub num_majority: usize,
    pub num_reconstruct: usize,
    #[validate(length(min = 1))]
    pub core_addresses: Vec<String>,
    pub fhe_params: Option<FheParameter>,
}

fn validate_core_client_conf(conf: &CoreClientConfig) -> Result<(), ValidationError> {
    let num_parties = conf.core_addresses.len();

    if conf.object_folder.len() != conf.core_addresses.len() {
        return Err(
            ValidationError::new("Address/Object length mismatch").with_message(
                format!(
                    "Number of object folders ({}) must match number of core addresses ({})",
                    conf.object_folder.len(),
                    conf.core_addresses.len(),
                )
                .into(),
            ),
        );
    }

    if num_parties > 1 {
        // threshold config
        let threshold = (num_parties - 1) / 3; // Note that this is floored division. We assumt that 3t+1=n for now.

        // a majority is more than t parties agreeing. But we could also set it to a higher value up to num_parties.
        if conf.num_majority <= threshold || conf.num_majority > num_parties {
            return Err(ValidationError::new("Threshold Majority Vote Count Error").with_message(format!("Number for majority votes ({}) must be greater than the threshold ({}) and smaller than the number of parties ({}).", conf.num_majority, threshold, num_parties).into()));
        }

        // reconstruction needs at least t+2 parties responses. But we could also set it to a higher value up to num_parties.
        if conf.num_reconstruct < threshold + 2 || conf.num_reconstruct > num_parties {
            return Err(ValidationError::new("Threshold Reconstruction Count Error").with_message(format!("Number for reconstruction shares ({}) must be at least t+2 ({}) and smaller than the number of parties ({}).", conf.num_reconstruct, threshold + 2, num_parties).into()));
        }
    } else {
        // centralized config, here both values must be 1.
        if conf.num_majority != 1 {
            return Err(
                ValidationError::new("Centralized Majority Vote Count Error").with_message(
                    format!(
                    "Number for majority votes ({}) must be equal to 1 for a centralized config.",
                    conf.num_majority,
                )
                    .into(),
                ),
            );
        }
        if conf.num_reconstruct != 1 {
            return Err(
                ValidationError::new("Centralized Reconstruction Count Error").with_message(
                    format!(
                    "Number for reconstruction ({}) must be equal to 1 for a centralized config.",
                    conf.num_reconstruct,
                )
                    .into(),
                ),
            );
        }
    }

    Ok(())
}

impl<'de> Deserialize<'de> for CoreClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Clone, Default, Debug)]
        pub struct CoreClientConfigBuffer {
            pub s3_endpoint: String,
            pub object_folder: Vec<String>,
            pub decryption_mode: Option<DecryptionMode>,
            pub num_majority: usize,
            pub num_reconstruct: usize,
            pub core_addresses: Vec<String>,
            pub fhe_params: Option<FheParameter>,
        }

        let temp = CoreClientConfigBuffer::deserialize(deserializer)?;

        let conf = CoreClientConfig {
            s3_endpoint: temp.s3_endpoint,
            object_folder: temp.object_folder,
            decryption_mode: temp.decryption_mode,
            num_majority: temp.num_majority,
            num_reconstruct: temp.num_reconstruct,
            core_addresses: temp.core_addresses,
            fhe_params: temp.fhe_params,
        };

        conf.validate().map_err(serde::de::Error::custom)?;

        Ok(conf)
    }
}

use tfhe::FheTypes as TfheFheType;

#[derive(Copy, Clone, Default, EnumString, PartialEq, Display, Debug, Serialize, Deserialize)]
pub enum FheType {
    #[default]
    #[strum(serialize = "ebool")]
    Ebool,
    #[strum(serialize = "euint4")]
    Euint4,
    #[strum(serialize = "euint8")]
    Euint8,
    #[strum(serialize = "euint16")]
    Euint16,
    #[strum(serialize = "euint32")]
    Euint32,
    #[strum(serialize = "euint64")]
    Euint64,
    #[strum(serialize = "euint128")]
    Euint128,
    #[strum(serialize = "euint160")]
    Euint160,
    #[strum(serialize = "euint256")]
    Euint256,
    #[strum(serialize = "euint512")]
    Euint512,
    #[strum(serialize = "euint1024")]
    Euint1024,
    #[strum(serialize = "euint2048")]
    Euint2048,
    #[strum(serialize = "unknown")]
    Unknown,
}

impl FheType {
    // We don't use it for now, but useful to have
    #[allow(dead_code)]
    fn as_str_name(self) -> &'static str {
        match self {
            FheType::Ebool => "Ebool",
            FheType::Euint4 => "Euint4",
            FheType::Euint8 => "Euint8",
            FheType::Euint16 => "Euint16",
            FheType::Euint32 => "Euint32",
            FheType::Euint64 => "Euint64",
            FheType::Euint128 => "Euint128",
            FheType::Euint160 => "Euint160",
            FheType::Euint256 => "Euint256",
            FheType::Euint512 => "Euint512",
            FheType::Euint1024 => "Euint1024",
            FheType::Euint2048 => "Euint2048",
            FheType::Unknown => "Unknown",
        }
    }

    pub fn bits(&self) -> usize {
        match self {
            FheType::Ebool => 1,
            FheType::Euint4 => 4,
            FheType::Euint8 => 8,
            FheType::Euint16 => 16,
            FheType::Euint32 => 32,
            FheType::Euint64 => 64,
            FheType::Euint128 => 128,
            FheType::Euint160 => 160,
            FheType::Euint256 => 256,
            FheType::Euint512 => 512,
            FheType::Euint1024 => 1024,
            FheType::Euint2048 => 2048,
            FheType::Unknown => 0,
        }
    }

    pub fn from_str_name(value: &str) -> FheType {
        match value {
            "Ebool" => Self::Ebool,
            "Euint4" => Self::Euint4,
            "Euint8" => Self::Euint8,
            "Euint16" => Self::Euint16,
            "Euint32" => Self::Euint32,
            "Euint64" => Self::Euint64,
            "Euint128" => Self::Euint128,
            "Euint160" => Self::Euint160,
            "Euint256" => Self::Euint256,
            "Euint512" => Self::Euint512,
            "Euint1024" => Self::Euint1024,
            "Euint2048" => Self::Euint2048,
            _ => Self::Unknown,
        }
    }
}

impl From<u8> for FheType {
    fn from(value: u8) -> Self {
        match value {
            0 => FheType::Ebool,
            1 => FheType::Euint4,
            2 => FheType::Euint8,
            3 => FheType::Euint16,
            4 => FheType::Euint32,
            5 => FheType::Euint64,
            6 => FheType::Euint128,
            7 => FheType::Euint160,
            8 => FheType::Euint256,
            9 => FheType::Euint512,
            10 => FheType::Euint1024,
            11 => FheType::Euint2048,
            _ => FheType::Unknown,
        }
    }
}

impl From<TfheFheType> for FheType {
    fn from(value: TfheFheType) -> Self {
        match value {
            TfheFheType::Bool => FheType::Ebool,
            TfheFheType::Uint4 => FheType::Euint4,
            TfheFheType::Uint8 => FheType::Euint8,
            TfheFheType::Uint16 => FheType::Euint16,
            TfheFheType::Uint32 => FheType::Euint32,
            TfheFheType::Uint64 => FheType::Euint64,
            TfheFheType::Uint128 => FheType::Euint128,
            TfheFheType::Uint160 => FheType::Euint160,
            TfheFheType::Uint256 => FheType::Euint256,
            TfheFheType::Uint512 => FheType::Euint512,
            TfheFheType::Uint1024 => FheType::Euint1024,
            TfheFheType::Uint2048 => FheType::Euint2048,
            _ => FheType::Unknown,
        }
    }
}

impl TryInto<TfheFheType> for FheType {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<TfheFheType, Self::Error> {
        match self {
            FheType::Ebool => Ok(TfheFheType::Bool),
            FheType::Euint4 => Ok(TfheFheType::Uint4),
            FheType::Euint8 => Ok(TfheFheType::Uint8),
            FheType::Euint16 => Ok(TfheFheType::Uint16),
            FheType::Euint32 => Ok(TfheFheType::Uint32),
            FheType::Euint64 => Ok(TfheFheType::Uint64),
            FheType::Euint128 => Ok(TfheFheType::Uint128),
            FheType::Euint160 => Ok(TfheFheType::Uint160),
            FheType::Euint256 => Ok(TfheFheType::Uint256),
            FheType::Euint512 => Ok(TfheFheType::Uint512),
            FheType::Euint1024 => Ok(TfheFheType::Uint1024),
            FheType::Euint2048 => Ok(TfheFheType::Uint2048),
            _ => Err(anyhow::anyhow!("Not supported")),
        }
    }
}

// CLI arguments
#[derive(Debug, Parser, Clone)]
pub struct NoParameters {}

/// Parse a string as hex string. The string can optionally start with "0x". Odd-length strings will be padded with a single leading zero.
pub fn parse_hex(arg: &str) -> anyhow::Result<Vec<u8>> {
    // Remove "0x" or "0X" prefix if present
    let arg = arg.strip_prefix("0x").unwrap_or(arg);
    let hex_str = arg.strip_prefix("0X").unwrap_or(arg);

    // Handle odd-length hex strings by padding with a single leading zero
    let hex_str = if hex_str.len() % 2 == 1 {
        format!("0{hex_str}")
    } else {
        hex_str.to_string()
    };

    Ok(hex::decode(hex_str)?)
}

#[derive(Debug, Subcommand, Clone)]
pub enum CipherArguments {
    FromFile(CipherFile),
    FromArgs(CipherParameters),
}

impl CipherArguments {
    pub fn get_batch_size(&self) -> usize {
        match self {
            CipherArguments::FromFile(cipher_file) => cipher_file.batch_size,
            CipherArguments::FromArgs(cipher_parameters) => cipher_parameters.batch_size,
        }
    }

    pub fn get_num_requests(&self) -> usize {
        match self {
            CipherArguments::FromFile(cipher_file) => cipher_file.num_requests,
            CipherArguments::FromArgs(cipher_parameters) => cipher_parameters.num_requests,
        }
    }
}

#[derive(Debug, Args, Clone, Serialize, Deserialize)]
pub struct CipherParameters {
    /// Hex value to encrypt and request a public/user decryption.
    /// The value will be converted from a little endian hex string to a `Vec<u8>`.
    /// Can optionally have a "0x" prefix.
    #[clap(long, short = 'e')]
    pub to_encrypt: String,
    /// Data type of `to_encrypt`.
    /// Expected one of ebool, euint4, ..., euint2048
    #[clap(long, short = 'd')]
    pub data_type: FheType,
    /// Boolean to activate ciphertext compression or not. Default: False.
    #[clap(long, short = 'c')]
    pub compression: bool,
    /// Boolean to do SnS preprocessing on the ciphertext or not.
    /// SnS preprocessing performs a PBS to convert 64-bit ciphertexts to 128-bit ones.
    /// Default: False.
    #[clap(long)]
    pub precompute_sns: bool,
    /// Key identifier to use for public/user decryption.
    #[clap(long, short = 'k')]
    pub key_id: KeyId,
    /// Number of copies of the ciphertext to process in a request.
    /// This is ignored for the encryption command.
    #[serde(skip_serializing, skip_deserializing)]
    #[clap(long, short = 'b', default_value_t = 1)]
    pub batch_size: usize,
    /// Numbers of requests to process at once.
    /// Each request uses a copy of the same batch.
    #[serde(skip_serializing, skip_deserializing)]
    #[clap(long, short = 'n', default_value_t = 1)]
    pub num_requests: usize,
    /// Optionally dump the ciphertext to a file.
    #[serde(skip_serializing, skip_deserializing)]
    #[clap(long)]
    pub ciphertext_output_path: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
pub struct CipherFile {
    /// Input file of the ciphertext.
    #[clap(long)]
    pub input_path: PathBuf,
    /// Number of copies of the ciphertext to process in a request.
    #[clap(long, short = 'b', default_value_t = 1)]
    pub batch_size: usize,
    /// Numbers of requests to process at once.
    /// Each request uses a copy of the same batch.
    #[clap(long, short = 'n', default_value_t = 1)]
    pub num_requests: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherWithParams {
    params: CipherParameters,
    ct_format: String,
    cipher: Vec<u8>,
}

#[derive(ValueEnum, Debug, Clone, Default)]
pub enum KeySetType {
    #[default]
    Standard,
    // DecompressionOnly, // we'll support this in the future
    AddSnsCompressionKey,
}

impl From<KeySetType> for kms_grpc::kms::v1::KeySetType {
    fn from(value: KeySetType) -> Self {
        match value {
            KeySetType::Standard => kms_grpc::kms::v1::KeySetType::Standard,
            KeySetType::AddSnsCompressionKey => kms_grpc::kms::v1::KeySetType::AddSnsCompressionKey,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct KeySetAddedInfo {
    #[clap(long)]
    base_keyset_id_for_sns_compression_key: Option<RequestId>,
}

impl From<KeySetAddedInfo> for kms_grpc::kms::v1::KeySetAddedInfo {
    fn from(value: KeySetAddedInfo) -> Self {
        kms_grpc::kms::v1::KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
            base_keyset_id_for_sns_compression_key: value
                .base_keyset_id_for_sns_compression_key
                .map(|x| x.into()),
        }
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct SharedKeyGenParameters {
    #[clap(value_enum, long, short = 't')]
    pub keyset_type: Option<KeySetType>,
    #[command(flatten)]
    pub keyset_added_info: Option<KeySetAddedInfo>,
}

#[derive(Debug, Parser, Clone)]
pub struct KeyGenParameters {
    #[clap(long, short = 'i')]
    pub preproc_id: RequestId,
    #[command(flatten)]
    pub shared_args: SharedKeyGenParameters,
}

#[derive(Debug, Parser, Clone)]
pub struct InsecureKeyGenParameters {
    #[command(flatten)]
    pub shared_args: SharedKeyGenParameters,
}

#[derive(Debug, Parser, Clone)]
pub struct CrsParameters {
    #[clap(long, short = 'm')]
    pub max_num_bits: u32,
}

#[derive(Debug, Parser, Clone)]
pub struct ResultParameters {
    #[clap(long, short = 'i')]
    pub request_id: RequestId,
}

#[derive(Debug, Subcommand, Clone)]
pub enum CCCommand {
    PreprocKeyGen(NoParameters),
    PreprocKeyGenResult(ResultParameters),
    KeyGen(KeyGenParameters),
    KeyGenResult(ResultParameters),
    InsecureKeyGen(InsecureKeyGenParameters),
    InsecureKeyGenResult(ResultParameters),
    Encrypt(CipherParameters),
    #[clap(subcommand)]
    PublicDecrypt(CipherArguments),
    PublicDecryptResult(ResultParameters),
    #[clap(subcommand)]
    UserDecrypt(CipherArguments),
    CrsGen(CrsParameters),
    CrsGenResult(ResultParameters),
    InsecureCrsGen(CrsParameters),
    InsecureCrsGenResult(ResultParameters),
    GetOperatorPublicKey(NoParameters),
    CustodianBackupRestore(NoParameters),
    DoNothing(NoParameters),
}

#[derive(Debug, Parser, Validate)]
pub struct CmdConfig {
    /// Path to the configuration file
    #[clap(long, short = 'f')]
    #[validate(length(min = 1))]
    pub file_conf: Option<String>,
    /// The command to execute
    #[clap(subcommand)]
    pub command: CCCommand,
    /// Whether to print logs or not
    #[clap(long, short = 'l')]
    pub logs: bool,
    /// Max number of iterations to query the KMS for a response
    #[clap(long, default_value = "30")]
    #[validate(range(min = 1))]
    pub max_iter: usize,
    /// Should we expect a response from every KMS core or not
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

/// a dummy Eip-712 domain for testing
fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
    )
}

fn dummy_handle() -> Vec<u8> {
    vec![23_u8; 32]
}

pub struct EncryptionResult {
    pub cipher: Vec<u8>,
    pub ct_format: CiphertextFormat,
    pub plaintext: TypedPlaintext,
    pub key_id: KeyId,
}

impl EncryptionResult {
    pub fn new(
        cipher: Vec<u8>,
        ct_format: CiphertextFormat,
        plaintext: TypedPlaintext,
        key_id: KeyId,
    ) -> Self {
        Self {
            cipher,
            ct_format,
            plaintext,
            key_id,
        }
    }
}

pub async fn fetch_ctxt_from_file(
    input_path: PathBuf,
) -> Result<EncryptionResult, Box<dyn std::error::Error + 'static>> {
    let cipher_with_params: CipherWithParams = read_element(input_path).await?;
    let ptxt = TypedPlaintext {
        bytes: parse_hex(cipher_with_params.params.to_encrypt.as_str())?,
        fhe_type: cipher_with_params.params.data_type as i32,
    };

    let ct_format = CiphertextFormat::from_str_name(&cipher_with_params.ct_format)
        .ok_or_else(|| anyhow!("Failed to recover ct_format"))?;

    let key_id = cipher_with_params.params.key_id;
    Ok(EncryptionResult::new(
        cipher_with_params.cipher,
        ct_format,
        ptxt,
        key_id,
    ))
}

/// encrypt a given value and return the ciphertext
/// parameters:
/// - `to_encrypt`: the value to encrypt in little endian byte order
/// - `fhe_type`: the type of the value to encrypt
/// - `key_id`: the key identifier to use for encryption
/// - `keys_folder`: the folder where the keys are stored
/// - `compressed`: whether to compress the ciphertext or not
pub async fn encrypt(
    keys_folder: &Path,
    cipher_params: CipherParameters,
) -> Result<EncryptionResult, Box<dyn std::error::Error + 'static>> {
    let to_encrypt = parse_hex(cipher_params.to_encrypt.as_str())?;
    if to_encrypt.len() != cipher_params.data_type.bits().div_ceil(8) {
        tracing::warn!("Byte length of value to encrypt ({}) does not match FHE type ({}) and will be padded/truncated.", to_encrypt.len(), cipher_params.data_type);
    }

    let ptxt = TypedPlaintext {
        bytes: to_encrypt,
        fhe_type: cipher_params.data_type as i32,
    };
    let typed_to_encrypt = TestingPlaintext::try_from(ptxt.clone())?;

    tracing::info!(
        "Encrypting plaintext: {:?}, {:?}, {:?}",
        ptxt,
        cipher_params.data_type,
        typed_to_encrypt
    );

    tracing::debug!(
        "Attempting to create ct using key material from {:?}",
        keys_folder
    );

    let (cipher, ct_format, _) = compute_cipher_from_stored_key(
        Some(keys_folder),
        typed_to_encrypt,
        &cipher_params.key_id.into(),
        EncryptionConfig {
            compression: cipher_params.compression,
            precompute_sns: cipher_params.precompute_sns,
        },
    )
    .await;

    if let Some(path) = cipher_params.ciphertext_output_path.clone() {
        let cipher_w_params = CipherWithParams {
            cipher: cipher.clone(),
            params: cipher_params.clone(),
            ct_format: ct_format.as_str_name().to_string(),
        };
        write_element(path, &cipher_w_params).await?;
    }

    Ok(EncryptionResult::new(
        cipher,
        ct_format,
        ptxt,
        cipher_params.key_id,
    ))
}

fn join_vars(args: &[&str]) -> String {
    args.iter()
        .filter(|&s| !s.is_empty())
        .copied()
        .collect::<Vec<&str>>()
        .join("/")
}

// TODO: handle auth
// TODO: add option to either use local  key or remote key
pub async fn fetch_object(endpoint: &str, folder: &str, object_id: &str) -> anyhow::Result<Bytes> {
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
            tracing::info!("Successfully downloaded {} bytes for object {object_id} from endpoint {endpoint}/{folder}", bytes.len());
            // Here you can process the bytes as needed
            Ok(bytes)
        } else {
            let response_status = response.status();
            let response_content = response.text().await?;
            tracing::error!("Error: {}", response_status);
            tracing::error!("Response: {}", response_content);
            Err(anyhow::anyhow!(format!(
                "Couldn't fetch object {object_id} from endpoint {endpoint}/{folder}\nStatus: {}\nResponse: {}",
                response_status, response_content
            ),))
        }
    } else {
        let key_path = Path::new(endpoint).join(folder).join(object_id);
        let byte_res = tokio::fs::read(&key_path).await.map_err(|e| {
            anyhow!(
                "Failed to read byte file at {:?} with error: {e}",
                &key_path
            )
        })?;
        Ok(Bytes::from(byte_res))
    }
}

async fn write_bytes_to_file(
    folder_path: &Path,
    filename: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let path = folder_path.join(filename);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?;
    }
    tokio::fs::write(&path, data).await.map_err(|e| {
        anyhow!(
            "Failed to write bytes to file at {:?} with error: {e}",
            &path
        )
    })?;
    Ok(())
}

static INIT_LOG: Once = Once::new();

pub fn init_testing() {
    INIT_LOG.call_once(setup_logging);
}

pub fn setup_logging() {
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "core-client.log");
    let file_and_stdout = file_appender.and(std::io::stdout);

    // read the RUST_LOG environment variable to set the logging level, or set to INFO as default
    let log_level_str = std::env::var("RUST_LOG").unwrap_or_else(|_| "INFO".to_string());
    let log_level = tracing::Level::from_str(&log_level_str).unwrap_or(tracing::Level::INFO);

    println!("Setting up logging with level: {log_level:?}");

    let subscriber = tracing_subscriber::fmt()
        .with_writer(file_and_stdout)
        .with_ansi(false)
        .with_max_level(log_level)
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set logging subscriber");
}

/// This fetches material which is global
/// i.e. everything related to CRS and FHE public materials
async fn fetch_global_pub_object_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    object_id: &str,
    object_name: &str,
    object_folder: &str,
) -> anyhow::Result<()> {
    // Fetch pub-key from storage and dump it for later use
    let folder = destination_prefix.join("PUB").join(object_name);
    let content = fetch_object(
        s3_endpoint,
        &format!("{object_folder}/{object_name}"),
        object_id,
    )
    .await?;
    write_bytes_to_file(&folder, object_id, content.as_ref()).await
}

/// This fetches material which is local
/// i.e. everything related to parties verification keys
async fn fetch_local_key_and_write_to_file(
    destination_prefix: &Path,
    s3_endpoint: &str,
    object_id: &str,
    object_name: &str,
    object_folder: &[String],
) -> anyhow::Result<()> {
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
                &format!("{folder_name}/{object_name}"),
                object_id,
            )
            .await?;
            write_bytes_to_file(&folder, object_id, content.as_ref()).await?;
        }
        Ok(())
    }
}

/// This fetches the kms ethereum address from local storage
async fn fetch_kms_addresses(
    sim_conf: &CoreClientConfig,
) -> Result<Vec<alloy_primitives::Address>, Box<dyn std::error::Error + 'static>> {
    let key_id = &SIGNING_KEY_ID.to_string();
    let mut addr_bytes = Vec::with_capacity(sim_conf.object_folder.len());

    for folder_name in &sim_conf.object_folder {
        let content = fetch_object(
            &sim_conf.s3_endpoint.clone(),
            &format!("{}/{}", folder_name, "VerfAddress"),
            key_id,
        )
        .await?;
        addr_bytes.push(content);
    }

    // turn bytes read into Address type
    let kms_addrs: Vec<_> = addr_bytes
        .iter()
        .map(|x| {
            alloy_primitives::Address::parse_checksummed(
                str::from_utf8(x).unwrap_or_else(|_| {
                    panic!("cannot convert address bytes into UTF-8 string: {x:?}")
                }),
                None,
            )
            .unwrap_or_else(|e| panic!("invalid ethereum address: {x:?} - {e}"))
        })
        .collect();

    Ok(kms_addrs)
}

fn recover_address_from_ext_signature<S: SolStruct>(
    data: &S,
    domain: &Eip712Domain,
    external_sig: &[u8],
) -> anyhow::Result<alloy_primitives::Address> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // Deserialize the Signature. It reverses the call to `signature.as_bytes()` that we use for serialization.
    let sig = Signature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

    tracing::debug!("ext. signature bytes: {:x?}", external_sig);
    tracing::debug!("ext. signature: {:?}", sig);
    tracing::debug!("EIP-712 domain: {:?}", domain);

    let hash = hash_sol_struct(data, domain)?;

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("reconstructed address: {}", addr);

    Ok(addr)
}

/// check that the external signature on the keygen is valid, i.e. was made by one of the supplied addresses
fn check_standard_keyset_ext_signature(
    public_key: &CompactPublicKey,
    server_key: &ServerKey,
    prep_id: &RequestId,
    key_id: &RequestId,
    external_sig: &[u8],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let server_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, server_key)?;
    let public_key_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, public_key)?;

    let sol_type = KeygenVerification::new(prep_id, key_id, server_key_digest, public_key_digest);
    let addr = recover_address_from_ext_signature(&sol_type, domain, external_sig)?;

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!(
            "External  signature verification failed for keygen!"
        ))
    }
}

/// check that the external signature on the CRS is valid, i.e. was made by one of the supplied addresses
fn check_crsgen_ext_signature(
    crs: &CompactPkeCrs,
    crs_id: &RequestId,
    external_sig: &[u8],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let crs_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, crs)?;

    let max_num_bits = max_num_bits_from_crs(crs);
    let sol_type = CrsgenVerification::new(crs_id, max_num_bits, crs_digest);
    let addr = recover_address_from_ext_signature(&sol_type, domain, external_sig)?;

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!(
            "External  signature verification failed for keygen!"
        ))
    }
}

/// check that the external signature on the decryption result(s) is valid, i.e. was made by one of the supplied addresses
fn check_ext_pt_signature(
    external_sig: &[u8],
    plaintexts: &Vec<TypedPlaintext>,
    external_handles: Vec<Vec<u8>>,
    domain: Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
    extra_data: Vec<u8>,
) -> anyhow::Result<()> {
    // convert received data into proper format for EIP-712 verification
    if external_sig.len() != 65 {
        return Err(anyhow!(
            "Expected external signature of length 65 Bytes, but got {:?}",
            external_sig.len()
        ));
    }
    // this reverses the call to `signature.as_bytes()` that we use for serialization
    let sig = Signature::from_bytes_and_parity(external_sig, external_sig[64] & 0x01 == 0);

    tracing::debug!("ext. signature bytes: {:x?}", external_sig);
    tracing::debug!("ext. signature: {:?}", sig);
    tracing::debug!("EIP-712 domain: {:?}", domain);
    tracing::debug!("PTs: {:?}", plaintexts);
    tracing::debug!("ext. handles: {:?}", external_handles);

    let hash = compute_pt_message_hash(external_handles, plaintexts, domain, extra_data);

    let addr = sig.recover_address_from_prehash(&hash)?;
    tracing::info!("recovered address: {}", addr);

    // check that the address is in the list of known KMS addresses
    if kms_addrs.contains(&addr) {
        Ok(())
    } else {
        Err(anyhow!("External PT signature verification failed!"))
    }
}

fn check_external_decryption_signature(
    responses: &[PublicDecryptionResponse], // one response per party
    expected_answer: TypedPlaintext,
    external_handles: &[Vec<u8>],
    domain: &Eip712Domain,
    kms_addrs: &[alloy_primitives::Address],
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for response in responses {
        let payload = response.payload.as_ref().unwrap();
        check_ext_pt_signature(
            &response.external_signature,
            &payload.plaintexts,
            external_handles.to_owned(),
            domain.clone(),
            kms_addrs,
            vec![],
        )?;

        for (idx, pt) in payload.plaintexts.iter().enumerate() {
            tracing::info!(
                "Decrypt Result #{idx}: Plaintext: {:?} (Bytes: {}).",
                pt,
                hex::encode(pt.bytes.as_slice()),
            );
            results.push(pt.clone());
        }
    }

    let tp_expected = TestingPlaintext::try_from(expected_answer)?;
    for result in results {
        assert_eq!(tp_expected, TestingPlaintext::try_from(result).unwrap());
    }

    tracing::info!("Decryption response successfully processed.");
    Ok(())
}

/// retrieve public verification keys and Ethereum addresses of the MPC servers
async fn fetch_verf_keys(
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    tracing::info!("Fetching verification keys");

    // Fetch objects associated with Signature keys
    for object_name in ["VerfAddress", "VerfKey"] {
        fetch_local_key_and_write_to_file(
            destination_prefix,
            cc_conf.s3_endpoint.as_str(),
            &SIGNING_KEY_ID.to_string(),
            object_name,
            &cc_conf.object_folder,
        )
        .await?;
    }
    Ok(())
}

/// Fetch all remote objects associated with TFHE keys and store locally for the core client
async fn fetch_key(
    key_id: &str,
    sim_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    let object_names = vec![
        PubDataType::PublicKey,
        PubDataType::PublicKeyMetadata,
        PubDataType::ServerKey,
    ];
    tracing::info!("Fetching public key, server key and sns key with id {key_id}");
    for object_name in object_names {
        fetch_global_pub_object_and_write_to_file(
            destination_prefix,
            sim_conf.s3_endpoint.as_str(),
            key_id,
            &object_name.to_string(),
            sim_conf.object_folder.first().unwrap(),
        )
        .await?;
    }
    Ok(())
}

/// Fetch the remote CRS and store locally for the core client
async fn fetch_crs(
    crs_id: &str,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
) -> anyhow::Result<()> {
    tracing::info!("Fetching CRS with id {crs_id}");
    fetch_global_pub_object_and_write_to_file(
        destination_prefix,
        cc_conf.s3_endpoint.as_str(),
        crs_id,
        "CRS",
        cc_conf.object_folder.first().unwrap(),
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn do_keygen(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    kms_addrs: &[alloy_primitives::Address],
    param: FheParameter,
    preproc_id: Option<RequestId>,
    insecure: bool,
    shared_config: &SharedKeyGenParameters,
    destination_prefix: &Path,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    //NOTE: If we do not use dummy_domain here, then
    //this needs changing too in the KeyGenResult command.
    let keyset_config =
        shared_config
            .keyset_type
            .clone()
            .map(|x| kms_grpc::kms::v1::KeySetConfig {
                keyset_type: kms_grpc::kms::v1::KeySetType::from(x) as i32,
                standard_keyset_config: None,
            });
    let keyset_added_info = shared_config
        .keyset_added_info
        .clone()
        .map(kms_grpc::kms::v1::KeySetAddedInfo::from);
    let dkg_req = internal_client.key_gen_request(
        &req_id,
        preproc_id,
        Some(param),
        keyset_config,
        keyset_added_info,
        dummy_domain(),
    )?;

    //NOTE: Extract domain from request for sanity, but if we don't use dummy_domain
    //we have an issue in the (Insecure)KeyGenResult commands
    let domain = if let Some(domain) = &dkg_req.domain {
        protobuf_to_alloy_domain(domain)?
    } else {
        return Err(anyhow!("No domain provided in crsgen request"));
    };

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = dkg_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            if insecure {
                cur_client
                    .insecure_key_gen(tonic::Request::new(req_cloned))
                    .await
            } else {
                cur_client.key_gen(tonic::Request::new(req_cloned)).await
            }
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

    // get all responses
    let resp_response_vec = get_keygen_responses(
        core_endpoints,
        req_id,
        max_iter,
        insecure,
        num_expected_responses,
    )
    .await?;

    fetch_and_check_keygen(
        num_expected_responses,
        cc_conf,
        kms_addrs,
        destination_prefix,
        req_id,
        domain,
        resp_response_vec,
    )
    .await?;

    Ok(req_id)
}

#[allow(clippy::too_many_arguments)]
async fn do_crsgen(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cc_conf: &CoreClientConfig,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    kms_addrs: &[alloy_primitives::Address],
    max_num_bits: Option<u32>,
    param: FheParameter,
    insecure: bool,
    destination_prefix: &Path,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let num_expected_responses = if cmd_conf.expect_all_responses {
        num_parties
    } else {
        cc_conf.num_majority
    };

    let crs_req =
        internal_client.crs_gen_request(&req_id, max_num_bits, Some(param), &dummy_domain())?;

    //NOTE: Extract domain from request for sanity, but if we don't use dummy_domain
    //we have an issue in the (Insecure)CrsGenResult commands
    let domain = if let Some(domain) = &crs_req.domain {
        protobuf_to_alloy_domain(domain)?
    } else {
        return Err(anyhow!("No domain provided in crsgen request"));
    };

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = crs_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            if insecure {
                cur_client
                    .insecure_crs_gen(tonic::Request::new(req_cloned))
                    .await
            } else {
                cur_client.crs_gen(tonic::Request::new(req_cloned)).await
            }
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

    // get all responses
    let resp_response_vec = get_crsgen_responses(
        core_endpoints,
        req_id,
        max_iter,
        insecure,
        num_expected_responses,
    )
    .await?;

    fetch_and_check_crsgen(
        num_expected_responses,
        cc_conf,
        kms_addrs,
        destination_prefix,
        req_id,
        domain,
        resp_response_vec,
    )
    .await?;

    Ok(req_id)
}

#[allow(clippy::too_many_arguments)]
async fn do_preproc(
    internal_client: &mut Client,
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    rng: &mut AesRng,
    cmd_conf: &CmdConfig,
    num_parties: usize,
    param: FheParameter,
) -> anyhow::Result<RequestId> {
    let req_id = RequestId::new_random(rng);

    let max_iter = cmd_conf.max_iter;
    let domain = dummy_domain();
    let pp_req = internal_client.preproc_request(&req_id, Some(param), None, &domain)?; //TODO keyset config

    // make parallel requests by calling insecure keygen in a thread
    let mut req_tasks = JoinSet::new();

    for ce in core_endpoints.iter_mut() {
        let req_cloned = pp_req.clone();
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .key_gen_preproc(tonic::Request::new(req_cloned))
                .await
        });
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

    let responses = get_preproc_keygen_responses(core_endpoints, req_id, max_iter).await?;
    for response in responses {
        internal_client.process_preproc_response(&req_id, &domain, &response)?;
    }

    Ok(req_id)
}

async fn do_get_operator_pub_keys(
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
) -> anyhow::Result<Vec<String>> {
    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.iter_mut() {
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .get_operator_public_key(tonic::Request::new(kms_grpc::kms::v1::Empty {}))
                .await
        });
    }

    let mut backup_pks = Vec::with_capacity(core_endpoints.len());

    while let Some(inner) = req_tasks.join_next().await {
        let pk = inner??.into_inner();
        let attestation_doc = attestation_doc_validation::validate_and_parse_attestation_doc(
            &pk.attestation_document,
        )?;
        let Some(attested_pk) = attestation_doc.public_key else {
            anyhow::bail!("Bad response: public key not present in attestation document")
        };

        if pk.public_key.as_slice() != attested_pk.as_slice() {
            let dsep: DomainSep = *b"EQUALITY";
            let pk_hash = hex::encode(hash_element(&dsep, pk.public_key.as_slice()));
            let att_pk_hash = hex::encode(hash_element(&dsep, attested_pk.as_slice()));
            anyhow::bail!("Bad response: public key with hash {} does not match attestation document public key with hash {}", pk_hash, att_pk_hash)
        };

        backup_pks.push(hex::encode(pk.public_key.as_slice()));
    }

    Ok(backup_pks)
}

async fn do_custodian_backup_restore(
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.iter_mut() {
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .custodian_backup_restore(tonic::Request::new(kms_grpc::kms::v1::Empty {}))
                .await
        });
    }

    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(())
}

/// execute a command based on the provided configuration
pub async fn execute_cmd(
    cmd_config: &CmdConfig,
    destination_prefix: &Path,
) -> Result<Vec<(Option<RequestId>, String)>, Box<dyn std::error::Error + 'static>> {
    let client_timer_start = tokio::time::Instant::now();

    let path_to_config = cmd_config.file_conf.clone().unwrap();
    let command = &cmd_config.command;
    let max_iter = cmd_config.max_iter;
    let expect_all_responses = cmd_config.expect_all_responses;

    tracing::info!("Path to config: {:?}", &path_to_config);
    tracing::info!("Starting command: {:?}", command);
    let cc_conf: CoreClientConfig = Settings::builder()
        .path(&path_to_config)
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()?;

    tracing::info!("Core Client Config: {:?}", cc_conf);

    // if it's a public/user decryption, fetch the key and crs
    match command {
        CCCommand::PublicDecrypt(cipher_args) | CCCommand::UserDecrypt(cipher_args) => {
            tracing::info!("Fetching verification keys. ({command:?})");
            fetch_verf_keys(&cc_conf, destination_prefix).await?;

            //Only need to fetch tfhe keys if we are not sourcing the ctxt from file
            if let CipherArguments::FromArgs(cipher_params) = cipher_args {
                tracing::info!("Fetching tfhe keys. ({command:?})");
                fetch_key(&cipher_params.key_id.as_str(), &cc_conf, destination_prefix).await?;
            }
        }
        CCCommand::Encrypt(cipher_params) => {
            tracing::info!("Fetching tfhe keys. ({command:?})");
            fetch_key(&cipher_params.key_id.as_str(), &cc_conf, destination_prefix).await?;
        }
        CCCommand::KeyGen(_)
        | CCCommand::InsecureKeyGen(_)
        | CCCommand::CrsGen(_)
        | CCCommand::InsecureCrsGen(_)
        | CCCommand::PreprocKeyGen(_) => {
            tracing::info!("Fetching verification keys. ({command:?})");
            fetch_verf_keys(&cc_conf, destination_prefix).await?;
        }
        _ => {
            tracing::info!("No need to fetch key and CRS. ({command:?})");
        }
    }

    let mut rng = AesRng::from_entropy();

    let num_parties = cc_conf.core_addresses.len();

    ensure_client_keys_exist(Some(destination_prefix), &SIGNING_KEY_ID, true).await;

    let mut pub_storage: HashMap<u32, FileStorage> = HashMap::with_capacity(num_parties);
    let client_storage: FileStorage =
        FileStorage::new(Some(destination_prefix), StorageType::CLIENT, None).unwrap();
    let mut internal_client: Option<Client> = None;
    let mut core_endpoints_req = Vec::with_capacity(num_parties);
    let mut core_endpoints_resp = Vec::with_capacity(num_parties);

    let param = cc_conf.fhe_params.unwrap_or(FheParameter::Test);
    let client_param = match param {
        FheParameter::Test => TEST_PARAM,
        _ => DEFAULT_PARAM,
    };

    if let CCCommand::Encrypt(_) = command {
        //Don't need to connect if we just do an encrypt
    } else if num_parties == 1 {
        // central cores

        let address = cc_conf
            .core_addresses
            .first()
            .expect("No core address provided")
            .clone();

        tracing::info!("Centralized Core Client - connecting to: {}", address);

        // make sure address starts with http://
        let url = if address.starts_with("http://") {
            address
        } else {
            "http://".to_string() + &address
        };

        let core_endpoint_req = retry!(
            CoreServiceEndpointClient::connect(url.clone()).await,
            5,
            100
        )?;
        core_endpoints_req.push(core_endpoint_req);

        let core_endpoint_resp = retry!(
            CoreServiceEndpointClient::connect(url.clone()).await,
            5,
            100
        )?;
        core_endpoints_resp.push(core_endpoint_resp);

        // there's only 1 party, so use index 1
        pub_storage.insert(
            1,
            FileStorage::new(Some(destination_prefix), StorageType::PUB, None).unwrap(),
        );
        internal_client = Some(
            Client::new_client(
                client_storage,
                pub_storage,
                &client_param,
                cc_conf.decryption_mode,
            )
            .await
            .unwrap(),
        );
        tracing::info!("Centralized Client setup done.");
    } else {
        // threshold cores
        let addresses = cc_conf.core_addresses.clone();

        tracing::info!("Threshold Core Client - connecting to: {:?}", addresses);

        for (i, address) in addresses.iter().enumerate() {
            // make sure address starts with http://
            let url = if address.starts_with("http://") {
                address.clone()
            } else {
                "http://".to_string() + address
            };

            tracing::info!("Connecting to {:?}", url);

            let core_endpoint_req = retry!(
                CoreServiceEndpointClient::connect(url.clone()).await,
                5,
                100
            )?;
            core_endpoints_req.push(core_endpoint_req);

            let core_endpoint_resp = retry!(
                CoreServiceEndpointClient::connect(url.clone()).await,
                5,
                100
            )?;
            core_endpoints_resp.push(core_endpoint_resp);

            pub_storage.insert(
                i as u32 + 1,
                FileStorage::new(
                    Some(destination_prefix),
                    StorageType::PUB,
                    Some(Role::indexed_from_zero(i)),
                )
                .unwrap(),
            );
        }

        internal_client = Some(
            Client::new_client(
                client_storage,
                pub_storage,
                &client_param,
                cc_conf.decryption_mode,
            )
            .await
            .unwrap(),
        );

        tracing::info!("Threshold Client setup done.");
    }

    tracing::info!(
        "Parties: {}. FHE Parameters: {}",
        num_parties,
        param.as_str_name()
    );

    let kms_addrs = Arc::new(fetch_kms_addresses(&cc_conf).await?);

    let command_timer_start = tokio::time::Instant::now();

    // Execute the command
    let res = match command {
        CCCommand::PublicDecrypt(cipher_args) => {
            let internal_client = Arc::new(RwLock::new(internal_client.unwrap()));
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };

            let EncryptionResult {
                cipher: ciphertext,
                ct_format,
                plaintext: ptxt,
                key_id,
            } = match cipher_args {
                CipherArguments::FromFile(cipher_file) => {
                    fetch_ctxt_from_file(cipher_file.input_path.clone()).await?
                }
                CipherArguments::FromArgs(cipher_parameters) => {
                    encrypt(destination_prefix, cipher_parameters.clone()).await?
                }
            };

            let ct_batch = vec![
                TypedCiphertext {
                    ciphertext,
                    fhe_type: ptxt.fhe_type,
                    external_handle: dummy_handle(),
                    ciphertext_format: ct_format.into(),
                };
                cipher_args.get_batch_size()
            ];

            let mut timings_start = HashMap::new();
            let mut durations = Vec::new();

            let mut join_set: JoinSet<Result<_, anyhow::Error>> = JoinSet::new();
            let start = tokio::time::Instant::now();
            for _ in 0..cipher_args.get_num_requests() {
                let req_id = RequestId::new_random(&mut rng);
                let internal_client = internal_client.clone();
                let ct_batch = ct_batch.clone();
                let mut core_endpoints_req = core_endpoints_req.clone();
                let mut core_endpoints_resp = core_endpoints_resp.clone();
                let ptxt = ptxt.clone();
                let kms_addrs = kms_addrs.clone();

                // start timing measurement for this request
                timings_start.insert(req_id, tokio::time::Instant::now()); // start timing for this request

                join_set.spawn(async move {
                    // DECRYPTION REQUEST
                    let dec_req = internal_client.write().await.public_decryption_request(
                        ct_batch,
                        &dummy_domain(),
                        &req_id,
                        &key_id.into(),
                    )?;

                    // make parallel requests by calling [decrypt] in a thread
                    let mut req_tasks = JoinSet::new();

                    for ce in core_endpoints_req.iter_mut() {
                        let req_cloned = dec_req.clone();
                        let mut cur_client = ce.clone();
                        req_tasks.spawn(async move {
                            cur_client
                                .public_decrypt(tonic::Request::new(req_cloned))
                                .await
                        });
                    }

                    let mut req_response_vec = Vec::new();
                    while let Some(inner) = req_tasks.join_next().await {
                        req_response_vec.push(inner.unwrap().unwrap().into_inner());
                    }
                    assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

                    tracing::info!(
                        "{:?} ###! Sent all public decrypt requests. Since start {:?}",
                        req_id.as_str(),
                        start.elapsed()
                    );

                    let resp_response_vec = get_public_decrypt_responses(
                        &mut core_endpoints_resp,
                        Some(dec_req),
                        Some(ptxt),
                        req_id,
                        max_iter,
                        num_expected_responses,
                        &*internal_client.read().await,
                        &kms_addrs,
                        start,
                    )
                    .await?;

                    let res = format!("{resp_response_vec:x?}");
                    Ok((Some(req_id), res))
                });
            }

            let mut result_vec = Vec::new();
            while let Some(result) = join_set.join_next().await {
                let res = result??;
                let req_id = res.0.unwrap();
                let elapsed = timings_start.remove(&req_id).unwrap().elapsed();
                durations.push(elapsed);
                result_vec.push(res);
            }

            print_timings("public decrypt", &mut durations, start);

            result_vec
        }
        CCCommand::UserDecrypt(cipher_args) => {
            let internal_client = Arc::new(RwLock::new(
                internal_client.expect("UserDecrypt requires a KMS client"),
            ));
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_reconstruct
            };

            let EncryptionResult {
                cipher: ciphertext,
                ct_format,
                plaintext: ptxt,
                key_id,
            } = match cipher_args {
                CipherArguments::FromFile(cipher_file) => {
                    fetch_ctxt_from_file(cipher_file.input_path.clone()).await?
                }
                CipherArguments::FromArgs(cipher_parameters) => {
                    encrypt(destination_prefix, cipher_parameters.clone()).await?
                }
            };

            let ct_batch = vec![
                TypedCiphertext {
                    ciphertext,
                    fhe_type: ptxt.fhe_type,
                    external_handle: dummy_handle(),
                    ciphertext_format: ct_format.into(),
                };
                cipher_args.get_batch_size()
            ];

            do_user_decrypt(
                &mut rng,
                cipher_args.get_num_requests(),
                internal_client,
                ct_batch,
                key_id,
                core_endpoints_req.clone(),
                core_endpoints_resp.clone(),
                ptxt,
                num_parties,
                max_iter,
                num_expected_responses,
            )
            .await?
        }
        CCCommand::KeyGen(KeyGenParameters {
            preproc_id,
            shared_args,
        }) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!("Key generation with parameter {}.", param.as_str_name());
            let req_id = do_keygen(
                &mut internal_client,
                &mut core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                param,
                Some(*preproc_id),
                false,
                shared_args,
                destination_prefix,
            )
            .await?;

            vec![(Some(req_id), "keygen done".to_string())]
        }
        CCCommand::InsecureKeyGen(InsecureKeyGenParameters { shared_args }) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!(
                "Insecure key generation with parameter {}.",
                param.as_str_name()
            );
            let req_id = do_keygen(
                &mut internal_client,
                &mut core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                param,
                None,
                true,
                shared_args,
                destination_prefix,
            )
            .await?;

            vec![(Some(req_id), "insecure keygen done".to_string())]
        }
        CCCommand::CrsGen(CrsParameters { max_num_bits }) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!("CRS generation with parameter {}.", param.as_str_name());

            let req_id = do_crsgen(
                &mut internal_client,
                &mut core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                Some(*max_num_bits),
                param,
                false,
                destination_prefix,
            )
            .await?;
            vec![(Some(req_id), "crsgen done".to_string())]
        }
        CCCommand::InsecureCrsGen(CrsParameters { max_num_bits }) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!(
                "Insecure CRS generation with parameter {}.",
                param.as_str_name()
            );

            let req_id = do_crsgen(
                &mut internal_client,
                &mut core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                Some(*max_num_bits),
                param,
                true,
                destination_prefix,
            )
            .await?;
            vec![(Some(req_id), "insecure crsgen done".to_string())]
        }
        CCCommand::PreprocKeyGen(NoParameters {}) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!("Preprocessing with parameter {}.", param.as_str_name());

            let req_id = do_preproc(
                &mut internal_client,
                &mut core_endpoints_req,
                &mut rng,
                cmd_config,
                num_parties,
                param,
            )
            .await?;
            vec![(Some(req_id), "preproc done".to_string())]
        }
        CCCommand::DoNothing(NoParameters {}) => {
            tracing::info!("Nothing to do.");
            vec![(None, String::new())]
        }
        CCCommand::Encrypt(cipher_parameters) => {
            encrypt(destination_prefix, cipher_parameters.clone()).await?;
            vec![(None, "Encryption generated".to_string())]
        }
        CCCommand::PreprocKeyGenResult(result_parameters) => {
            let req_id: RequestId = result_parameters.request_id;
            let _ = get_preproc_keygen_responses(&mut core_endpoints_req, req_id, max_iter).await?;
            vec![(Some(req_id), "preproc result queried".to_string())]
        }
        CCCommand::KeyGenResult(result_parameters) => {
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };
            let req_id: RequestId = result_parameters.request_id;
            let resp_response_vec = get_keygen_responses(
                &mut core_endpoints_req,
                req_id,
                max_iter,
                false,
                num_expected_responses,
            )
            .await?;

            //NOTE: We assume the request comes from the core client too
            //which (for now) uses the dummy_domain
            fetch_and_check_keygen(
                num_expected_responses,
                &cc_conf,
                &kms_addrs,
                destination_prefix,
                req_id,
                dummy_domain(),
                resp_response_vec,
            )
            .await?;
            vec![(Some(req_id), "keygen result queried".to_string())]
        }
        CCCommand::InsecureKeyGenResult(result_parameters) => {
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };
            let req_id: RequestId = result_parameters.request_id;
            let resp_response_vec = get_keygen_responses(
                &mut core_endpoints_req,
                req_id,
                max_iter,
                true,
                num_expected_responses,
            )
            .await?;

            //NOTE: We assume the request comes from the core client too
            //which (for now) uses the dummy_domain
            fetch_and_check_keygen(
                num_expected_responses,
                &cc_conf,
                &kms_addrs,
                destination_prefix,
                req_id,
                dummy_domain(),
                resp_response_vec,
            )
            .await?;
            vec![(Some(req_id), "insecure keygen result queried".to_string())]
        }
        CCCommand::PublicDecryptResult(result_parameters) => {
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };
            let req_id: RequestId = result_parameters.request_id;
            let resp_response_vec = get_public_decrypt_responses(
                &mut core_endpoints_req,
                None,
                None,
                req_id,
                max_iter,
                num_expected_responses,
                internal_client.as_ref().unwrap(),
                &kms_addrs,
                tokio::time::Instant::now(),
            )
            .await?;
            let res = format!("{resp_response_vec:x?}");
            vec![(Some(req_id), res)]
        }
        CCCommand::CrsGenResult(result_parameters) => {
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };
            let req_id: RequestId = result_parameters.request_id;
            let resp_response_vec = get_crsgen_responses(
                &mut core_endpoints_req,
                req_id,
                max_iter,
                false,
                num_expected_responses,
            )
            .await?;

            //NOTE: We assume the request comes from the core client too
            //which (for now) uses the dummy_domain
            fetch_and_check_crsgen(
                num_expected_responses,
                &cc_conf,
                &kms_addrs,
                destination_prefix,
                req_id,
                dummy_domain(),
                resp_response_vec,
            )
            .await?;
            vec![(Some(req_id), "crs gen result queried".to_string())]
        }
        CCCommand::InsecureCrsGenResult(result_parameters) => {
            let num_expected_responses = if expect_all_responses {
                num_parties
            } else {
                cc_conf.num_majority
            };
            let req_id: RequestId = result_parameters.request_id;
            let resp_response_vec = get_crsgen_responses(
                &mut core_endpoints_req,
                req_id,
                max_iter,
                true,
                num_expected_responses,
            )
            .await?;

            //NOTE: We assume the request comes from the core client too
            //which (for now) uses the dummy_domain
            fetch_and_check_crsgen(
                num_expected_responses,
                &cc_conf,
                &kms_addrs,
                destination_prefix,
                req_id,
                dummy_domain(),
                resp_response_vec,
            )
            .await?;
            vec![(Some(req_id), "insecure crs gen result queried".to_string())]
        }
        CCCommand::GetOperatorPublicKey(NoParameters {}) => {
            let pks = do_get_operator_pub_keys(&mut core_endpoints_req).await?;
            pks.into_iter().map(|pk| (None, pk)).collect::<Vec<_>>()
        }
        CCCommand::CustodianBackupRestore(NoParameters {}) => {
            do_custodian_backup_restore(&mut core_endpoints_req).await?;
            vec![(None, "custodian backup restore complete".to_string())]
        }
    };

    tracing::info!("Core Client terminated successfully.");

    let total_duration = client_timer_start.elapsed();
    let command_duration = command_timer_start.elapsed();
    tracing::info!("Core Client command {command:?} took {total_duration:?} in total (including setup), and {command_duration:?} for the command only.");

    Ok(res)
}

// Prints the timings for the command execution, showing latency and throughput based on the measured durations.
fn print_timings(cmd: &str, durations: &mut [tokio::time::Duration], start: tokio::time::Instant) {
    // compute total time that is elapsed since we send the first request
    let total_elapsed = start.elapsed();

    // compute latency values
    let avg = durations.iter().sum::<tokio::time::Duration>() / durations.len() as u32;
    durations.sort();
    let median = if durations.len() % 2 == 0 {
        (durations[durations.len() / 2 - 1] + durations[durations.len() / 2]) / 2
    } else {
        durations[durations.len() / 2]
    };
    let min = durations[0];
    let max = durations[durations.len() - 1];

    tracing::info!(
        "Latency for {cmd}: Avg: {avg:?}, Median: {median:?}, Min: {min:?}, Max: {max:?}"
    );

    tracing::info!(
        "Total elapsed time for {cmd} with {} collected results: {total_elapsed:?}. Throughput: {} requests/s",
        durations.len(),
        durations.len() as f64 / total_elapsed.as_secs_f64()
    );

    // For debugging, print all collected durations
    tracing::debug!("All durations: {:?}", durations);
}

#[allow(clippy::too_many_arguments)]
async fn do_user_decrypt<R: Rng + CryptoRng>(
    rng: &mut R,
    num_requests: usize,
    internal_client: Arc<RwLock<Client>>,
    ct_batch: Vec<TypedCiphertext>,
    key_id: KeyId,
    core_endpoints_req: Vec<CoreServiceEndpointClient<Channel>>,
    core_endpoints_resp: Vec<CoreServiceEndpointClient<Channel>>,
    ptxt: TypedPlaintext,
    num_parties: usize,
    max_iter: usize,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<(Option<RequestId>, String)>> {
    let mut join_set: JoinSet<Result<_, anyhow::Error>> = JoinSet::new();
    let mut timings_start = HashMap::new();
    let mut durations = Vec::new();
    let start = tokio::time::Instant::now();

    for _ in 0..num_requests {
        let req_id = RequestId::new_random(rng);
        let internal_client = internal_client.clone();
        let ct_batch = ct_batch.clone();
        let mut core_endpoints_req = core_endpoints_req.clone();
        let mut core_endpoints_resp = core_endpoints_resp.clone();
        let original_plaintext = ptxt.clone();

        // start timing measurement for this request
        timings_start.insert(req_id, tokio::time::Instant::now()); // start timing for this request

        // USER_DECRYPTION REQUEST
        join_set.spawn(async move {
            let user_decrypt_req_tuple = internal_client.write().await.user_decryption_request(
                &dummy_domain(),
                ct_batch,
                &req_id,
                &key_id.into(),
            )?;

            let (user_decrypt_req, enc_pk, enc_sk) = user_decrypt_req_tuple;

            // make parallel requests by calling user decryption in a thread
            let mut req_tasks = JoinSet::new();

            for ce in &mut core_endpoints_req {
                let req_cloned = user_decrypt_req.clone();
                let mut cur_client = ce.clone();
                req_tasks.spawn(async move {
                    cur_client
                        .user_decrypt(tonic::Request::new(req_cloned))
                        .await
                });
            }

            // make sure all requests have been sent
            let mut req_response_vec = Vec::new();
            while let Some(inner) = req_tasks.join_next().await {
                req_response_vec.push(inner.unwrap().unwrap().into_inner());
            }
            assert_eq!(req_response_vec.len(), num_parties); // check that the request has reached all parties

            tracing::info!(
                "{:?} ###! Sent all user decrypt requests. Since start {:?}",
                req_id.as_str(),
                start.elapsed()
            );

            // get all responses
            let mut resp_tasks = JoinSet::new();
            for ce in &mut core_endpoints_resp {
                let mut cur_client = ce.clone();
                let req_id_clone = user_decrypt_req.request_id.as_ref().unwrap().clone();

                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete decryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        SLEEP_TIME_BETWEEN_REQUESTS_MS,
                    ))
                    .await;

                    let mut response = cur_client
                        .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                    let mut ctr = 0_usize;
                    while response.is_err()
                        && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                    {
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            SLEEP_TIME_BETWEEN_REQUESTS_MS,
                        ))
                        .await;
                        // do at most max_iter retries
                        assert!(
                            ctr < max_iter,
                            "timeout while waiting for user decryption after {max_iter} retries."
                        );
                        ctr += 1;
                        response = cur_client
                            .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }
                    (req_id_clone, response.unwrap().into_inner())
                });
            }

            // collect responses (at least num_expected_responses)
            let mut resp_response_vec = Vec::new();
            while let Some(resp) = resp_tasks.join_next().await {
                resp_response_vec.push(resp.unwrap().1);
                // break this loop and continue with the rest of the processing if we have enough responses
                if resp_response_vec.len() >= num_expected_responses {
                    break;
                }
            }

            tracing::info!(
                "{:?} ###! Received {} user decrypt responses. Since start {:?}",
                req_id.as_str(),
                resp_response_vec.len(),
                start.elapsed()
            );

            let client_request = ParsedUserDecryptionRequest::try_from(&user_decrypt_req).unwrap();
            let eip712_domain =
                protobuf_to_alloy_domain(user_decrypt_req.domain.as_ref().unwrap()).unwrap();
            let plaintexts = internal_client
                .read()
                .await
                .process_user_decryption_resp(
                    &client_request,
                    &eip712_domain,
                    &resp_response_vec,
                    &enc_pk,
                    &enc_sk,
                )
                .inspect_err(|e| {
                    tracing::error!(
                        "Error: User decryption response is NOT valid! Reason: {}",
                        e
                    )
                })?;

            // test that all results are matching the original plaintext
            for pt in &plaintexts {
                assert_eq!(
                    TestingPlaintext::try_from(pt.clone())?,
                    TestingPlaintext::try_from(original_plaintext.clone())?
                );
            }

            let decrypted_plaintext = plaintexts[0].clone();

            tracing::info!(
                "User decryption response is ok: {:?} / {:?}",
                original_plaintext,
                TestingPlaintext::try_from(decrypted_plaintext.clone())?,
            );

            let res = format!(
                "User decrypted Plaintext {:?}",
                TestingPlaintext::try_from(decrypted_plaintext)?
            );

            tracing::info!(
                "{:?} ###! Verified user decrypt responses and reconstructed. Since start {:?}",
                req_id.as_str(),
                start.elapsed()
            );

            Ok((Some(req_id), res))
        });
    }
    let mut result_vec = Vec::new();
    while let Some(result) = join_set.join_next().await {
        let res = result??;
        let req_id = res.0.unwrap();
        let elapsed = timings_start.remove(&req_id).unwrap().elapsed();
        durations.push(elapsed);
        result_vec.push(res);
    }

    print_timings("user decrypt", &mut durations, start);

    Ok(result_vec)
}

#[allow(clippy::too_many_arguments)]
async fn get_public_decrypt_responses(
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    dec_req: Option<PublicDecryptionRequest>,
    expected_answer: Option<TypedPlaintext>,
    request_id: RequestId,
    max_iter: usize,
    num_expected_responses: usize,
    internal_client: &Client,
    kms_addrs: &[alloy_primitives::Address],
    start: tokio::time::Instant,
) -> anyhow::Result<Vec<PublicDecryptionResponse>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_id, ce) in core_endpoints.iter_mut().enumerate() {
        let mut cur_client = ce.clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            let mut response = cur_client
                .get_public_decryption_result(tonic::Request::new(request_id.into()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                // do at most max_iter retries
                assert!(
                    ctr < max_iter,
                    "timeout while waiting for public decryption after {max_iter} retries."
                );
                ctr += 1;
                response = cur_client
                    .get_public_decryption_result(tonic::Request::new(request_id.into()))
                    .await;
            }
            (core_id, request_id, response.unwrap().into_inner())
        });
    }
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        let (core_id, _req_id, resp) = resp?;
        resp_response_vec.push((core_id, resp));
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }

    tracing::info!(
        "{:?} ###! Received {} public decrypt responses. Since start {:?}",
        request_id.as_str(),
        resp_response_vec.len(),
        start.elapsed()
    );

    resp_response_vec.sort_by_key(|(id, _)| *id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();

    //If an expected answer is provided consider it,
    //otherwise consider the first answer
    let ptxt = expected_answer.unwrap_or_else(|| {
        resp_response_vec
            .first()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .plaintexts
            .first()
            .unwrap()
            .clone()
    });

    let (domain, external_handles) = if let Some(decryption_request) = dec_req.as_ref() {
        let domain_msg = decryption_request.domain.as_ref().unwrap();
        let domain = protobuf_to_alloy_domain(domain_msg)?;
        // retrieve external handles from request
        let external_handles: Vec<_> = decryption_request
            .ciphertexts
            .iter()
            .map(|ct| ct.external_handle.clone())
            .collect();
        (domain, external_handles)
    } else {
        //If the decryption request isn't provided we assume it was dummy domains and handles
        let num_handles = resp_response_vec
            .first()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .plaintexts
            .len();
        (dummy_domain(), vec![dummy_handle(); num_handles])
    };

    // check the internal signatures
    internal_client.process_decryption_resp(
        dec_req,
        &resp_response_vec,
        num_expected_responses as u32,
    )?;

    // check the external signatures
    check_external_decryption_signature(
        &resp_response_vec,
        ptxt,
        &external_handles,
        &domain,
        kms_addrs,
    )
    .unwrap();

    tracing::info!(
        "{:?} ###! Verified public decypt responses. Since start {:?}",
        request_id.as_str(),
        start.elapsed()
    );

    Ok(resp_response_vec)
}

async fn get_preproc_keygen_responses(
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    request_id: RequestId,
    max_iter: usize,
) -> anyhow::Result<Vec<KeyGenPreprocResult>> {
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_id, client) in core_endpoints.iter_mut().enumerate() {
        let mut client = client.clone();
        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete preprocessing
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            let mut response = client
                .get_key_gen_preproc_result(tonic::Request::new(request_id.into()))
                .await;
            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                // do at most max_iter retries
                assert!(
                    ctr < max_iter,
                    "timeout while waiting for preprocessing after {max_iter} retries."
                );
                ctr += 1;
                response = client
                    .get_key_gen_preproc_result(tonic::Request::new(request_id.into()))
                    .await;
            }

            (core_id, request_id, response.unwrap().into_inner())
        });
    }
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        let (core_id, resp_request_id, resp_res) = resp?;
        assert_eq!(request_id, resp_request_id);
        // any failures that happen will panic here
        resp_response_vec.push((core_id, resp_res));
    }
    resp_response_vec.sort_by_key(|(id, _)| *id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    assert_eq!(resp_response_vec.len(), core_endpoints.len());
    Ok(resp_response_vec)
}

async fn get_keygen_responses(
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    request_id: RequestId,
    max_iter: usize,
    insecure: bool,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<KeyGenResult>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_id, ce) in core_endpoints.iter_mut().enumerate() {
        let mut cur_client = ce.clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;

            let mut response = if insecure {
                cur_client
                    .get_insecure_key_gen_result(tonic::Request::new(request_id.into()))
                    .await
            } else {
                cur_client
                    .get_key_gen_result(tonic::Request::new(request_id.into()))
                    .await
            };

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                assert!(ctr < max_iter, "timeout while waiting for keygen after {max_iter} retries (insecure: {insecure})");
                ctr += 1;
                response = if insecure {
                    cur_client
                        .get_insecure_key_gen_result(tonic::Request::new(request_id.into()))
                        .await
                } else {
                    cur_client
                        .get_key_gen_result(tonic::Request::new(request_id.into()))
                        .await
                };

                tracing::info!(
                    "Got response for insecure keygen: {:?} (insecure: {insecure})",
                    response
                );
            }
            (core_id, request_id, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        let (core_id, _request_id, resp) = resp?;
        resp_response_vec.push((core_id, resp));
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    resp_response_vec.sort_by_key(|(id, _)| *id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    Ok(resp_response_vec)
}

async fn get_crsgen_responses(
    core_endpoints: &mut [CoreServiceEndpointClient<Channel>],
    request_id: RequestId,
    max_iter: usize,
    insecure: bool,
    num_expected_responses: usize,
) -> anyhow::Result<Vec<CrsGenResult>> {
    // get all responses
    let mut resp_tasks = JoinSet::new();
    //We use enumerate to be able to sort the responses so they are determinstic for a given config
    for (core_id, ce) in core_endpoints.iter_mut().enumerate() {
        let mut cur_client = ce.clone();

        resp_tasks.spawn(async move {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(SLEEP_TIME_BETWEEN_REQUESTS_MS)).await;

            let mut response = if insecure {
                cur_client
                    .get_insecure_crs_gen_result(tonic::Request::new(request_id.into()))
                    .await
            } else {
                cur_client
                    .get_crs_gen_result(tonic::Request::new(request_id.into()))
                    .await
            };

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(SLEEP_TIME_BETWEEN_REQUESTS_MS)).await;
                // do at most max_iter retries
                assert!(ctr < max_iter, "timeout while waiting for crsgen after {max_iter} retries (insecure: {insecure})");
                ctr += 1;
                response = if insecure {
                    cur_client
                        .get_insecure_crs_gen_result(tonic::Request::new(request_id.into()))
                        .await
                } else {
                    cur_client
                        .get_crs_gen_result(tonic::Request::new(request_id.into()))
                        .await
                };

                tracing::info!("Got response for crsgen: {:?} (insecure: {insecure})", response);
            }
            (core_id,request_id, response.unwrap().into_inner())
        });
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        let (core_id, _request_id, resp) = resp?;
        resp_response_vec.push((core_id, resp));
        // break this loop and continue with the rest of the processing if we have enough responses
        if resp_response_vec.len() >= num_expected_responses {
            break;
        }
    }
    resp_response_vec.sort_by_key(|(id, _)| *id);
    let resp_response_vec: Vec<_> = resp_response_vec
        .into_iter()
        .map(|(_, resp)| resp)
        .collect();
    Ok(resp_response_vec)
}

async fn fetch_and_check_keygen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    request_id: RequestId,
    domain: Eip712Domain,
    responses: Vec<KeyGenResult>,
) -> anyhow::Result<()> {
    assert!(
        responses.len() >= num_expected_responses,
        "Expected at least {} responses, but got only {}",
        num_expected_responses,
        responses.len()
    );

    // Download the generated keys. We do this just once, to save time, assuming that all generated keys are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all keys and compare them.
    fetch_key(&request_id.to_string(), cc_conf, destination_prefix).await?;
    let public_key = load_pk_from_storage(Some(destination_prefix), &request_id).await;
    let server_key = load_server_key_from_storage(Some(destination_prefix), &request_id).await;

    for response in responses {
        let resp_req_id: RequestId = response.request_id.try_into()?;
        tracing::info!("Received KeyGenResult with request ID {}", resp_req_id); //TODO print key digests and signatures?

        assert_eq!(
            request_id, resp_req_id,
            "Request ID of response does not match the transaction"
        );

        let external_signature = response.external_signature;
        let prep_id = response.preprocessing_id.ok_or(anyhow!(
            "No preprocessing ID in keygen response, cannot verify external signature"
        ))?;
        check_standard_keyset_ext_signature(
            &public_key,
            &server_key,
            &prep_id.try_into()?,
            &request_id,
            &external_signature,
            &domain,
            kms_addrs,
        )?;

        tracing::info!("EIP712 verification of Public Key and Server Key successful.");
    }
    Ok(())
}

async fn fetch_and_check_crsgen(
    num_expected_responses: usize,
    cc_conf: &CoreClientConfig,
    kms_addrs: &[alloy_primitives::Address],
    destination_prefix: &Path,
    request_id: RequestId,
    domain: Eip712Domain,
    responses: Vec<CrsGenResult>,
) -> anyhow::Result<()> {
    assert!(
        responses.len() >= num_expected_responses,
        "Expected at least {} responses, but got only {}",
        num_expected_responses,
        responses.len()
    );

    // Download the generated keys. We do this just once, to save time, assuming that all generated keys are indentical.
    // If we want to test for malicious behavior in the threshold case, we need to download all keys and compare them.
    fetch_crs(&request_id.to_string(), cc_conf, destination_prefix).await?;
    let crs = load_crs_from_storage(Some(destination_prefix), &request_id).await;

    for response in responses {
        let resp_req_id: RequestId = response.request_id.try_into()?;
        tracing::info!("Received CrsGenResult with request ID {}", resp_req_id); //TODO print key digests and signatures?

        assert_eq!(
            request_id, resp_req_id,
            "Request ID of response does not match the transaction"
        );
        let external_signature = response.external_signature;

        check_crsgen_ext_signature(&crs, &request_id, &external_signature, &domain, kms_addrs)?;

        tracing::info!("EIP712 verification of CRS successful.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::k256::ecdsa::SigningKey;
    use kms_grpc::rpc_types::PrivDataType;
    use kms_lib::{
        consts::{TEST_CENTRAL_CRS_ID, TEST_PARAM},
        cryptography::internal_crypto_types::PrivateSigKey,
        engine::base::compute_external_pubdata_signature,
        util::key_setup::{ensure_central_crs_exists, ensure_central_server_signing_keys_exist},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };
    use std::{env, str::FromStr};
    use tfhe::zk::CompactPkeCrs;
    use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;

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

    #[test]
    fn test_core_client_config() {
        let path_to_config = "config/client_local_centralized.toml".to_string();
        tracing::info!("Path to config: {:?}", &path_to_config);
        let cc_conf_test: CoreClientConfig = Settings::builder()
            .path(&path_to_config)
            .env_prefix("CORE_CLIENT")
            .build()
            .init_conf()
            .unwrap();

        tracing::info!("Core Client Config: {:?}", cc_conf_test);
        // check that the fhe_params value from the config toml ("Default") is read correctly
        assert_eq!(cc_conf_test.fhe_params, Some(FheParameter::Default));

        // now set the env variable that overwrites fhe_params with "Test", which should take precedence if it's set
        env::set_var("CORE_CLIENT__FHE_PARAMS", "Test");

        let cc_conf_default: CoreClientConfig = Settings::builder()
            .path(&path_to_config)
            .env_prefix("CORE_CLIENT")
            .build()
            .init_conf()
            .unwrap();

        // check that the fhe_params value from the env var ("Test") is read correctly, even if the toml contains "Default"
        assert_eq!(cc_conf_default.fhe_params, Some(FheParameter::Test));
    }

    #[tokio::test]
    async fn test_eip712_sigs() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        // make sure signing keys exist
        ensure_central_server_signing_keys_exist(
            &mut pub_storage,
            &mut priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;

        // compute a small CRS for testing
        let crs_id = &TEST_CENTRAL_CRS_ID;
        ensure_central_crs_exists(
            &mut pub_storage,
            &mut priv_storage,
            TEST_PARAM,
            crs_id,
            true,
        )
        .await;
        let crs: CompactPkeCrs = read_versioned_at_request_id(
            &pub_storage,
            &RequestId::from_str(&crs_id.to_string()).unwrap(),
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();

        // read generated private signature key, derive public verifcation key and address from it
        let sk: PrivateSigKey = read_versioned_at_request_id(
            &priv_storage,
            &RequestId::from_str(&SIGNING_KEY_ID.to_string()).unwrap(),
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        let pk = SigningKey::verifying_key(sk.sk());
        let addr = alloy_signer::utils::public_key_to_address(pk);

        // set up a dummy EIP 712 domain
        let domain = alloy_sol_types::eip712_domain!(
            name: "dummy-test",
            version: "1",
            chain_id: 0,
            verifying_contract: alloy_primitives::Address::ZERO,
            // No salt
        );

        let max_num_bits = max_num_bits_from_crs(&crs);
        let crs_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &crs).unwrap();
        let crs_sol_struct = CrsgenVerification::new(crs_id, max_num_bits, crs_digest);

        // sign with EIP712
        let external_sig =
            compute_external_pubdata_signature(&sk, &crs_sol_struct, &domain).unwrap();

        // check that the signature verifies and unwraps without error
        check_crsgen_ext_signature(&crs, crs_id, &external_sig, &domain, &[addr]).unwrap();

        // check that verification fails for a wrong address
        let wrong_address = alloy_primitives::address!("0EdA6bf26964aF942Eed9e03e53442D37aa960EE");
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &external_sig, &domain, &[wrong_address])
                .unwrap_err()
                .to_string()
                .contains("External crs/pubkey signature verification failed!")
        );

        // check that verification fails for signature that is too short
        let short_sig = [0_u8; 37];
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &short_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("Expected external signature of length 65 Bytes, but got 37")
        );

        // check that verification fails for a byte string that is not a signature
        let malformed_sig = [23_u8; 65];
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &malformed_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("signature error")
        );

        // check that verification fails for a signature that does not match the message
        let wrong_sig = hex::decode("cf92fe4c0b7c72fd8571c9a6680f2cd7481ebed7a3c8c7c7a6e6eaf27f5654f36100c146e609e39950953602ed73a3c10c1672729295ed8b33009b375813e5801b").unwrap();
        assert!(
            check_crsgen_ext_signature(&crs, crs_id, &wrong_sig, &domain, &[addr])
                .unwrap_err()
                .to_string()
                .contains("External crs/pubkey signature verification failed!")
        );
    }
}
