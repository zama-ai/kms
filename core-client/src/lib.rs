/// Core Client library
///
/// This library implements most functionalities to interact with deployed KMS cores.
/// This library also includes an associated CLI.
mod backup;
mod crsgen;
mod decrypt;
mod keygen;
pub mod mpc_context;
mod prss_init;
mod reshare;
mod s3_operations;

// reexport fetch_public_elements for integration test
pub use crate::s3_operations::fetch_public_elements;

use crate::backup::{
    do_custodian_backup_recovery, do_custodian_recovery_init, do_get_operator_pub_keys,
    do_new_custodian_context, do_restore_from_backup,
};
use crate::crsgen::{do_crsgen, fetch_and_check_crsgen, get_crsgen_responses};
use crate::decrypt::{do_public_decrypt, do_user_decrypt, get_public_decrypt_responses};
use crate::keygen::{
    do_keygen, do_partial_preproc, do_preproc, fetch_and_check_keygen, get_keygen_responses,
    get_preproc_keygen_responses,
};
use crate::mpc_context::do_new_mpc_context;
use crate::prss_init::do_prss_init;
use crate::reshare::do_reshare;
use aes_prng::AesRng;
use clap::{Args, Parser, Subcommand, ValueEnum};
use core::str;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::{CiphertextFormat, FheParameter, TypedCiphertext, TypedPlaintext};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{ContextId, KeyId, RequestId};
use kms_lib::backup::custodian::{InternalCustodianRecoveryOutput, InternalCustodianSetupMessage};
use kms_lib::client::client_wasm::Client;
use kms_lib::consts::{DEFAULT_PARAM, SIGNING_KEY_ID, TEST_PARAM};
use kms_lib::util::file_handling::{
    read_element, safe_read_element_versioned, safe_write_element_versioned, write_element,
};
use kms_lib::util::key_setup::{
    ensure_client_keys_exist,
    test_tools::{compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext},
};
use kms_lib::vault::storage::{file::FileStorage, StorageType};
use kms_lib::vault::storage::{make_storage, read_text_at_request_id};
use kms_lib::vault::Vault;
use kms_lib::{conf, DecryptionMode};
use observability::conf::Settings;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Once};
use strum_macros::{Display, EnumString};
use tfhe::FheTypes as TfheFheType;
use threshold_fhe::execution::runtime::party::Role;
use tokio::sync::RwLock;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use validator::{Validate, ValidationError};

// time to sleep between retries of requests in milliseconds
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

#[derive(Serialize, Clone, Validate, Debug)]
#[validate(schema(function = validate_core_client_conf))]
pub struct CoreClientConfig {
    // The mode of the KMS ("centralized" or "threshold"). Threshold by default.
    pub kms_type: KmsType,
    // List of configurations for the cores
    #[validate(length(min = 1))]
    pub cores: Vec<CoreConf>,
    pub decryption_mode: Option<DecryptionMode>,
    #[validate(range(min = 1))]
    pub num_majority: usize,
    #[validate(range(min = 1))]
    pub num_reconstruct: usize,
    pub fhe_params: Option<FheParameter>,
}

#[derive(Deserialize, Serialize, Clone, Validate, Default, Debug)]
pub struct CoreConf {
    /// The ID of the given KMS server (monotonically increasing positive integer starting at 1)
    #[validate(range(min = 1))]
    pub party_id: usize,
    /// The address of the given KMS server, including the port
    #[validate(length(min = 1))]
    pub address: String,
    /// The S3 endpoint where the public material of the given server can be reached
    #[validate(length(min = 1))]
    pub s3_endpoint: String,

    /// The folder at the S3 endpoint where the data is stored.
    pub object_folder: String,

    #[cfg(feature = "testing")]
    /// The folder at the S3 endpoint where the private data is stored.
    /// This is only used for testing context switching.
    pub private_object_folder: Option<String>,

    #[cfg(feature = "testing")]
    /// The path for the KMS configuration file,
    /// this is only needed for testing context switching.
    pub config_path: Option<PathBuf>,
}

fn validate_core_client_conf(conf: &CoreClientConfig) -> Result<(), ValidationError> {
    // The number of parties in the configuration, this may not be the actual number of KMS parties IRL. But is just the ones we currently communicate with.
    let num_parties = conf.cores.len();

    for cur_core in &conf.cores {
        if cur_core.party_id == 0 || cur_core.party_id > num_parties {
            return Err(ValidationError::new("Incorrect Party ID").with_message(
                format!(
                    "Party ID must be between 1 and the number of parties ({}), but was {}.",
                    num_parties, cur_core.party_id
                )
                .into(),
            ));
        }
        if conf
            .cores
            .iter()
            .filter(|x| x.party_id == cur_core.party_id)
            .count()
            > 1
        {
            return Err(ValidationError::new("Duplicate Party ID").with_message(
                format!(
                    "Party ID {} is duplicated in the configuration.",
                    cur_core.party_id
                )
                .into(),
            ));
        }
        if conf
            .cores
            .iter()
            .filter(|x| x.address == cur_core.address)
            .count()
            > 1
        {
            return Err(ValidationError::new("Duplicate Address").with_message(
                format!(
                    "Address {} is duplicated in the configuration.",
                    cur_core.address
                )
                .into(),
            ));
        }
    }
    if conf.num_majority > num_parties {
        return Err(ValidationError::new("Majority Vote Count Error").with_message(format!("Number for majority votes ({}) must be smaller than or equal to the number of parties the CLI communicates with ({}).", conf.num_majority, num_parties).into()));
    }
    if conf.num_reconstruct > num_parties {
        return Err(ValidationError::new("Reconstruction Count Error").with_message(format!("Number for reconstruction shares ({}) must be smaller than or equal to the number of parties the CLI communicates with ({}).", conf.num_reconstruct, num_parties).into()));
    }
    if conf.num_reconstruct < conf.num_majority {
        return Err(ValidationError::new("Reconstruction Count Error").with_message(format!("Number for reconstruction shares ({}) must be greater than or equal to the number of majority votes ({}).", conf.num_reconstruct, conf.num_majority).into()));
    }

    if num_parties > 1 {
        // Should be a threshold config
        if conf.kms_type != KmsType::Threshold {
            return Err(ValidationError::new("KMS Type Error").with_message(format!("KMS mode must be 'threshold' when there are multiple cores ({} cores configured).", num_parties).into()));
        }
    } else {
        // We may be in the centralized or threshold mode (communicating with a single server)
        if conf.kms_type == KmsType::Centralized {
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
            if conf.cores.first().expect("no party IDs found").party_id != 1 {
                return Err(
                    ValidationError::new("Centralized Party ID Error").with_message(
                        format!(
                    "Party ID of the single core in a centralized config must be 1, but was {}.",
                    conf.cores.first().unwrap().party_id
                )
                        .into(),
                    ),
                );
            }
        }
    }

    Ok(())
}

impl<'de> Deserialize<'de> for CoreClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Clone, Debug)]
        pub struct CoreClientConfigBuffer {
            // The mode of the KMS ("centralized" or "threshold"). Threshold by default.
            pub kms_type: KmsType,
            // List of configurations for the cores
            pub cores: Vec<CoreConf>,
            pub decryption_mode: Option<DecryptionMode>,
            pub num_majority: usize,
            pub num_reconstruct: usize,
            pub fhe_params: Option<FheParameter>,
        }

        let temp = CoreClientConfigBuffer::deserialize(deserializer)?;

        let conf = CoreClientConfig {
            kms_type: temp.kms_type,
            cores: temp.cores,
            decryption_mode: temp.decryption_mode,
            num_majority: temp.num_majority,
            num_reconstruct: temp.num_reconstruct,
            fhe_params: temp.fhe_params,
        };

        conf.validate().map_err(serde::de::Error::custom)?;

        Ok(conf)
    }
}

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

/// Initialize the PRSS for a given context and epoch.
///
/// This command will be deprecated and be combined with the resharing command.
#[derive(Debug, Parser, Clone)]
pub struct PrssInitParameters {
    /// Optionally specify the context ID to use for the PRSS initialization.
    /// Defaults to the default epoch if not specified.
    #[clap(long)]
    pub context_id: ContextId,
    /// Optionally specify the epoch ID to use for the PRSS initialization.
    /// Defaults to the default epoch if not specified.
    /// The PRSS will be stored under the epoch ID.
    #[clap(long)]
    pub epoch_id: EpochId,
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
    /// Expected one of ebool, euint8, ..., euint256
    #[clap(long, short = 'd')]
    pub data_type: FheType,
    /// Disable ciphertext compression. Default: False, i.e. compression is used.
    #[clap(long, alias = "nc")]
    pub no_compression: bool,
    /// Disable SnS preprocessing on the ciphertext on the core-client.
    /// SnS preprocessing performs a PBS to convert 64-bit ciphertexts to 128-bit ones.
    /// Default: False, i.e. the SnS is precomputed on the core client.
    #[clap(long, alias = "ns")]
    pub no_precompute_sns: bool,
    /// Key identifier to use for public/user decryption.
    #[clap(long, short = 'k')]
    pub key_id: KeyId,
    /// Optionally specify the context ID to use for the decryption.
    /// If not specified, the default context will be used.
    #[clap(long)]
    pub context_id: Option<ContextId>,
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
    // TODO(#2799)
    // DecompressionOnly, // we'll support this in the future
}

impl From<KeySetType> for kms_grpc::kms::v1::KeySetType {
    fn from(value: KeySetType) -> Self {
        match value {
            KeySetType::Standard => kms_grpc::kms::v1::KeySetType::Standard,
        }
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct SharedKeyGenParameters {
    #[clap(value_enum, long, short = 't')]
    pub keyset_type: Option<KeySetType>,
    // TODO(#2799)
    // #[command(flatten)]
    // pub keyset_added_info: Option<KeySetAddedInfo>,
    pub context_id: Option<ContextId>,
    pub epoch_id: Option<EpochId>,
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
pub struct NewCustodianContextParameters {
    #[clap(long, short = 't')]
    pub threshold: u32,
    #[clap(long, short = 'm')]
    pub setup_msg_paths: Vec<PathBuf>,
}
#[derive(Debug, Args, Clone)]
pub struct ContextPath {
    /// Input file of the ciphertext.
    #[clap(long)]
    pub input_path: PathBuf,
}

#[derive(Debug, Subcommand, Clone)]
pub enum NewMpcContextParameters {
    /// Safe Serialized version of the struct ContextInfo
    /// stored in a file.
    SerializedContextPath(ContextPath),
    ContextToml(ContextPath),
}

#[derive(Debug, Parser, Clone)]
pub struct NewTestingMpcContextFileParameters {
    /// The context ID to use for the new MPC context.
    #[clap(long)]
    pub context_id: ContextId,

    /// The path to store the context.
    #[clap(long)]
    pub context_path: PathBuf,
}

#[derive(Debug, Parser, Clone)]
pub struct ResultParameters {
    #[clap(long, short = 'i')]
    pub request_id: RequestId,
}

#[derive(Debug, Parser, Clone)]
pub struct RecoveryInitParameters {
    /// Indicator as to whether the KMS should overwrite a possible existing ephemeral key
    /// If false, the call will be indempotent, if true, this will not be the case
    #[clap(long, short = 'o', default_value_t = false)]
    pub overwrite_ephemeral_key: bool,
    /// Paths to write the operator responses, the responses stored in these paths are not ordered.
    #[clap(long, short = 'r')]
    pub operator_recovery_resp_paths: Vec<PathBuf>,
}

#[derive(Debug, Parser, Clone)]

pub struct RecoveryParameters {
    #[clap(long, short = 'i')]
    pub custodian_context_id: RequestId,
    #[clap(long, short = 'r')]
    pub custodian_recovery_outputs: Vec<PathBuf>,
}

#[derive(Debug, Parser, Clone)]
pub struct ReshareParameters {
    /// ID of the key to reshare
    #[clap(long, short = 'k')]
    pub key_id: RequestId,

    /// ID of the preprocessing used to generate the key
    #[clap(long, short = 'i')]
    pub preproc_id: RequestId,

    /// The context ID to do the resharing from.
    /// If it's not given then the default context is used.
    #[clap(long)]
    pub from_context_id: Option<ContextId>,

    /// The epoch ID to do the resharing from.
    /// If it's not given then the default epoch is used.
    #[clap(long)]
    pub from_epoch_id: Option<EpochId>,

    /// The hex-encoded server key digest to use for resharing.
    #[clap(long)]
    pub server_key_digest: String,

    /// The hex-encoded public key digest to use for resharing.
    #[clap(long)]
    pub public_key_digest: String,
}

#[derive(Debug, Parser, Clone)]
pub struct KeyGenPreprocParameters {
    /// Optionally specify the context ID to use for the preprocessing.
    /// Defaults to the default context if not specified.
    #[clap(long)]
    pub context_id: Option<ContextId>,
    /// Optionally specify the epoch ID to use for the preprocessing.
    /// Defaults to the default epoch if not specified.
    #[clap(long)]
    pub epoch_id: Option<EpochId>,
}

#[derive(Debug, Parser, Clone)]
pub struct PartialKeyGenPreprocParameters {
    #[clap(long)]
    pub context_id: Option<ContextId>,
    #[clap(long)]
    pub epoch_id: Option<EpochId>,
    /// Percentage of offline phase to run (0-100)
    #[clap(long, short = 'p')]
    pub percentage_offline: u32,
    /// Whether to store dummy preprocessing, needed to run online DKG if percentage is not 100
    #[clap(long, short = 's')]
    pub store_dummy_preprocessing: bool,
}

#[derive(Debug, Subcommand, Clone)]
pub enum CCCommand {
    PreprocKeyGen(KeyGenPreprocParameters),
    PartialPreprocKeyGen(PartialKeyGenPreprocParameters),
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
    NewCustodianContext(NewCustodianContextParameters),
    GetOperatorPublicKey(NoParameters),
    CustodianRecoveryInit(RecoveryInitParameters),
    CustodianBackupRecovery(RecoveryParameters),
    BackupRestore(NoParameters),
    Reshare(ReshareParameters),
    #[clap(subcommand)]
    NewMpcContext(NewMpcContextParameters),
    PrssInit(PrssInitParameters),
    #[cfg(feature = "testing")]
    NewTestingMpcContextFile(NewTestingMpcContextFileParameters),
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
    /// Set this if you expect a response from every KMS core
    #[clap(long, short = 'a', default_value_t = false)]
    pub expect_all_responses: bool,
    /// Set this if you want to download the generated keys/CRSes from all KMS cores
    #[clap(long, short = 'd', default_value_t = false)]
    pub download_all: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString, Display)]
pub enum KmsType {
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

// dummy ciphertext handle for testing
fn dummy_handle() -> Vec<u8> {
    vec![23_u8; 32]
}

pub struct EncryptionResult {
    pub cipher: Vec<u8>,
    pub ct_format: CiphertextFormat,
    pub plaintext: TypedPlaintext,
    pub key_id: KeyId,
    pub context_id: Option<ContextId>,
}

impl EncryptionResult {
    pub fn new(
        cipher: Vec<u8>,
        ct_format: CiphertextFormat,
        plaintext: TypedPlaintext,
        key_id: KeyId,
        context_id: Option<ContextId>,
    ) -> Self {
        Self {
            cipher,
            ct_format,
            plaintext,
            key_id,
            context_id,
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
        .ok_or_else(|| anyhow::anyhow!("Failed to recover ct_format"))?;

    let key_id = cipher_with_params.params.key_id;
    let context_id = cipher_with_params.params.context_id;
    Ok(EncryptionResult::new(
        cipher_with_params.cipher,
        ct_format,
        ptxt,
        key_id,
        context_id,
    ))
}

/// encrypt a given value and return the ciphertext
/// parameters:
/// - `keys_folder`: the root of the storage of the core client
/// - `party_id`: the 1-indexed ID of the KMS core whose public keys we will use (should not matter as long as the server is online)
pub async fn encrypt(
    keys_folder: &Path,
    party_id: usize,
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
        party_id,
        EncryptionConfig {
            compression: !cipher_params.no_compression,
            precompute_sns: !cipher_params.no_precompute_sns,
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
        cipher_params.context_id,
    ))
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

/// This reads the kms ethereum address from local file system
async fn read_kms_addresses_local(
    path: &Path,
    sim_conf: &CoreClientConfig,
) -> Result<Vec<alloy_primitives::Address>, Box<dyn std::error::Error + 'static>> {
    let mut addr_strings = Vec::with_capacity(sim_conf.cores.len());

    for cur_core in &sim_conf.cores {
        // NOTE: [cur_core.party_id] might not match the storage path, as a workaround,
        // if the kms config exists, then use the my_id field from there.
        let storage_role = {
            #[cfg(feature = "testing")]
            match cur_core.config_path {
                Some(ref p) => {
                    let core_config: conf::CoreConfig =
                        conf::init_conf(p.to_str().expect("expect core config path")).unwrap();
                    Role::indexed_from_one(
                        core_config
                            .threshold
                            .expect("expect threshold config")
                            .my_id,
                    )
                }
                None => Role::indexed_from_one(cur_core.party_id),
            }
            #[cfg(not(feature = "testing"))]
            Role::indexed_from_one(cur_core.party_id)
        };

        let vault = {
            let store_path = Some(conf::Storage::File(conf::FileStorage {
                path: path.to_path_buf(),
            }));
            let optional_storage_role = match sim_conf.kms_type {
                KmsType::Centralized => None, // in centralized mode, there is only one party, so no need to specify role to access the right storage
                KmsType::Threshold => Some(storage_role),
            };
            let storage = make_storage(
                store_path,
                StorageType::PUB,
                optional_storage_role,
                None,
                None,
            )?;
            Vault {
                storage,
                keychain: None,
            }
        };

        let content = read_text_at_request_id(
            &vault,
            &SIGNING_KEY_ID,
            &PubDataType::VerfAddress.to_string(),
        )
        .await?;
        addr_strings.push(content);
    }

    // turn the read bytes into Address type
    let kms_addrs: Vec<_> = addr_strings
        .iter()
        .map(|x| {
            alloy_primitives::Address::parse_checksummed(x, None)
                .unwrap_or_else(|e| panic!("invalid ethereum address: {x:?} - {e}"))
        })
        .collect();

    Ok(kms_addrs)
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

    let mut rng = AesRng::from_entropy();
    let num_parties = cc_conf.cores.len();

    ensure_client_keys_exist(Some(destination_prefix), &SIGNING_KEY_ID, true).await;

    let mut pub_storage: HashMap<u32, FileStorage> = HashMap::with_capacity(num_parties);
    let client_storage: FileStorage =
        FileStorage::new(Some(destination_prefix), StorageType::CLIENT, None).unwrap();
    let mut internal_client: Option<Client> = None;
    let mut core_endpoints_req = HashMap::with_capacity(num_parties);
    let mut core_endpoints_resp = HashMap::with_capacity(num_parties);

    // use secure default params if nothing is set
    let fhe_params = cc_conf.fhe_params.unwrap_or(FheParameter::Default);
    let client_param = match fhe_params {
        FheParameter::Test => TEST_PARAM,
        _ => DEFAULT_PARAM,
    };

    // Vector of KMS ethereum addresses
    let mut addr_vec = Vec::new();

    if let CCCommand::Encrypt(_) = command {
        //Don't need to fetch or connect if we just do an encrypt
    } else if let CCCommand::DoNothing(_) = command {
        // Don't need to fetch or connect if we just do nothing
    } else {
        // Otherwise always fetch the public verfication keys, as otherwise the internal Client will complain when being constructed as it cannot validate the connection with the servers
        tracing::info!("Fetching verification keys. ({command:?})");
        let public_verf_types = vec![PubDataType::VerfAddress, PubDataType::VerfKey];
        let _ = fetch_public_elements(
            &SIGNING_KEY_ID.to_string(),
            &public_verf_types,
            &cc_conf,
            destination_prefix,
            true, // we always need to download all verification keys
        )
        .await?;

        // read the addresses we just fetched from disk
        addr_vec.append(&mut read_kms_addresses_local(destination_prefix, &cc_conf).await?);

        match cc_conf.kms_type {
            KmsType::Centralized => {
                let address = cc_conf
                    .cores
                    .first()
                    .expect("No core address provided")
                    .address
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
                // Centralized is always party 1
                core_endpoints_req.insert(1, core_endpoint_req);

                let core_endpoint_resp = retry!(
                    CoreServiceEndpointClient::connect(url.clone()).await,
                    5,
                    100
                )?;
                core_endpoints_resp.insert(1, core_endpoint_resp);

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
            }
            KmsType::Threshold => {
                // threshold cores
                tracing::info!(
                    "Threshold Core Client - connecting to n={:?} KMS servers",
                    cc_conf.cores.len()
                );

                for cur_core in &cc_conf.cores {
                    // make sure address starts with http://
                    let url = if cur_core.address.starts_with("http://") {
                        cur_core.address.clone()
                    } else {
                        "http://".to_string() + cur_core.address.as_str()
                    };

                    tracing::info!(
                        "Connecting to party {:?} via URL {:?}",
                        cur_core.party_id,
                        url
                    );

                    let core_endpoint_req = retry!(
                        CoreServiceEndpointClient::connect(url.clone()).await,
                        5,
                        100
                    )?;
                    core_endpoints_req.insert(cur_core.party_id as u32, core_endpoint_req);

                    let core_endpoint_resp = retry!(
                        CoreServiceEndpointClient::connect(url.clone()).await,
                        5,
                        100
                    )?;
                    core_endpoints_resp.insert(cur_core.party_id as u32, core_endpoint_resp);

                    // NOTE: [cur_core.party_id] might not match the storage path, as a workaround,
                    // if the kms config exists, then use the my_id field from there.
                    let storage_role = {
                        #[cfg(feature = "testing")]
                        match cur_core.config_path {
                            Some(ref p) => {
                                let core_config: conf::CoreConfig =
                                    conf::init_conf(p.to_str().expect("expect core config path"))
                                        .unwrap();
                                Role::indexed_from_one(
                                    core_config
                                        .threshold
                                        .expect("expect threshold config")
                                        .my_id,
                                )
                            }
                            None => Role::indexed_from_one(cur_core.party_id),
                        }
                        #[cfg(not(feature = "testing"))]
                        Role::indexed_from_one(cur_core.party_id)
                    };
                    pub_storage.insert(
                        cur_core.party_id as u32,
                        FileStorage::new(
                            Some(destination_prefix),
                            StorageType::PUB,
                            Some(storage_role),
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
        };
    }
    tracing::info!(
        "Parties: {}. FHE Parameters: {}",
        num_parties,
        fhe_params.as_str_name()
    );

    let kms_addrs = Arc::new(addr_vec);

    let key_types = vec![
        PubDataType::PublicKey,
        PubDataType::PublicKeyMetadata,
        PubDataType::ServerKey,
    ];

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
                context_id,
            } = match cipher_args {
                CipherArguments::FromFile(cipher_file) => {
                    fetch_ctxt_from_file(cipher_file.input_path.clone()).await?
                }
                CipherArguments::FromArgs(cipher_parameters) => {
                    //Only need to fetch tfhe keys if we are not sourcing the ctxt from file
                    tracing::info!("Fetching keys {key_types:?}. ({command:?})");
                    let party_ids = fetch_public_elements(
                        &cipher_parameters.key_id.as_str(),
                        &key_types,
                        &cc_conf,
                        destination_prefix,
                        false,
                    )
                    .await?;
                    encrypt(
                        destination_prefix,
                        *party_ids.first().expect("no party IDs found"),
                        cipher_parameters.clone(),
                    )
                    .await?
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

            do_public_decrypt(
                &mut rng,
                cipher_args.get_num_requests(),
                internal_client,
                ct_batch,
                key_id,
                context_id,
                &core_endpoints_req,
                &core_endpoints_resp,
                ptxt,
                num_parties,
                kms_addrs.to_vec(),
                max_iter,
                num_expected_responses,
            )
            .await?
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
                context_id,
            } = match cipher_args {
                CipherArguments::FromFile(cipher_file) => {
                    fetch_ctxt_from_file(cipher_file.input_path.clone()).await?
                }
                CipherArguments::FromArgs(cipher_parameters) => {
                    //Only need to fetch tfhe keys if we are not sourcing the ctxt from file
                    tracing::info!("Fetching keys {key_types:?}. ({command:?})");
                    let party_ids = fetch_public_elements(
                        &cipher_parameters.key_id.as_str(),
                        &key_types,
                        &cc_conf,
                        destination_prefix,
                        false,
                    )
                    .await?;
                    encrypt(
                        destination_prefix,
                        *party_ids.first().expect("no party IDs found"),
                        cipher_parameters.clone(),
                    )
                    .await?
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
                context_id,
                &core_endpoints_req,
                &core_endpoints_resp,
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
            tracing::info!(
                "Key generation with parameter {}.",
                fhe_params.as_str_name()
            );
            let req_id = do_keygen(
                &mut internal_client,
                &core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                fhe_params,
                *preproc_id,
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
                fhe_params.as_str_name()
            );
            let dummy_preproc_id = RequestId::new_random(&mut rng);
            let req_id = do_keygen(
                &mut internal_client,
                &core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                fhe_params,
                dummy_preproc_id,
                true,
                shared_args,
                destination_prefix,
            )
            .await?;

            vec![(Some(req_id), "insecure keygen done".to_string())]
        }
        CCCommand::CrsGen(CrsParameters { max_num_bits }) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!(
                "CRS generation with parameter {}.",
                fhe_params.as_str_name()
            );

            let req_id = do_crsgen(
                &mut internal_client,
                &core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                Some(*max_num_bits),
                fhe_params,
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
                fhe_params.as_str_name()
            );

            let req_id = do_crsgen(
                &mut internal_client,
                &core_endpoints_req,
                &mut rng,
                &cc_conf,
                cmd_config,
                num_parties,
                &kms_addrs,
                Some(*max_num_bits),
                fhe_params,
                true,
                destination_prefix,
            )
            .await?;
            vec![(Some(req_id), "insecure crsgen done".to_string())]
        }
        CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id,
            epoch_id,
        }) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!("Preprocessing with parameter {}.", fhe_params.as_str_name());

            let req_id = do_preproc(
                &mut internal_client,
                &core_endpoints_req,
                &mut rng,
                cmd_config,
                num_parties,
                fhe_params,
                context_id.as_ref(),
                epoch_id.as_ref(),
            )
            .await?;
            vec![(Some(req_id), "preproc done".to_string())]
        }
        CCCommand::PartialPreprocKeyGen(partial_params) => {
            let mut internal_client = internal_client.unwrap();
            tracing::info!(
                "Partial Preprocessing with parameter {} (running {}% , storing dummy: {}).",
                fhe_params.as_str_name(),
                partial_params.percentage_offline,
                partial_params.store_dummy_preprocessing
            );

            let req_id = do_partial_preproc(
                &mut internal_client,
                &core_endpoints_req,
                &mut rng,
                cmd_config,
                num_parties,
                fhe_params,
                partial_params,
            )
            .await?;
            vec![(
                Some(req_id),
                format!(
                    "partial preproc done, generated {} % (dummy preproc stored: {})",
                    partial_params.percentage_offline, partial_params.store_dummy_preprocessing
                ),
            )]
        }
        CCCommand::DoNothing(NoParameters {}) => {
            tracing::info!("Nothing to do.");
            vec![(None, String::new())]
        }
        CCCommand::Encrypt(cipher_parameters) => {
            tracing::info!("Fetching keys {key_types:?}. ({command:?})");
            let party_ids = fetch_public_elements(
                &cipher_parameters.key_id.as_str(),
                &key_types,
                &cc_conf,
                destination_prefix,
                false,
            )
            .await?;
            encrypt(
                destination_prefix,
                *party_ids.first().expect("no party IDs found"),
                cipher_parameters.clone(),
            )
            .await?;
            vec![(None, "Encryption generated".to_string())]
        }
        CCCommand::PreprocKeyGenResult(result_parameters) => {
            let req_id: RequestId = result_parameters.request_id;
            let _ = get_preproc_keygen_responses(&core_endpoints_req, req_id, max_iter).await?;
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
                &core_endpoints_req,
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
                cmd_config.download_all,
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
                &core_endpoints_req,
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
                cmd_config.download_all,
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
                &core_endpoints_req,
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
                &core_endpoints_req,
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
                cmd_config.download_all,
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
                &core_endpoints_req,
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
                cmd_config.download_all,
            )
            .await?;
            vec![(Some(req_id), "insecure crs gen result queried".to_string())]
        }
        CCCommand::NewCustodianContext(new_custodian_context_parameters) => {
            let mut setup_msgs = Vec::new();
            for cur_path in &new_custodian_context_parameters.setup_msg_paths {
                let cur_setup: InternalCustodianSetupMessage =
                    safe_read_element_versioned(cur_path).await?;
                setup_msgs.push(cur_setup);
            }
            let context_id = do_new_custodian_context(
                &core_endpoints_req,
                &mut rng,
                new_custodian_context_parameters.threshold,
                setup_msgs,
            )
            .await?;
            vec![(
                Some(context_id),
                "new custodian context created".to_string(),
            )]
        }
        CCCommand::GetOperatorPublicKey(NoParameters {}) => {
            let pks = do_get_operator_pub_keys(&core_endpoints_req).await?;
            pks.into_iter().map(|pk| (None, pk)).collect::<Vec<_>>()
        }
        CCCommand::CustodianRecoveryInit(RecoveryInitParameters {
            overwrite_ephemeral_key,
            operator_recovery_resp_paths,
        }) => {
            assert_eq!(
                operator_recovery_resp_paths.len(),
                num_parties,
                "Number of operator recovery response paths must match number of operators in the configuration files"
            );
            let res =
                do_custodian_recovery_init(&core_endpoints_req, *overwrite_ephemeral_key).await?;
            assert_eq!(res.len(), operator_recovery_resp_paths.len());

            let backup_id = res[0].backup_id();

            // no ordering of results and paths here
            for (cur_res, cur_path) in res.into_iter().zip(operator_recovery_resp_paths) {
                assert_eq!(
                    backup_id,
                    cur_res.backup_id(),
                    "All recovery responses must belong to the same backup ID"
                );
                safe_write_element_versioned(cur_path, &cur_res).await?;
            }

            vec![(
                Some(backup_id),
                "custodian recovery init queried and recovery request stored".to_string(),
            )]
        }
        CCCommand::CustodianBackupRecovery(RecoveryParameters {
            custodian_context_id,
            custodian_recovery_outputs,
        }) => {
            // We assume the output files are ordered the same way as the operators in the configuration file.
            let mut custodian_outputs = Vec::new();
            for recovery_path in custodian_recovery_outputs {
                let read_recovery: InternalCustodianRecoveryOutput =
                    safe_read_element_versioned(&recovery_path).await?;
                custodian_outputs.push(read_recovery);
            }
            do_custodian_backup_recovery(
                &core_endpoints_req,
                &cc_conf,
                *custodian_context_id,
                custodian_outputs,
            )
            .await?;
            vec![(
                Some(*custodian_context_id),
                "custodian backup restore complete".to_string(),
            )]
        }
        CCCommand::BackupRestore(NoParameters {}) => {
            do_restore_from_backup(&mut core_endpoints_req).await?;
            vec![(None, "backup restore complete".to_string())]
        }
        CCCommand::Reshare(ReshareParameters {
            key_id,
            preproc_id,
            from_context_id,
            from_epoch_id,
            server_key_digest,
            public_key_digest,
        }) => {
            let request_id = do_reshare(
                &mut internal_client.expect("Reshare requires a KMS client"),
                &core_endpoints_req,
                &mut rng,
                cmd_config,
                &cc_conf,
                destination_prefix,
                &kms_addrs,
                num_parties,
                fhe_params,
                *key_id,
                *preproc_id,
                from_context_id.as_ref(),
                from_epoch_id.as_ref(),
                server_key_digest.as_ref(),
                public_key_digest.as_ref(),
            )
            .await
            .unwrap();
            vec![
                (Some(request_id), "Reshare complete".to_string()),
                (Some(*key_id), "Key ready to be used".to_string()),
            ]
        }
        CCCommand::NewMpcContext(context_param) => match context_param {
            NewMpcContextParameters::SerializedContextPath(context_path) => {
                let ctx_id =
                    do_new_mpc_context(&core_endpoints_req, &context_path.input_path).await?;
                vec![(
                    Some(ctx_id.into()),
                    "new mpc context created from serialized context".to_string(),
                )]
            }
            NewMpcContextParameters::ContextToml(_context_path) => {
                unimplemented!("Creating new MPC context from TOML is not yet implemented");
            }
        },
        #[cfg(feature = "testing")]
        CCCommand::NewTestingMpcContextFile(NewTestingMpcContextFileParameters {
            context_id,
            context_path,
        }) => {
            // import stuff here because we're in the testing feature
            use kms_lib::consts::SAFE_SER_SIZE_LIMIT;
            use std::io::Write;

            let context = crate::mpc_context::create_test_context_info_from_core_config(
                *context_id,
                &cc_conf,
            )
            .await?;

            let mut buf = Vec::new();
            tfhe::safe_serialization::safe_serialize(&context, &mut buf, SAFE_SER_SIZE_LIMIT)
                .unwrap();

            let mut file = std::fs::File::create(context_path).unwrap();
            file.write_all(&buf).unwrap();

            vec![(
                Some((*context_id).into()),
                format!(
                    "new testing mpc context created and stored to file {:?}",
                    context_path
                ),
            )]
        }
        CCCommand::PrssInit(PrssInitParameters {
            context_id,
            epoch_id,
        }) => {
            do_prss_init(&core_endpoints_req, context_id, epoch_id).await?;
            vec![(Some((*epoch_id).into()), "prss init done".to_string())]
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
    // compute total time that is elapsed since we sent the first request
    let total_elapsed = start.elapsed();

    // compute latency values
    let avg = durations.iter().sum::<tokio::time::Duration>() / durations.len() as u32;
    durations.sort();
    let median = if durations.len().is_multiple_of(2) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

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
        assert!(parse_hex("Ox01").is_err()); // leading O (letter) instead of 0 (digit)
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
}
