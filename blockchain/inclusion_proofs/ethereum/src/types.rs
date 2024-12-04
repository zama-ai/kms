use hex::FromHexError;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

pub const ACL_REENCRYPT_MAPPING_SLOT: u8 = 0;
pub const ACL_DECRYPT_MAPPING_SLOT: u8 = 1;

pub const TRUE_SOLIDITY_STR: &str = "0x1";

type Hex = Vec<u8>;

pub struct EthereumConfig {
    pub json_rpc_url: String,
    pub acl_contract_address: String,
}

#[derive(Clone)]
pub enum EVMProofParams {
    Decrypt(DecryptProofParams),
    Reencrypt(ReencryptProofParams),
}

#[derive(Clone)]
pub struct DecryptProofParams {
    pub ciphertext_handles: Vec<Hex>,
}

#[derive(Clone)]
pub struct ReencryptProofParams {
    pub ciphertext_handles: Vec<Hex>,
    pub accounts: Vec<Hex>,
}

#[derive(Serialize)]
pub struct EthGetProofRequest<'a> {
    pub jsonrpc: &'static str,
    pub method: &'static str,
    pub params: [&'a serde_json::Value; 3],
    pub id: u32,
}

/// EVM specific proof of a perrmission granted for a list of cipher text handles
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvmPermissionProof {
    /// Ordered list of cipher text handles.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub ciphertext_handles: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Ordered list of cipher text handles.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub accounts: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(enumeration = "Permission", tag = "3")]
    pub permission: i32,
    /// Block height at which the proof was generated.
    #[prost(uint64, tag = "4")]
    pub block_height: u64,
    /// Root hash for merkle proofs.
    #[prost(bytes = "vec", tag = "5")]
    pub root_hash: ::prost::alloc::vec::Vec<u8>,
    /// Address on ACL contract on ethermint.
    #[prost(bytes = "vec", tag = "6")]
    pub contract_address: ::prost::alloc::vec::Vec<u8>,
    /// This is a set of encoded proofs for the list of cipher text handles.
    ///
    /// Should be decoded using the data formats for specific blockchain such as
    /// ethereum, ethermint.
    ///
    /// Note:
    /// 1. For ethermint, this is list of encoded proof ops. See
    ///    cometbft/proto/cometbft/crypto/v1/proof.proto.
    /// 2. For ethereum, this is serialized ethereum storag proof json.
    #[prost(bytes = "vec", repeated, tag = "7")]
    pub proof: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}

/// Represents the operations allowed for a cipher text handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Permission {
    Decrypt = 0,
    Reencrypt = 1,
}

impl Permission {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Permission::Decrypt => "Decrypt",
            Permission::Reencrypt => "Reencrypt",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "Decrypt" => Some(Self::Decrypt),
            "Reencrypt" => Some(Self::Reencrypt),
            _ => None,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EthGetProofResponse {
    pub result: EthGetProofResult,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(non_snake_case)]
pub struct EthGetProofResult {
    pub storageHash: String,
    pub storageProof: Vec<StorageProofJSON>,

    #[serde(default)]
    pub storageLocation: Vec<u8>, // This field is not from json and will be populated after parsing.
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StorageProofJSON {
    pub key: String,
    pub value: String,
    pub proof: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct EthErrorResponse {
    pub code: i32,
    pub message: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum EthResponse {
    Success(EthGetProofResponse),
    Error { error: EthErrorResponse },
}

/// Converts a 32-byte array to a big-endian integer.
pub fn bytes32_to_biguint(bytes: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Converts a big-endian integer to a 32-byte array.
pub fn biguint_to_bytes32(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();

    // Ensure we have exactly 32 bytes (padding with leading zeros if necessary)
    let mut result = [0u8; 32];
    let start_index = 32 - bytes.len().min(32);
    result[start_index..].copy_from_slice(&bytes);

    result
}

// calls hex::decode on the argument, stripping the 0x or 0X prefix if present
pub(crate) fn hex_decode_strip_0x_prefix(arg: &str) -> Result<Vec<u8>, FromHexError> {
    let arg = arg.strip_prefix("0x").unwrap_or(arg);
    let arg = arg.strip_prefix("0X").unwrap_or(arg);
    hex::decode(arg)
}
