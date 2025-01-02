use super::conversions::*;
use core::hash::{Hash, Hasher};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, Event};
use serde::de::Error;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ops::Deref;
use std::str::FromStr;
use strum::EnumProperty;
use strum_macros::{Display, EnumIs, EnumIter, EnumString};
use tfhe_versionable::{Versionize, VersionsDispatch};
use typed_builder::TypedBuilder;

#[cfg(feature = "non-wasm")]
use kms_grpc::kms::FheType as RPCFheType;

#[derive(VersionsDispatch)]
pub enum FheParameterVersioned {
    V0(FheParameter),
}

/// This type needs to match the protobuf type called [FheParameter].
#[cw_serde]
#[derive(Copy, Default, EnumString, Eq, Display, EnumIter, Versionize)]
#[versionize(FheParameterVersioned)]
pub enum FheParameter {
    #[default]
    #[strum(serialize = "default")]
    Default,
    #[strum(serialize = "test")]
    Test,
}

impl From<FheParameter> for i32 {
    fn from(value: FheParameter) -> Self {
        match value {
            FheParameter::Test => 0,
            FheParameter::Default => 1,
        }
    }
}

impl TryFrom<i32> for FheParameter {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<FheParameter, Self::Error> {
        match value {
            0 => Ok(FheParameter::Test),
            1 => Ok(FheParameter::Default),
            _ => Err(anyhow::anyhow!("Invalid FHE parameter")),
        }
    }
}

impl FheParameter {
    pub fn to_fhe_parameter_string(&self) -> String {
        // Our string representation is defined by the serialized json,
        // but the json encoding surrounds the string with double quotes,
        // so we need to extract the inner string so this result can be
        // processed by other functions, e.g., turned into a [FheParameter].
        serde_json::json!(self)
            .to_string()
            .trim_matches('\"')
            .to_string()
    }
}

pub trait Eip712Values {
    fn eip712_name(&self) -> &str;

    fn eip712_version(&self) -> &str;

    fn eip712_chain_id(&self) -> &HexVector;

    fn eip712_verifying_contract(&self) -> &str;

    fn eip712_salt(&self) -> Option<&HexVector>;
}

#[derive(VersionsDispatch)]
pub enum KmsCorePartyVersioned {
    V0(KmsCoreParty),
}

/// This struct contains all the metadata information needed about a KMS core party:
/// - public_storage_label: the label of the public storage to append to the base URL when fetching
///   public keys
#[cw_serde]
#[derive(Default, Versionize, TypedBuilder)]
#[versionize(KmsCorePartyVersioned)]
pub struct KmsCoreParty {
    pub public_storage_label: String,
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum OperationValueVersioned {
    V0(OperationValue),
}

#[cw_serde]
#[derive(Eq, EnumString, Display, EnumIter, strum_macros::EnumProperty, EnumIs, Versionize)]
#[versionize(OperationValueVersioned)]
pub enum OperationValue {
    #[serde(rename = "decrypt")]
    #[strum(serialize = "decrypt")]
    Decrypt(DecryptValues),
    #[strum(serialize = "decrypt_response")]
    #[serde(rename = "decrypt_response")]
    DecryptResponse(DecryptResponseValues),
    #[strum(serialize = "reencrypt")]
    #[serde(rename = "reencrypt")]
    Reencrypt(ReencryptValues),
    #[strum(serialize = "reencrypt_response")]
    #[serde(rename = "reencrypt_response")]
    ReencryptResponse(ReencryptResponseValues),
    #[strum(serialize = "verify_proven_ct")]
    #[serde(rename = "verify_proven_ct")]
    VerifyProvenCt(VerifyProvenCtValues),
    #[strum(serialize = "verify_proven_ct_response")]
    #[serde(rename = "verify_proven_ct_response")]
    VerifyProvenCtResponse(VerifyProvenCtResponseValues),
    #[strum(serialize = "keygen")]
    #[serde(rename = "keygen")]
    KeyGen(KeyGenValues),
    #[strum(serialize = "keygen_response")]
    #[serde(rename = "keygen_response")]
    KeyGenResponse(KeyGenResponseValues),
    #[strum(serialize = "insecure_key_gen")]
    #[serde(rename = "insecure_key_gen")]
    InsecureKeyGen(InsecureKeyGenValues),
    #[strum(serialize = "keygen_preproc")]
    #[serde(rename = "keygen_preproc")]
    // NOTE this is not supposed to have an inner value. If it ever gets one, correct method OperationValue::has_no_inner_value
    KeyGenPreproc(KeyGenPreprocValues),
    #[strum(serialize = "keygen_preproc_response")]
    #[serde(rename = "keygen_preproc_response")]
    // NOTE this is not supposed to have an inner value. If it ever gets one, correct method OperationValue::has_no_inner_value
    KeyGenPreprocResponse(KeyGenPreprocResponseValues),
    #[strum(serialize = "crs_gen")]
    #[serde(rename = "crs_gen")]
    CrsGen(CrsGenValues),
    #[strum(serialize = "insecure_crs_gen")]
    #[serde(rename = "insecure_crs_gen")]
    InsecureCrsGen(InsecureCrsGenValues),
    #[strum(serialize = "crs_gen_response")]
    #[serde(rename = "crs_gen_response")]
    CrsGenResponse(CrsGenResponseValues),
}

impl OperationValue {
    fn has_no_inner_value(&self) -> bool {
        matches!(
            self,
            Self::KeyGenPreproc(_) | Self::KeyGenPreprocResponse(_)
        )
    }

    /// Returns true if this operation is a key or crs generation operation
    pub fn is_gen(&self) -> bool {
        matches!(
            self,
            Self::CrsGen(_)
                | Self::InsecureCrsGen(_)
                | Self::KeyGenPreproc(_)
                | Self::KeyGen(_)
                | Self::InsecureKeyGen(_)
        )
    }

    /// Returns the values' name as a string
    pub fn values_name(&self) -> &'static str {
        match self {
            Self::Decrypt(_) => "DecryptValues",
            Self::DecryptResponse(_) => "DecryptResponseValues",
            Self::Reencrypt(_) => "ReencryptValues",
            Self::ReencryptResponse(_) => "ReencryptResponseValues",
            Self::VerifyProvenCt(_) => "VerifyProvenCtValues",
            Self::VerifyProvenCtResponse(_) => "VerifyProvenCtResponseValues",
            Self::KeyGen(_) => "KeyGenValues",
            Self::KeyGenResponse(_) => "KeyGenResponseValues",
            Self::InsecureKeyGen(_) => "InsecureKeyGenValues",
            Self::KeyGenPreproc(_) => "KeyGenPreprocValues",
            Self::KeyGenPreprocResponse(_) => "KeyGenPreprocResponseValues",
            Self::CrsGen(_) => "CrsGenValues",
            Self::InsecureCrsGen(_) => "InsecureCrsGenValues",
            Self::CrsGenResponse(_) => "CrsGenResponseValues",
        }
    }
}

impl From<OperationValue> for KmsOperation {
    fn from(value: OperationValue) -> Self {
        match value {
            OperationValue::Decrypt(_) => KmsOperation::Decrypt,
            OperationValue::DecryptResponse(_) => KmsOperation::DecryptResponse,
            OperationValue::Reencrypt(_) => KmsOperation::Reencrypt,
            OperationValue::ReencryptResponse(_) => KmsOperation::ReencryptResponse,
            OperationValue::VerifyProvenCt(_) => KmsOperation::VerifyProvenCt,
            OperationValue::VerifyProvenCtResponse(_) => KmsOperation::VerifyProvenCtResponse,
            OperationValue::KeyGen(_) => KmsOperation::KeyGen,
            OperationValue::KeyGenResponse(_) => KmsOperation::KeyGenResponse,
            OperationValue::InsecureKeyGen(_) => KmsOperation::InsecureKeyGen,
            OperationValue::KeyGenPreproc(_) => KmsOperation::KeyGenPreproc,
            OperationValue::KeyGenPreprocResponse(_) => KmsOperation::KeyGenPreprocResponse,
            OperationValue::CrsGen(_) => KmsOperation::CrsGen,
            OperationValue::InsecureCrsGen(_) => KmsOperation::InsecureCrsGen,
            OperationValue::CrsGenResponse(_) => KmsOperation::CrsGenResponse,
        }
    }
}

impl OperationValue {
    pub fn into_kms_operation(&self) -> KmsOperation {
        self.clone().into()
    }

    pub fn is_request(&self) -> bool {
        self.into_kms_operation().is_request()
    }

    pub fn is_response(&self) -> bool {
        self.into_kms_operation().is_response()
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum TransactionVersioned {
    V0(Transaction),
}

#[cw_serde]
#[derive(Eq, Default, Versionize)]
#[versionize(TransactionVersioned)]
pub struct Transaction {
    block_height: u64,
    transaction_index: u32,
    operations: Vec<OperationValue>,
}

impl Transaction {
    pub fn new(block_height: u64, transaction_index: u32, operations: Vec<OperationValue>) -> Self {
        Self {
            block_height,
            transaction_index,
            operations,
        }
    }
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    pub fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    pub fn operations(&self) -> &Vec<OperationValue> {
        &self.operations
    }

    pub fn add_operation(&mut self, operation: OperationValue) {
        self.operations.push(operation);
    }

    pub fn add_operations(&mut self, operations: Vec<OperationValue>) {
        self.operations.extend(operations);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, VersionsDispatch)]
pub enum FheTypeVersioned {
    V0(FheType),
}

#[cw_serde]
#[derive(Copy, Default, EnumString, Eq, Display, Versionize)]
#[versionize(FheTypeVersioned)]
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
    fn as_str_name(&self) -> &'static str {
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

#[cfg(feature = "non-wasm")]
impl From<RPCFheType> for FheType {
    fn from(value: RPCFheType) -> Self {
        match value {
            RPCFheType::Ebool => FheType::Ebool,
            RPCFheType::Euint4 => FheType::Euint4,
            RPCFheType::Euint8 => FheType::Euint8,
            RPCFheType::Euint16 => FheType::Euint16,
            RPCFheType::Euint32 => FheType::Euint32,
            RPCFheType::Euint64 => FheType::Euint64,
            RPCFheType::Euint128 => FheType::Euint128,
            RPCFheType::Euint160 => FheType::Euint160,
            RPCFheType::Euint256 => FheType::Euint256,
            RPCFheType::Euint512 => FheType::Euint512,
            RPCFheType::Euint1024 => FheType::Euint1024,
            RPCFheType::Euint2048 => FheType::Euint2048,
        }
    }
}

#[cfg(feature = "non-wasm")]
impl TryInto<RPCFheType> for FheType {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<RPCFheType, Self::Error> {
        match self {
            FheType::Ebool => Ok(RPCFheType::Ebool),
            FheType::Euint4 => Ok(RPCFheType::Euint4),
            FheType::Euint8 => Ok(RPCFheType::Euint8),
            FheType::Euint16 => Ok(RPCFheType::Euint16),
            FheType::Euint32 => Ok(RPCFheType::Euint32),
            FheType::Euint64 => Ok(RPCFheType::Euint64),
            FheType::Euint128 => Ok(RPCFheType::Euint128),
            FheType::Euint160 => Ok(RPCFheType::Euint160),
            FheType::Euint256 => Ok(RPCFheType::Euint256),
            FheType::Euint512 => Ok(RPCFheType::Euint512),
            FheType::Euint1024 => Ok(RPCFheType::Euint1024),
            FheType::Euint2048 => Ok(RPCFheType::Euint2048),
            _ => Err(anyhow::anyhow!("Not supported")),
        }
    }
}

#[cw_serde]
#[derive(Copy, Eq, EnumString, Display)]
pub enum KmsEventAttributeKey {
    #[strum(serialize = "kmsoperation")]
    OperationType,
    #[strum(serialize = "txn_id")]
    TransactionId,
}

#[derive(Serialize, Deserialize, Debug, Clone, VersionsDispatch)]
pub enum DecryptValuesVersioned {
    V0(DecryptValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(DecryptValuesVersioned)]
pub struct DecryptValues {
    /// The ID of the FHE public key used
    key_id: HexVector,
    /// The list of KV store ciphertext handles to be decrypted
    ciphertext_handles: RedactedHexVectorList,
    /// The list of FHE types of the above ciphertexts
    fhe_types: Vec<FheType>,
    /// The list of external handles of the above ciphertexts (e.g. from fheVM)
    external_handles: Option<HexVectorList>,
    /// The version number
    version: u32,
    /// The address of the ACL contract
    acl_address: String,
    /// Proof of permission to decrypt included in ACL contract
    proof: String,

    // EIP-712
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl DecryptValues {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key_id: impl Into<HexVector>,
        ciphertext_handles: impl Into<RedactedHexVectorList>,
        fhe_types: Vec<FheType>,
        external_handles: Option<impl Into<HexVectorList>>,
        version: u32,
        acl_address: String,
        proof: String,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            key_id: key_id.into(),
            ciphertext_handles: ciphertext_handles.into(),
            fhe_types,
            external_handles: external_handles.map(Into::into),
            version,
            acl_address,
            proof,
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn fhe_types(&self) -> &Vec<FheType> {
        &self.fhe_types
    }

    pub fn ciphertext_handles(&self) -> &RedactedHexVectorList {
        &self.ciphertext_handles
    }

    pub fn external_handles(&self) -> &Option<HexVectorList> {
        &self.external_handles
    }

    pub fn proof(&self) -> &str {
        &self.proof
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }

    pub fn acl_address(&self) -> &str {
        &self.acl_address
    }
}

impl From<DecryptValues> for OperationValue {
    fn from(value: DecryptValues) -> Self {
        OperationValue::Decrypt(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum ReencryptValuesVersioned {
    V0(ReencryptValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(ReencryptValuesVersioned)]
pub struct ReencryptValues {
    signature: HexVector,

    // Payload
    /// The version number
    version: u32,
    /// The address of the client receiving the reencryption output
    client_address: String,
    /// The encyption key of the client
    enc_key: RedactedHexVector,
    /// The FHE type of the value to be reencrypted
    fhe_type: FheType,
    /// The ID of the FHE public key used
    key_id: HexVector,
    /// The host blockchain handle for ciphertext to be reencrypted
    external_ciphertext_handle: RedactedHexVector,
    /// The KV-store handle of the ciphertext to be reencrypted
    ciphertext_handle: RedactedHexVector,
    /// The SHA3 digest of the ciphertext to be reencrypted
    ciphertext_digest: RedactedHexVector,
    /// The address of the ACL contract
    acl_address: String,
    /// Proof of permission to decrypt included in ACL contract
    proof: String,

    // EIP-712:
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes if present
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl ReencryptValues {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signature: impl Into<HexVector>,
        version: u32,
        client_address: String,
        enc_key: impl Into<RedactedHexVector>,
        fhe_type: FheType,
        key_id: impl Into<HexVector>,
        external_ciphertext_handle: impl Into<RedactedHexVector>,
        ciphertext_handle: impl Into<RedactedHexVector>,
        ciphertext_digest: impl Into<RedactedHexVector>,
        acl_address: String,
        proof: String,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            signature: signature.into(),
            version,
            client_address,
            enc_key: enc_key.into(),
            fhe_type,
            key_id: key_id.into(),
            external_ciphertext_handle: external_ciphertext_handle.into(),
            ciphertext_handle: ciphertext_handle.into(),
            ciphertext_digest: ciphertext_digest.into(),
            acl_address,
            proof,
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn client_address(&self) -> &str {
        &self.client_address
    }

    pub fn enc_key(&self) -> &RedactedHexVector {
        &self.enc_key
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn external_ciphertext_handle(&self) -> &RedactedHexVector {
        &self.external_ciphertext_handle
    }
    pub fn ciphertext_handle(&self) -> &RedactedHexVector {
        &self.ciphertext_handle
    }

    pub fn ciphertext_digest(&self) -> &RedactedHexVector {
        &self.ciphertext_digest
    }

    pub fn acl_address(&self) -> &str {
        &self.acl_address
    }

    pub fn proof(&self) -> &str {
        &self.proof
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl From<ReencryptValues> for OperationValue {
    fn from(value: ReencryptValues) -> Self {
        OperationValue::Reencrypt(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum VerifyProvenCtValuesVersioned {
    V0(VerifyProvenCtValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(VerifyProvenCtValuesVersioned)]
pub struct VerifyProvenCtValues {
    /// The ID of the CRS used
    crs_id: HexVector,
    /// The ID of the FHE public key used
    key_id: HexVector,
    /// The address of the dapp the input is used for
    contract_address: String,
    /// The address of the client providing the input
    client_address: String,
    /// The KV-store handle of the ciphertext and proof to be verified
    ct_proof_handle: RedactedHexVector,
    /// The address of the ACL contract
    acl_address: String,

    // EIP-712:
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl VerifyProvenCtValues {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crs_id: impl Into<HexVector>,
        key_id: impl Into<HexVector>,
        contract_address: String,
        client_address: String,
        ct_proof_handle: impl Into<RedactedHexVector>,
        acl_address: String,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            crs_id: crs_id.into(),
            key_id: key_id.into(),
            contract_address,
            client_address,
            ct_proof_handle: ct_proof_handle.into(),
            acl_address,
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn crs_id(&self) -> &HexVector {
        &self.crs_id
    }

    pub fn contract_address(&self) -> &str {
        &self.contract_address
    }

    pub fn acl_address(&self) -> &str {
        &self.acl_address
    }

    pub fn client_address(&self) -> &str {
        &self.client_address
    }

    pub fn ct_proof_handle(&self) -> &RedactedHexVector {
        &self.ct_proof_handle
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl From<VerifyProvenCtValues> for OperationValue {
    fn from(value: VerifyProvenCtValues) -> Self {
        OperationValue::VerifyProvenCt(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum DecryptResponseValuesVersioned {
    V0(DecryptResponseValues),
}

#[cw_serde]
#[derive(Default, Eq, Versionize, TypedBuilder)]
#[versionize(DecryptResponseValuesVersioned)]
pub struct DecryptResponseValues {
    signature: HexVector,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    payload: HexVector,
}

impl DecryptResponseValues {
    pub fn new(signature: impl Into<HexVector>, payload: impl Into<HexVector>) -> Self {
        Self {
            signature: signature.into(),
            payload: payload.into(),
        }
    }

    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn payload(&self) -> &HexVector {
        &self.payload
    }
}

impl From<DecryptResponseValues> for OperationValue {
    fn from(value: DecryptResponseValues) -> Self {
        OperationValue::DecryptResponse(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenPreprocResponseValuesVersioned {
    V0(KeyGenPreprocResponseValues),
}

#[cw_serde]
#[derive(Default, Eq, Versionize, TypedBuilder)]
#[versionize(KeyGenPreprocResponseValuesVersioned)]
pub struct KeyGenPreprocResponseValues {
    // NOTE: there's no actual response except an "ok"
}

impl KeyGenPreprocResponseValues {
    pub fn new() -> Self {
        Self {}
    }
}

impl From<KeyGenPreprocResponseValues> for OperationValue {
    fn from(value: KeyGenPreprocResponseValues) -> Self {
        OperationValue::KeyGenPreprocResponse(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenResponseValuesVersioned {
    V0(KeyGenResponseValues),
}

#[cw_serde]
#[derive(Default, Eq, Versionize, TypedBuilder)]
#[versionize(KeyGenResponseValuesVersioned)]
pub struct KeyGenResponseValues {
    request_id: HexVector,
    public_key_digest: String,
    public_key_signature: HexVector,
    public_key_external_signature: HexVector,
    // server key is bootstrap key
    server_key_digest: String,
    server_key_signature: HexVector,
    server_key_external_signature: HexVector,
    // we do not need SnS key
    // The parameter used to generate the public keys
    // Note that it is fetched from the ASC
    param: FheParameter,
}

impl KeyGenResponseValues {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: impl Into<HexVector>,
        public_key_digest: String,
        public_key_signature: impl Into<HexVector>,
        public_key_external_signature: impl Into<HexVector>,
        server_key_digest: String,
        server_key_signature: impl Into<HexVector>,
        server_key_external_signature: impl Into<HexVector>,
        param: impl Into<FheParameter>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            public_key_digest,
            public_key_signature: public_key_signature.into(),
            public_key_external_signature: public_key_external_signature.into(),
            server_key_digest,
            server_key_signature: server_key_signature.into(),
            server_key_external_signature: server_key_external_signature.into(),
            param: param.into(),
        }
    }

    pub fn request_id(&self) -> &HexVector {
        &self.request_id
    }

    pub fn public_key_digest(&self) -> &str {
        &self.public_key_digest
    }

    pub fn public_key_signature(&self) -> &HexVector {
        &self.public_key_signature
    }

    pub fn public_key_external_signature(&self) -> &HexVector {
        &self.public_key_external_signature
    }

    pub fn server_key_digest(&self) -> &str {
        &self.server_key_digest
    }

    pub fn server_key_signature(&self) -> &HexVector {
        &self.server_key_signature
    }

    pub fn server_key_external_signature(&self) -> &HexVector {
        &self.server_key_external_signature
    }

    pub fn param(&self) -> &FheParameter {
        &self.param
    }
}

impl From<KeyGenResponseValues> for OperationValue {
    fn from(value: KeyGenResponseValues) -> Self {
        OperationValue::KeyGenResponse(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum ReencryptResponseValuesVersioned {
    V0(ReencryptResponseValues),
}

#[cw_serde]
#[derive(Default, Eq, Versionize, TypedBuilder)]
#[versionize(ReencryptResponseValuesVersioned)]
pub struct ReencryptResponseValues {
    signature: HexVector,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    payload: HexVector,

    /// Digest of ciphertext.
    /// In the payload from KMS, cipher text digest is used as reference, since
    /// the KMS is now aware of external handle values. However, client does not
    /// have this value as uses external handle as reference. Hence include this
    /// value in the response, so that client can verify the integrity of the
    /// payload.
    /// This will be set by the gateway, when it finally returns the value.
    ciphertext_digest: Option<HexVector>,
}

impl ReencryptResponseValues {
    pub fn new(signature: impl Into<HexVector>, payload: impl Into<HexVector>) -> Self {
        Self {
            signature: signature.into(),
            payload: payload.into(),
            ciphertext_digest: None,
        }
    }

    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn payload(&self) -> &HexVector {
        &self.payload
    }

    pub fn set_ciphertext_digest(&mut self, ciphertext_digest: impl Into<HexVector>) {
        self.ciphertext_digest = Some(ciphertext_digest.into());
    }
}

impl From<ReencryptResponseValues> for OperationValue {
    fn from(value: ReencryptResponseValues) -> Self {
        OperationValue::ReencryptResponse(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum VerifyProvenCtResponseValuesVersioned {
    V0(VerifyProvenCtResponseValues),
}

#[cw_serde]
#[derive(Default, Eq, Versionize, TypedBuilder)]
#[versionize(VerifyProvenCtResponseValuesVersioned)]
pub struct VerifyProvenCtResponseValues {
    signature: HexVector,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    payload: HexVector,
}

impl VerifyProvenCtResponseValues {
    pub fn new(signature: impl Into<HexVector>, payload: impl Into<HexVector>) -> Self {
        Self {
            signature: signature.into(),
            payload: payload.into(),
        }
    }

    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn payload(&self) -> &HexVector {
        &self.payload
    }
}

impl From<VerifyProvenCtResponseValues> for OperationValue {
    fn from(value: VerifyProvenCtResponseValues) -> Self {
        OperationValue::VerifyProvenCtResponse(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum CrsGenResponseValuesVersioned {
    V0(CrsGenResponseValues),
}

#[cw_serde]
#[derive(Default, Eq, Versionize, TypedBuilder)]
#[versionize(CrsGenResponseValuesVersioned)]
pub struct CrsGenResponseValues {
    /// The request ID of the CRS generation.
    request_id: String,
    /// The CRS digest, which can be used to derive the storage URL for the CRS.
    digest: String,
    /// The signature on the digest.
    signature: HexVector,
    /// The external signature on the digest (e.g. EIP-712).
    external_signature: HexVector,
    max_num_bits: u32,
    // The parameter for which the CRS was generated
    // Note that parameter is fetched from the ASC
    param: FheParameter,
}

impl CrsGenResponseValues {
    pub fn new(
        request_id: String,
        digest: String,
        signature: impl Into<HexVector>,
        external_signature: impl Into<HexVector>,
        max_num_bits: u32,
        param: impl Into<FheParameter>,
    ) -> Self {
        Self {
            request_id,
            digest,
            signature: signature.into(),
            external_signature: external_signature.into(),
            max_num_bits,
            param: param.into(),
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn external_signature(&self) -> &HexVector {
        &self.external_signature
    }

    pub fn max_num_bits(&self) -> u32 {
        self.max_num_bits
    }

    pub fn param(&self) -> &FheParameter {
        &self.param
    }
}

impl From<CrsGenResponseValues> for OperationValue {
    fn from(value: CrsGenResponseValues) -> Self {
        OperationValue::CrsGenResponse(value)
    }
}

#[derive(Debug)]
pub struct GenResponseValuesSavedEvent {
    operation_value: OperationValue,
}

impl GenResponseValuesSavedEvent {
    pub fn new(operation_value: OperationValue) -> Self {
        Self { operation_value }
    }
}

impl From<GenResponseValuesSavedEvent> for Event {
    fn from(event: GenResponseValuesSavedEvent) -> Self {
        Event::new("gen_response_values_saved").add_attributes([(
            event.operation_value.values_name(),
            event.operation_value.to_string(),
        )])
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenPreprocValuesVersioned {
    V0(KeyGenPreprocValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(KeyGenPreprocValuesVersioned)]
pub struct KeyGenPreprocValues {}

impl KeyGenPreprocValues {
    pub fn new() -> Self {
        Self {}
    }
}

impl From<KeyGenPreprocValues> for OperationValue {
    fn from(value: KeyGenPreprocValues) -> Self {
        OperationValue::KeyGenPreproc(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenValuesVersioned {
    V0(KeyGenValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(KeyGenValuesVersioned)]
pub struct KeyGenValues {
    /// Hex-encoded preprocessing ID.
    /// This ID refers to the request ID of a preprocessing request.
    preproc_id: HexVector,

    // EIP-712:
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl KeyGenValues {
    pub fn new(
        preproc_id: impl Into<HexVector>,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            preproc_id: preproc_id.into(),
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn preproc_id(&self) -> &HexVector {
        &self.preproc_id
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl Eip712Values for KeyGenValues {
    fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl From<KeyGenValues> for OperationValue {
    fn from(value: KeyGenValues) -> Self {
        OperationValue::KeyGen(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum InsecureKeyGenValuesVersioned {
    V0(InsecureKeyGenValues),
}
// There is no preprocessing id when using insecure key generation.
#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(InsecureKeyGenValuesVersioned)]
pub struct InsecureKeyGenValues {
    // EIP-712:
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl InsecureKeyGenValues {
    pub fn new(
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl Eip712Values for InsecureKeyGenValues {
    fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl From<InsecureKeyGenValues> for OperationValue {
    fn from(value: InsecureKeyGenValues) -> Self {
        OperationValue::InsecureKeyGen(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum CrsGenValuesVersioned {
    V0(CrsGenValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(CrsGenValuesVersioned)]
pub struct CrsGenValues {
    max_num_bits: u32,

    // EIP-712:
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl CrsGenValues {
    pub fn new(
        max_num_bits: u32,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            max_num_bits,
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn max_num_bits(&self) -> u32 {
        self.max_num_bits
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl Eip712Values for CrsGenValues {
    fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl From<CrsGenValues> for OperationValue {
    fn from(value: CrsGenValues) -> Self {
        OperationValue::CrsGen(value)
    }
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum InsecureCrsGenValuesVersioned {
    V0(InsecureCrsGenValues),
}

#[cw_serde]
#[derive(Eq, Default, Versionize, TypedBuilder)]
#[versionize(InsecureCrsGenValuesVersioned)]
pub struct InsecureCrsGenValues {
    max_num_bits: u32,

    // EIP-712:
    /// The name of the EIP-712 domain
    eip712_name: String,
    /// The version of the EIP-712 domain
    eip712_version: String,
    /// The chain-id used for EIP-712
    /// This MUST be 32 bytes
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    /// This MUST be 32 bytes if present
    eip712_salt: Option<HexVector>,
}

impl InsecureCrsGenValues {
    pub fn new(
        max_num_bits: u32,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: impl Into<HexVector>,
        eip712_verifying_contract: String,
        eip712_salt: Option<impl Into<HexVector>>,
    ) -> anyhow::Result<Self> {
        let (chain_id, salt) = validate_eip712(eip712_chain_id, eip712_salt)?;
        Ok(Self {
            max_num_bits,
            eip712_name,
            eip712_version,
            eip712_chain_id: chain_id,
            eip712_verifying_contract,
            eip712_salt: salt,
        })
    }

    pub fn max_num_bits(&self) -> u32 {
        self.max_num_bits
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    pub fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl Eip712Values for InsecureCrsGenValues {
    fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    fn eip712_chain_id(&self) -> &HexVector {
        &self.eip712_chain_id
    }

    fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    #[allow(clippy::needless_borrow)]
    fn eip712_salt(&self) -> Option<&HexVector> {
        (&self.eip712_salt).as_ref()
    }
}

impl From<InsecureCrsGenValues> for OperationValue {
    fn from(value: InsecureCrsGenValues) -> Self {
        OperationValue::InsecureCrsGen(value)
    }
}

/// Validate that the chain ID and salt are conforment to the eip712 standard.
/// That is, wether they are 32 bytes if present.
/// and return the chain ID and salt as a tuple of [HexVectors].
fn validate_eip712(
    chain_id: impl Into<HexVector>,
    salt: Option<impl Into<HexVector>>,
) -> anyhow::Result<(HexVector, Option<HexVector>)> {
    let chain_id = chain_id.into();
    if chain_id.len() != 32 {
        return Err(anyhow::anyhow!(
            "eip712_chain_id must be 32 bytes long but is {} bytes long",
            chain_id.len()
        ));
    }
    let updated_salt = match salt {
        Some(salt) => {
            let inner_salt = salt.into();
            if inner_salt.len() != 32 {
                return Err(anyhow::anyhow!(
                    "eip712_salt must be 32 bytes long but is {} bytes long",
                    inner_salt.len()
                ));
            }
            Some(inner_salt)
        }
        None => None,
    };
    Ok((chain_id, updated_salt))
}

#[cw_serde]
#[derive(Eq, EnumString, Display, EnumIter, strum_macros::EnumProperty, EnumIs, Default, Hash)]
pub enum KmsOperation {
    #[default]
    #[strum(serialize = "decrypt", props(request = "true"))]
    Decrypt,
    #[strum(serialize = "decrypt_response", props(response = "true"))]
    DecryptResponse,
    #[strum(serialize = "reencrypt", props(request = "true"))]
    Reencrypt,
    #[strum(serialize = "reencrypt_response", props(response = "true"))]
    ReencryptResponse,
    #[strum(serialize = "verify_proven_ct", props(request = "true"))]
    VerifyProvenCt,
    #[strum(serialize = "verify_proven_ct_response", props(response = "true"))]
    VerifyProvenCtResponse,
    #[strum(serialize = "keyurl", props(request = "true"))]
    KeyUrl,
    #[strum(serialize = "keyurl_response", props(response = "true"))]
    KeyUrlResponse,
    #[strum(serialize = "keygen_preproc", props(request = "true"))]
    #[serde(rename = "keygen_preproc")]
    KeyGenPreproc,
    #[strum(serialize = "keygen_preproc_response", props(response = "true"))]
    #[serde(rename = "keygen_preproc_response")]
    KeyGenPreprocResponse,
    #[strum(serialize = "keygen", props(request = "true"))]
    #[serde(rename = "keygen")]
    KeyGen,
    #[strum(serialize = "keygen_response", props(response = "true"))]
    #[serde(rename = "keygen_response")]
    KeyGenResponse,
    #[strum(serialize = "insecure_key_gen", props(request = "true"))]
    #[serde(rename = "insecure_key_gen")]
    InsecureKeyGen,
    #[strum(serialize = "crs_gen", props(request = "true"))]
    #[serde(rename = "crs_gen")]
    CrsGen,
    #[strum(serialize = "insecure_crs_gen", props(request = "true"))]
    #[serde(rename = "insecure_crs_gen")]
    InsecureCrsGen,
    #[strum(serialize = "crs_gen_response", props(response = "true"))]
    CrsGenResponse,
}

impl KmsOperation {
    pub fn is_request(&self) -> bool {
        self.get_str("request").unwrap_or("false") == "true"
    }

    pub fn is_response(&self) -> bool {
        self.get_str("response").unwrap_or("false") == "true"
    }

    pub fn to_response(&self) -> Result<KmsOperation, anyhow::Error> {
        match *self {
            KmsOperation::Decrypt => Ok(KmsOperation::DecryptResponse),
            KmsOperation::Reencrypt => Ok(KmsOperation::ReencryptResponse),
            KmsOperation::KeyGenPreproc => Ok(KmsOperation::KeyGenPreprocResponse),
            KmsOperation::KeyGen => Ok(KmsOperation::KeyGenResponse),
            KmsOperation::InsecureKeyGen => Ok(KmsOperation::KeyGenResponse),
            KmsOperation::CrsGen => Ok(KmsOperation::CrsGenResponse),
            KmsOperation::InsecureCrsGen => Ok(KmsOperation::CrsGenResponse),
            KmsOperation::VerifyProvenCt => Ok(KmsOperation::VerifyProvenCtResponse),
            _ => Err(anyhow::anyhow!(
                "To response is not supported for self: {:?}",
                self
            )),
        }
    }

    /// Return the list of request operations associated to the response operation
    ///
    /// This returns a list because in case of generation (key or CRS) responses, there are two
    /// possible request operations associated: the normal one and the insecure one.
    pub fn to_requests(&self) -> Result<Vec<KmsOperation>, anyhow::Error> {
        match *self {
            KmsOperation::DecryptResponse => Ok(vec![KmsOperation::Decrypt]),
            KmsOperation::ReencryptResponse => Ok(vec![KmsOperation::Reencrypt]),
            KmsOperation::KeyGenPreprocResponse => Ok(vec![KmsOperation::KeyGenPreproc]),
            KmsOperation::KeyGenResponse => {
                Ok(vec![KmsOperation::KeyGen, KmsOperation::InsecureKeyGen])
            }
            KmsOperation::CrsGenResponse => {
                Ok(vec![KmsOperation::CrsGen, KmsOperation::InsecureCrsGen])
            }
            KmsOperation::VerifyProvenCtResponse => Ok(vec![KmsOperation::VerifyProvenCt]),
            _ => Err(anyhow::anyhow!(
                "To requests is not supported for self: {:?}",
                self
            )),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, TypedBuilder, Deserialize)]
pub struct KmsMessage {
    #[builder(setter(into), default = None)]
    #[serde(skip_serializing_if = "Option::is_none")]
    txn_id: Option<TransactionId>,
    #[builder(setter(into))]
    #[serde(flatten, skip_serializing_if = "OperationValue::has_no_inner_value")]
    pub value: OperationValue,
}

pub type KmsMessageWithoutProof = KmsMessage;

#[derive(Serialize)]
struct InnerKmsMessage<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    txn_id: Option<&'a TransactionId>,
    #[serde(flatten, skip_serializing_if = "OperationValue::has_no_inner_value")]
    value: &'a OperationValue,
}

impl Serialize for KmsMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = InnerKmsMessage {
            txn_id: self.txn_id.as_ref(),
            value: &self.value,
        };
        let operation = Box::leak(self.value.to_string().into_boxed_str());
        let mut ser = serializer.serialize_map(None)?;
        ser.serialize_entry(operation, &data)?;
        ser.end()
    }
}

impl KmsMessage {
    pub fn txn_id(&self) -> Option<&TransactionId> {
        self.txn_id.as_ref()
    }

    pub fn value(&self) -> &OperationValue {
        &self.value
    }

    pub fn to_json(&self) -> Result<Value, serde_json::error::Error> {
        serde_json::to_value(self)
    }

    // NOTE: This logic is most likely already somewhere deep in the macros
    // as the ASC needs to do this too...
    pub fn from_json(value: &str) -> Result<Self, serde_json::error::Error> {
        let value: Value = serde_json::from_str(value)?;
        match value {
            serde_json::Value::Object(mut map) => {
                if map.keys().len() == 1 {
                    //Can unwrap safely here as we just checked the length
                    let op = map.keys().next().unwrap().clone();
                    serde_json::from_value(map.remove(&op).unwrap())
                } else {
                    Err(serde_json::error::Error::custom(
                        "Unexpected value when parsing json",
                    ))
                }
            }
            _ => Err(serde_json::error::Error::custom(
                "Unexpected value when parsing json",
            )),
        }
    }
}

#[cw_serde]
#[derive(Eq, Default)]
pub struct TransactionId(pub(crate) HexVector);

impl Deref for TransactionId {
    type Target = HexVector;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TransactionId {
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(TransactionId(HexVector::from_hex(hex)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.deref().deref().clone()
    }

    /// converts the transaction id to a little endian u64 value.
    /// value is padded with zeros if smaller than 8 bytes.
    /// values in bytes 9 and onward are discarded
    pub fn to_u64(&self) -> u64 {
        let mut padded_vec = self.to_vec();
        padded_vec.resize(8, 0); // Pad with zeros if less than 8 bytes, or truncate to 8 bytes
        let mut out = 0u64;
        for (i, v) in padded_vec.into_iter().enumerate().take(8) {
            out |= (v as u64) << (8 * i);
        }
        out
    }
}

impl From<&HexVector> for TransactionId {
    fn from(value: &HexVector) -> Self {
        TransactionId(value.clone())
    }
}

impl From<HexVector> for TransactionId {
    fn from(value: HexVector) -> Self {
        TransactionId(value)
    }
}

impl From<Vec<u8>> for TransactionId {
    fn from(value: Vec<u8>) -> Self {
        TransactionId(HexVector(value))
    }
}

impl From<TransactionId> for Attribute {
    fn from(value: TransactionId) -> Self {
        Attribute::new(
            KmsEventAttributeKey::TransactionId.to_string(),
            value.0.to_hex(),
        )
    }
}

impl Hash for TransactionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_hex().hash(state);
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default, Hash)]
pub struct KmsEvent {
    #[builder(setter(into))]
    pub operation: KmsOperation,
    #[builder(setter(into))]
    pub txn_id: TransactionId,
}

impl std::fmt::Display for KmsEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} with txn_id: {}",
            self.operation,
            self.txn_id.to_hex(),
        )
    }
}

impl KmsEvent {
    pub fn operation(&self) -> &KmsOperation {
        &self.operation
    }

    pub fn txn_id(&self) -> &TransactionId {
        &self.txn_id
    }
}

impl From<KmsEvent> for Event {
    fn from(value: KmsEvent) -> Self {
        let event_type = value.operation().to_string();
        let attributes = vec![<TransactionId as Into<Attribute>>::into(value.txn_id)];
        Event::new(event_type).add_attributes(attributes)
    }
}

impl TryFrom<Event> for KmsEvent {
    type Error = anyhow::Error;
    fn try_from(event: Event) -> Result<Self, Self::Error> {
        let mut attributes = event.attributes;
        let pos_tx_id = attributes
            .iter()
            .position(|a| a.key == "txn_id")
            .ok_or_else(|| anyhow::anyhow!("Missing txn_id attribute"))?;
        let txn_id: TransactionId = attributes
            .get(pos_tx_id)
            .map(|a| hex::decode(a.value.as_str()))
            .transpose()?
            .map(Into::into)
            .ok_or_else(|| anyhow::anyhow!("Missing txn_id attribute"))?;
        attributes.remove(pos_tx_id);
        let operation = event
            .ty
            .as_str()
            .strip_prefix("wasm-")
            .ok_or_else(|| anyhow::anyhow!("Invalid event type"))?;
        let operation = KmsOperation::from_str(operation)?;
        Ok(KmsEvent { operation, txn_id })
    }
}

#[cw_serde]
#[derive(Eq)]
pub struct TransactionEvent {
    pub tx_hash: String,
    pub event: KmsEvent,
}

#[derive(Debug, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum MigrationStatus {
    Success,
    #[strum(serialize = "in progress")]
    InProgress,
    Failed,
}

#[derive(Debug)]
pub struct MigrationEvent {
    from_version: String,
    to_version: String,
    status: MigrationStatus,
}

impl MigrationEvent {
    pub fn new(from_version: String, to_version: String) -> Self {
        Self {
            from_version,
            to_version,
            status: MigrationStatus::InProgress,
        }
    }

    pub fn update_status(&mut self, status: MigrationStatus) {
        self.status = status;
    }

    pub fn set_success(&mut self) {
        self.status = MigrationStatus::Success;
    }

    pub fn set_failed(&mut self) {
        self.status = MigrationStatus::Failed;
    }
}

impl From<MigrationEvent> for Event {
    fn from(event: MigrationEvent) -> Self {
        Event::new("migration").add_attributes([
            ("from_version", event.from_version),
            ("to_version", event.to_version),
            ("status", event.status.to_string()),
        ])
    }
}

#[derive(Debug)]
pub struct UpdateAllowlistsEvent<T> {
    pub new_addresses: Vec<String>,
    pub operation: String,
    pub operation_type: T,
    pub sender: String,
}

impl<T> From<UpdateAllowlistsEvent<T>> for Event
where
    T: std::string::ToString,
{
    fn from(event: UpdateAllowlistsEvent<T>) -> Self {
        Event::new("update_allowlists").add_attributes([
            ("new_addresses", event.new_addresses.join(",")),
            ("operation", event.operation),
            ("operation_type", event.operation_type.to_string()),
            ("sender", event.sender),
        ])
    }
}

#[derive(Debug)]
pub struct SenderAllowedEvent {
    operation: String,
    sender: String,
    allowed: bool,
}

impl SenderAllowedEvent {
    pub fn new(operation: String, sender: String) -> Self {
        Self {
            operation,
            sender,
            allowed: true,
        }
    }
}

impl From<SenderAllowedEvent> for Event {
    fn from(event: SenderAllowedEvent) -> Self {
        Event::new("sender_allowed").add_attributes([
            ("operation", event.operation),
            ("sender", event.sender),
            ("allowed", event.allowed.to_string()),
        ])
    }
}

#[derive(Debug)]
pub struct KeyAccessAllowedEvent {
    key_id: String,
    sender_allowed: String,
}

impl KeyAccessAllowedEvent {
    pub fn new(key_id: String, sender_allowed: String) -> Self {
        Self {
            key_id,
            sender_allowed,
        }
    }
}

impl From<KeyAccessAllowedEvent> for Event {
    fn from(event: KeyAccessAllowedEvent) -> Self {
        Event::new("key_access_allowed").add_attributes([
            ("key_id", event.key_id),
            ("sender_allowed", event.sender_allowed),
        ])
    }
}

#[derive(Debug)]
pub struct ContractAclUpdatedEvent {
    key_id: String,
    address_added: String,
}

impl ContractAclUpdatedEvent {
    pub fn new(key_id: String, address_added: String) -> Self {
        Self {
            key_id,
            address_added,
        }
    }
}

impl From<ContractAclUpdatedEvent> for Event {
    fn from(event: ContractAclUpdatedEvent) -> Self {
        Event::new("contract_acl_updated").add_attributes([
            ("key_id", event.key_id),
            ("address_added", event.address_added),
        ])
    }
}

#[derive(Debug)]
pub struct ConfigurationUpdatedEvent<T> {
    configuration_operation: String,
    old_value: T,
    new_value: T,
}

impl<T> ConfigurationUpdatedEvent<T> {
    pub fn new(configuration_operation: String, old_value: T, new_value: T) -> Self {
        Self {
            configuration_operation,
            old_value,
            new_value,
        }
    }
}

impl<T> From<ConfigurationUpdatedEvent<T>> for Event
where
    T: std::string::ToString,
{
    fn from(event: ConfigurationUpdatedEvent<T>) -> Self {
        Event::new("configuration_updated").add_attributes([
            ("configuration_operation", event.configuration_operation),
            ("old_value", event.old_value.to_string()),
            ("new_value", event.new_value.to_string()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::panic;
    use quickcheck::{Arbitrary, Gen};
    use strum::IntoEnumIterator;

    impl Arbitrary for FheParameter {
        fn arbitrary(g: &mut Gen) -> FheParameter {
            match u8::arbitrary(g) % 2 {
                0 => FheParameter::Test,
                1 => FheParameter::Default,
                _ => panic!("Invalid FheParameter"),
            }
        }
    }

    impl Arbitrary for FheType {
        fn arbitrary(g: &mut Gen) -> FheType {
            match u8::arbitrary(g) % 8 {
                0 => FheType::Ebool,
                1 => FheType::Euint4,
                2 => FheType::Euint8,
                3 => FheType::Euint16,
                4 => FheType::Euint32,
                5 => FheType::Euint64,
                6 => FheType::Euint128,
                7 => FheType::Euint160,
                _ => FheType::Unknown,
            }
        }
    }

    impl Arbitrary for KmsEventAttributeKey {
        fn arbitrary(g: &mut Gen) -> KmsEventAttributeKey {
            match u8::arbitrary(g) % 2 {
                0 => KmsEventAttributeKey::OperationType,
                _ => KmsEventAttributeKey::TransactionId,
            }
        }
    }

    impl Arbitrary for HexVector {
        fn arbitrary(g: &mut Gen) -> HexVector {
            HexVector(Vec::<u8>::arbitrary(g))
        }
    }

    impl Arbitrary for RedactedHexVectorList {
        fn arbitrary(g: &mut Gen) -> RedactedHexVectorList {
            RedactedHexVectorList(Vec::<HexVector>::arbitrary(g))
        }
    }

    impl Arbitrary for HexVectorList {
        fn arbitrary(g: &mut Gen) -> HexVectorList {
            HexVectorList(Vec::<HexVector>::arbitrary(g))
        }
    }

    impl Arbitrary for DecryptValues {
        fn arbitrary(g: &mut Gen) -> DecryptValues {
            DecryptValues {
                version: u32::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                fhe_types: Vec::<FheType>::arbitrary(g),
                ciphertext_handles: RedactedHexVectorList::arbitrary(g),
                external_handles: Some(HexVectorList::arbitrary(g)),
                proof: String::arbitrary(g),
                eip712_name: String::arbitrary(g),
                eip712_version: String::arbitrary(g),
                eip712_chain_id: HexVector::arbitrary(g),
                eip712_verifying_contract: String::arbitrary(g),
                eip712_salt: Some(HexVector::arbitrary(g)),
                acl_address: String::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptValues {
        fn arbitrary(g: &mut Gen) -> ReencryptValues {
            ReencryptValues {
                signature: HexVector::arbitrary(g),
                version: u32::arbitrary(g),
                client_address: String::arbitrary(g),
                enc_key: HexVector::arbitrary(g).into(),
                fhe_type: FheType::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                external_ciphertext_handle: HexVector::arbitrary(g).into(),
                ciphertext_handle: HexVector::arbitrary(g).into(),
                ciphertext_digest: HexVector::arbitrary(g).into(),
                proof: String::arbitrary(g),
                eip712_name: String::arbitrary(g),
                eip712_version: String::arbitrary(g),
                eip712_chain_id: HexVector::arbitrary(g),
                eip712_verifying_contract: String::arbitrary(g),
                eip712_salt: Some(HexVector::arbitrary(g)),
                acl_address: String::arbitrary(g),
            }
        }
    }

    impl Arbitrary for VerifyProvenCtValues {
        fn arbitrary(g: &mut Gen) -> VerifyProvenCtValues {
            VerifyProvenCtValues {
                crs_id: HexVector::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                contract_address: String::arbitrary(g),
                client_address: String::arbitrary(g),
                ct_proof_handle: HexVector::arbitrary(g).into(),
                acl_address: String::arbitrary(g),
                eip712_name: String::arbitrary(g),
                eip712_version: String::arbitrary(g),
                eip712_chain_id: HexVector::arbitrary(g),
                eip712_verifying_contract: String::arbitrary(g),
                eip712_salt: Some(HexVector::arbitrary(g)),
            }
        }
    }

    impl Arbitrary for DecryptResponseValues {
        fn arbitrary(g: &mut Gen) -> DecryptResponseValues {
            DecryptResponseValues {
                signature: HexVector::arbitrary(g),
                payload: HexVector::arbitrary(g),
            }
        }
    }

    impl Arbitrary for KeyGenResponseValues {
        fn arbitrary(g: &mut Gen) -> KeyGenResponseValues {
            KeyGenResponseValues {
                request_id: HexVector::arbitrary(g),
                public_key_digest: String::arbitrary(g),
                public_key_signature: HexVector::arbitrary(g),
                public_key_external_signature: HexVector::arbitrary(g),
                server_key_digest: String::arbitrary(g),
                server_key_signature: HexVector::arbitrary(g),
                server_key_external_signature: HexVector::arbitrary(g),
                param: FheParameter::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptResponseValues {
        fn arbitrary(g: &mut Gen) -> ReencryptResponseValues {
            ReencryptResponseValues {
                signature: HexVector::arbitrary(g),
                payload: HexVector::arbitrary(g),
                ciphertext_digest: None,
            }
        }
    }

    impl Arbitrary for VerifyProvenCtResponseValues {
        fn arbitrary(g: &mut Gen) -> VerifyProvenCtResponseValues {
            VerifyProvenCtResponseValues {
                signature: HexVector::arbitrary(g),
                payload: HexVector::arbitrary(g),
            }
        }
    }

    impl Arbitrary for CrsGenResponseValues {
        fn arbitrary(g: &mut Gen) -> CrsGenResponseValues {
            // TODO consider constraining the arbitrary domain
            // to only use request_id and digest of fixed length hex digits
            CrsGenResponseValues {
                request_id: String::arbitrary(g),
                digest: String::arbitrary(g),
                signature: HexVector::arbitrary(g),
                external_signature: HexVector::arbitrary(g),
                max_num_bits: u32::arbitrary(g),
                param: FheParameter::arbitrary(g),
            }
        }
    }

    impl Arbitrary for KmsOperation {
        fn arbitrary(g: &mut Gen) -> KmsOperation {
            match u8::arbitrary(g) % 8 {
                0 => KmsOperation::Decrypt,
                1 => KmsOperation::DecryptResponse,
                2 => KmsOperation::Reencrypt,
                3 => KmsOperation::ReencryptResponse,
                4 => KmsOperation::VerifyProvenCt,
                5 => KmsOperation::KeyGen,
                6 => KmsOperation::KeyGenResponse,
                7 => KmsOperation::CrsGen,
                _ => KmsOperation::CrsGenResponse,
            }
        }
    }

    impl Arbitrary for TransactionId {
        fn arbitrary(g: &mut Gen) -> TransactionId {
            TransactionId(HexVector::arbitrary(g))
        }
    }

    impl Arbitrary for KmsEvent {
        fn arbitrary(g: &mut Gen) -> KmsEvent {
            KmsEvent {
                operation: KmsOperation::arbitrary(g),
                txn_id: TransactionId::arbitrary(g),
            }
        }
    }

    #[test]
    fn test_create_kms_operation_event() {
        let operation = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(vec![1])
            .build();

        let event: Event = operation.into();
        let attributes = event.attributes;

        assert_eq!(event.ty, KmsOperation::Decrypt.to_string());

        assert_eq!(attributes.len(), 1);
        let result = attributes.iter().find(move |a| {
            a.key == KmsEventAttributeKey::TransactionId.to_string()
                && a.value == hex::encode(vec![1])
        });
        assert!(result.is_some());
    }

    #[test]
    fn test_decrypt_event_to_json() {
        let decrypt_values = DecryptValues::new(
            "my_key_id".as_bytes().to_vec(),
            vec![vec![1, 2, 3], vec![4, 4, 4]],
            vec![FheType::Euint8, FheType::Euint16],
            Some(vec![vec![9, 8, 7], vec![5, 4, 3]]),
            1,
            "acl_address".to_string(),
            "some_proof".to_string(),
            "eip712name".to_string(),
            "version".to_string(),
            [1; 32].to_vec(),
            "contract".to_string(),
            Some([42; 32].to_vec()),
        )
        .unwrap();
        let message: KmsMessageWithoutProof = KmsMessage::builder().value(decrypt_values).build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt": {
                "decrypt":{
                    "version": 1,
                    "key_id": hex::encode("my_key_id".as_bytes()),
                    "fhe_types": ["euint8", "euint16"],
                    "external_handles": [hex::encode([9,8,7]), hex::encode([5, 4, 3])],
                    "ciphertext_handles": [hex::encode([1, 2, 3]), hex::encode([4, 4, 4])],
                    "proof": "some_proof",
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([1; 32]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([42; 32]),
                    "acl_address": "acl_address",
                }
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_decrypt_response_event_to_json() {
        let decrypt_response_values = DecryptResponseValues::new(vec![4, 5, 6], vec![1, 2, 3]);
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(decrypt_response_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt_response": {
                "decrypt_response": {
                    "signature": hex::encode([4, 5, 6]),
                    "payload": hex::encode([1, 2, 3]),
                },
                "txn_id": hex::encode([1]),
            }
        });
        assert_eq!(json, json_str);

        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_reencrypt_event_to_json() {
        let reencrypt_values = ReencryptValues::new(
            vec![1],
            1,
            "0x1234".to_string(),
            vec![4],
            FheType::Ebool,
            "kid".as_bytes().to_vec(),
            vec![3],
            vec![5],
            vec![8],
            "0xfe11".to_string(),
            "some_proof".to_string(),
            "eip712name".to_string(),
            "version".to_string(),
            [0_u8; 32].to_vec(),
            "contract".to_string(),
            None::<Vec<u8>>,
        )
        .unwrap();
        let message: KmsMessageWithoutProof = KmsMessage::builder().value(reencrypt_values).build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt": {
                "reencrypt": {
                    "signature": hex::encode([1]),
                    "version": 1,
                    "client_address": "0x1234",
                    "enc_key": hex::encode(vec![4]),
                    "fhe_type": "ebool",
                    "key_id": hex::encode("kid".as_bytes()),
                    "external_ciphertext_handle": hex::encode(vec![3]),
                    "ciphertext_handle": hex::encode(vec![5]),
                    "ciphertext_digest": hex::encode(vec![8]),
                    "proof": "some_proof",
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([0_u8; 32]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": None::<Vec<u8>>,
                    "acl_address": "0xfe11",
                }
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_reencrypt_response_event_to_json() {
        let reencrypt_response_values = ReencryptResponseValues::new(vec![1], vec![2]);
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(reencrypt_response_values)
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt_response": {
                "reencrypt_response": {
                    "ciphertext_digest": null,
                    "signature": hex::encode([1]),
                    "payload": hex::encode([2]),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_verify_proven_ct_event_to_json() {
        let verify_proven_ct_values = VerifyProvenCtValues::new(
            "cid".as_bytes().to_vec(),
            "kid".as_bytes().to_vec(),
            "0x4321".to_string(),
            "0x1234".to_string(),
            vec![5],
            "0xfedc".to_string(),
            "eip712name".to_string(),
            "version".to_string(),
            [0_u8; 32].to_vec(),
            "contract".to_string(),
            Some([1_u8; 32].to_vec()),
        )
        .unwrap();
        let message: KmsMessageWithoutProof =
            KmsMessage::builder().value(verify_proven_ct_values).build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "verify_proven_ct": {
                "verify_proven_ct": {
                    "client_address": "0x1234",
                    "contract_address": "0x4321",
                    "acl_address": "0xfedc",
                    "crs_id": hex::encode("cid".as_bytes()),
                    "key_id": hex::encode("kid".as_bytes()),
                    "ct_proof_handle": hex::encode(vec![5]),
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([0_u8; 32]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([1_u8; 32]),
                },
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_verify_proven_ct_response_event_to_json() {
        let verify_proven_ct_response_values = VerifyProvenCtResponseValues::new(vec![1], vec![2]);
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(verify_proven_ct_response_values)
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "verify_proven_ct_response": {
                "verify_proven_ct_response": {
                    "signature": hex::encode([1]),
                    "payload": hex::encode([2]),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_keygen_event_to_json() {
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .value(
                KeyGenValues::new(
                    vec![],
                    "eip712name".to_string(),
                    "version".to_string(),
                    [1; 32].to_vec(),
                    "contract".to_string(),
                    Some([42; 32].to_vec()),
                )
                .unwrap(),
            )
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "keygen": {
                "keygen": {
                    "preproc_id": "",
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([1; 32]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([42; 32]),
                }
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_keygen_response_event_to_json() {
        let keygen_response_values = KeyGenResponseValues::new(
            vec![2, 2, 2],
            "abc".to_string(),
            vec![1, 2, 3],
            vec![1, 2, 3],
            "def".to_string(),
            vec![4, 5, 6],
            vec![7, 2, 7],
            FheParameter::Test,
        );
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(keygen_response_values)
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "keygen_response": {
                "keygen_response": {
                    "request_id": hex::encode([2, 2, 2]),
                    "public_key_digest": "abc",
                    "public_key_signature": hex::encode([1, 2, 3]),
                    "public_key_external_signature": hex::encode([1, 2, 3]),
                    "server_key_digest": "def",
                    "server_key_signature": hex::encode([4, 5, 6]),
                    "server_key_external_signature": hex::encode([7, 2 ,7]),
                    "param": FheParameter::Test.to_string(),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_crs_gen_event_to_json() {
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .value(
                CrsGenValues::new(
                    256,
                    "eip712name".to_string(),
                    "version".to_string(),
                    [1; 32].to_vec(),
                    "contract".to_string(),
                    None::<Vec<u8>>,
                )
                .unwrap(),
            )
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "crs_gen": {
                "crs_gen": {
                    "max_num_bits": 256,


                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([1; 32]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": None::<Vec<u8>>,
                }
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[test]
    fn test_crs_gen_response_event_to_json() {
        let crs_gen_response_values = CrsGenResponseValues::new(
            "abcdef".to_string(),
            "123456".to_string(),
            vec![1, 2, 3],
            vec![5, 3, 1],
            256,
            FheParameter::Test,
        );

        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(crs_gen_response_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "crs_gen_response": {
                "crs_gen_response": {
                    "request_id": "abcdef",
                    "digest": "123456",
                    "signature": hex::encode([1, 2, 3]),
                    "external_signature": hex::encode([5, 3, 1]),
                    "max_num_bits": 256,
                    "param": FheParameter::Test.to_string(),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
        let reconstructed_json = KmsMessage::from_json(&json_str.to_string()).unwrap();
        assert_eq!(reconstructed_json, message);
    }

    #[quickcheck]
    fn reversable_prop_on_event_to(xs: Vec<KmsEvent>) -> bool {
        let events = xs
            .iter()
            .map(|x| <KmsEvent as Into<Event>>::into(x.clone()))
            .map(|mut x| {
                x.ty = format!("wasm-{}", x.ty);
                x
            })
            .collect::<Vec<Event>>();
        let kms_event = events
            .iter()
            .map(|x| <Event as TryInto<KmsEvent>>::try_into(x.clone()))
            .collect::<Result<Vec<KmsEvent>, _>>();
        let kms_event = kms_event.unwrap();
        kms_event == xs
    }

    #[test]
    fn fhe_parameter_serialization() {
        // make sure these strings match what's in the protobuf [FheParameter]
        for fhe_parameter in FheParameter::iter() {
            match fhe_parameter {
                FheParameter::Default => {
                    assert_eq!(fhe_parameter.to_fhe_parameter_string(), "default");
                }
                FheParameter::Test => {
                    assert_eq!(fhe_parameter.to_fhe_parameter_string(), "test");
                }
            }
        }
    }

    #[test]
    fn txn_id_to_u64() {
        // test padding
        let t = TransactionId::from_hex("00").unwrap();
        assert_eq!(t.to_u64(), 0);
        let t = TransactionId::from_hex("01").unwrap();
        assert_eq!(t.to_u64(), 1);
        let t = TransactionId::from_hex("0102").unwrap();
        assert_eq!(t.to_u64(), 513);

        // 8 byte value
        let t = TransactionId::from_hex("2023232323232323").unwrap();
        assert_eq!(t.to_u64(), 2531906049332683552);

        // test truncation
        let t = TransactionId::from_hex("2023232323232323FFEEDD").unwrap();
        assert_eq!(t.to_u64(), 2531906049332683552);
        let t = TransactionId::from_hex("21232323232323230000DD42").unwrap();
        assert_eq!(t.to_u64(), 2531906049332683553);
    }
}
