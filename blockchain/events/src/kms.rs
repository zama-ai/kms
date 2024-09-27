use super::conversions::*;
use core::hash::Hash;
use core::hash::Hasher;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::to_json_binary;
use cosmwasm_std::{Attribute, Event};
use serde::ser::SerializeMap;
use serde::Serialize;
use serde_json::Value;
use std::ops::Deref;
use std::str::FromStr;
use strum::EnumProperty;
use strum_macros::{Display, EnumIs, EnumIter, EnumString};
use typed_builder::TypedBuilder;

#[cw_serde]
pub enum KmsCoreConf {
    Centralized(FheParameter),
    Threshold(KmsCoreThresholdConf),
}

/// This type needs to match the protobuf type
/// called [ParamChoice].
#[cw_serde]
#[derive(Copy, Default, EnumString, Eq, Display, EnumIter)]
pub enum FheParameter {
    #[default]
    #[strum(serialize = "default")]
    Default,
    #[strum(serialize = "test")]
    Test,
}

#[cw_serde]
pub struct KmsCoreThresholdConf {
    pub parties: Vec<KmsCoreParty>,
    pub response_count_for_majority_vote: usize,
    pub response_count_for_reconstruction: usize,
    pub degree_for_reconstruction: usize,
    pub param_choice: FheParameter,
}

impl KmsCoreConf {
    pub fn param_choice_string(&self) -> String {
        let param = match self {
            KmsCoreConf::Centralized(param_choice) => param_choice,
            KmsCoreConf::Threshold(inner) => &inner.param_choice,
        };
        // Our string representation is defined by the serialized json,
        // but the json encoding surrounds the string with double quotes,
        // so we need to extract the inner string so this result can be
        // processed by other functions, e.g., turned into a [ParamChoice].
        serde_json::json!(param)
            .to_string()
            .trim_matches('\"')
            .to_string()
    }

    /// The number of responses to perform majority voting.
    ///
    /// In the centralized setting, this is always 1.
    pub fn response_count_for_majority_vote(&self) -> usize {
        match self {
            KmsCoreConf::Centralized(_) => 1,
            KmsCoreConf::Threshold(x) => x.response_count_for_majority_vote,
        }
    }

    /// The number of shares needed to perform reconstruction.
    ///
    /// In the centralized setting, this is always 1.
    pub fn response_count_for_reconstruction(&self) -> usize {
        match self {
            KmsCoreConf::Centralized(_) => 1,
            KmsCoreConf::Threshold(x) => x.response_count_for_reconstruction,
        }
    }
}

#[cw_serde]
#[derive(Default)]
pub struct KmsCoreParty {
    pub party_id: HexVector,
    pub public_key: Option<RedactedHexVector>,
    pub address: String,
    pub tls_pub_key: Option<HexVector>,
}

#[cw_serde]
#[derive(Eq, EnumString, Display, EnumIter, strum_macros::EnumProperty, EnumIs)]
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
    #[strum(serialize = "zkp")]
    #[serde(rename = "zkp")]
    Zkp(ZkpValues),
    #[strum(serialize = "zkp_response")]
    #[serde(rename = "zkp_response")]
    ZkpResponse(ZkpResponseValues),
    #[strum(serialize = "keygen")]
    #[serde(rename = "keygen")]
    KeyGen(KeyGenValues),
    #[strum(serialize = "keygen_response")]
    #[serde(rename = "keygen_response")]
    KeyGenResponse(KeyGenResponseValues),
    #[strum(serialize = "keygen_preproc")]
    #[serde(rename = "keygen_preproc")]
    KeyGenPreproc(KeyGenPreprocValues),
    #[strum(serialize = "keygen_preproc_response")]
    #[serde(rename = "keygen_preproc_response")]
    KeyGenPreprocResponse(KeyGenPreprocResponseValues),
    #[strum(serialize = "crs_gen")]
    #[serde(rename = "crs_gen")]
    CrsGen(CrsGenValues),
    #[strum(serialize = "crs_gen_response")]
    #[serde(rename = "crs_gen_response")]
    CrsGenResponse(CrsGenResponseValues),
}

impl OperationValue {
    fn has_no_inner_value(&self) -> bool {
        matches!(
            self,
            Self::CrsGen(_) | Self::KeyGenPreproc(_) | Self::KeyGenPreprocResponse(_)
        )
    }

    /// Returns true if this operation needs information
    /// from the configuration smart contract to operate.
    pub fn needs_kms_config(&self) -> bool {
        matches!(
            self,
            Self::Decrypt(_)
                | Self::Reencrypt(_)
                | Self::CrsGen(_)
                | Self::KeyGenPreproc(_)
                | Self::KeyGen(_)
        )
    }
}

impl From<OperationValue> for KmsOperation {
    fn from(value: OperationValue) -> Self {
        match value {
            OperationValue::Decrypt(_) => KmsOperation::Decrypt,
            OperationValue::DecryptResponse(_) => KmsOperation::DecryptResponse,
            OperationValue::Reencrypt(_) => KmsOperation::Reencrypt,
            OperationValue::ReencryptResponse(_) => KmsOperation::ReencryptResponse,
            OperationValue::Zkp(_) => KmsOperation::Zkp,
            OperationValue::ZkpResponse(_) => KmsOperation::Zkp,
            OperationValue::KeyGen(_) => KmsOperation::KeyGen,
            OperationValue::KeyGenResponse(_) => KmsOperation::KeyGenResponse,
            OperationValue::KeyGenPreproc(_) => KmsOperation::KeyGenPreproc,
            OperationValue::KeyGenPreprocResponse(_) => KmsOperation::KeyGenPreprocResponse,
            OperationValue::CrsGen(_) => KmsOperation::CrsGen,
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

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct Transaction {
    block_height: u64,
    transaction_index: u32,
    #[builder(setter(into), default)]
    operations: Vec<OperationValue>,
}

impl Transaction {
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    pub fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    pub fn operations(&self) -> &Vec<OperationValue> {
        &self.operations
    }

    pub fn add_operation(&mut self, operation: OperationValue) -> Result<(), anyhow::Error> {
        self.operations.push(operation);
        Ok(())
    }
}

#[cw_serde]
#[derive(Copy, Default, EnumString, Eq, Display)]
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

#[cw_serde]
#[derive(Copy, Eq, EnumString, Display)]
pub enum KmsEventAttributeKey {
    #[strum(serialize = "kmsoperation")]
    OperationType,
    #[strum(serialize = "txn_id")]
    TransactionId,
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct DecryptValues {
    /// The ID of the FHE public key used
    #[builder(setter(into))]
    key_id: HexVector,
    /// The list of KV store ciphertext handles to be decrypted
    #[builder(setter(into))]
    ciphertext_handles: RedactedHexVectorList,
    /// The list of FHE types of the above ciphertexts
    fhe_types: Vec<FheType>,
    /// The list of external handles of the above ciphertexts (e.g. from fheVM)
    external_handles: Option<HexVectorList>,
    /// The version number
    version: u32,
    /// The address of the ACL contract
    #[builder(setter(into))]
    acl_address: String,

    // EIP-712
    /// The name of the EIP-712 domain
    #[builder(setter(into))]
    eip712_name: String,
    /// The version of the EIP-712 domain
    #[builder(setter(into))]
    eip712_version: String,
    /// The chain-id used for EIP-712
    #[builder(setter(into))]
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    #[builder(setter(into))]
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    #[builder(setter(into))]
    eip712_salt: HexVector,
}

impl DecryptValues {
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

    pub fn eip712_salt(&self) -> &HexVector {
        &self.eip712_salt
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

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct ReencryptValues {
    #[builder(setter(into))]
    signature: HexVector,

    // Payload
    /// The version number
    version: u32,
    /// The address of the client receiving the reencryption output
    client_address: String,
    /// The encyption key of the client
    #[builder(setter(into))]
    enc_key: RedactedHexVector,
    /// The FHE type of the value to be reencrypted
    fhe_type: FheType,
    /// The ID of the FHE public key used
    #[builder(setter(into))]
    key_id: HexVector,
    /// The KV-store handle of the ciphertext to be reencrypted
    #[builder(setter(into))]
    ciphertext_handle: RedactedHexVector,
    /// The SHA3 digest of the ciphertext to be reencrypted
    #[builder(setter(into))]
    ciphertext_digest: RedactedHexVector,

    // EIP-712:
    /// The name of the EIP-712 domain
    #[builder(setter(into))]
    eip712_name: String,
    /// The version of the EIP-712 domain
    #[builder(setter(into))]
    eip712_version: String,
    /// The chain-id used for EIP-712
    #[builder(setter(into))]
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    #[builder(setter(into))]
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    #[builder(setter(into))]
    eip712_salt: HexVector,
}

impl ReencryptValues {
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

    pub fn ciphertext_handle(&self) -> &RedactedHexVector {
        &self.ciphertext_handle
    }

    pub fn ciphertext_digest(&self) -> &RedactedHexVector {
        &self.ciphertext_digest
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

    pub fn eip712_salt(&self) -> &HexVector {
        &self.eip712_salt
    }
}

impl From<ReencryptValues> for OperationValue {
    fn from(value: ReencryptValues) -> Self {
        OperationValue::Reencrypt(value)
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct ZkpValues {
    /// The ID of the CRS used
    #[builder(setter(into))]
    crs_id: HexVector,
    /// The ID of the FHE public key used
    #[builder(setter(into))]
    key_id: HexVector,
    /// The address of the dapp the input is used for
    #[builder(setter(into))]
    contract_address: String,
    /// The address of the client providing the input
    #[builder(setter(into))]
    client_address: String,
    /// The KV-store handle of the ciphertext and proof to be verified
    #[builder(setter(into))]
    ct_proof_handle: RedactedHexVector,
    /// The address of the ACL contract
    #[builder(setter(into))]
    acl_address: String,

    // EIP-712:
    /// The name of the EIP-712 domain
    #[builder(setter(into))]
    eip712_name: String,
    /// The version of the EIP-712 domain
    #[builder(setter(into))]
    eip712_version: String,
    /// The chain-id used for EIP-712
    #[builder(setter(into))]
    eip712_chain_id: HexVector,
    /// The contract verifying the EIP-712 signature
    #[builder(setter(into))]
    eip712_verifying_contract: String,
    /// The optional EIP-712 salt
    #[builder(setter(into))]
    eip712_salt: HexVector,
}

impl ZkpValues {
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

    pub fn eip712_salt(&self) -> &HexVector {
        &self.eip712_salt
    }
}

impl From<ZkpValues> for OperationValue {
    fn from(value: ZkpValues) -> Self {
        OperationValue::Zkp(value)
    }
}
#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct DecryptResponseValues {
    #[builder(setter(into))]
    signature: HexVector,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    #[builder(setter(into))]
    payload: HexVector,
}

impl DecryptResponseValues {
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

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct KeyGenPreprocResponseValues {
    // NOTE: there's no actual response except an "ok"
}

impl From<KeyGenPreprocResponseValues> for OperationValue {
    fn from(value: KeyGenPreprocResponseValues) -> Self {
        OperationValue::KeyGenPreprocResponse(value)
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct KeyGenResponseValues {
    #[builder(setter(into))]
    request_id: HexVector,
    public_key_digest: String,
    #[builder(setter(into))]
    public_key_signature: HexVector,
    // server key is bootstrap key
    server_key_digest: String,
    #[builder(setter(into))]
    server_key_signature: HexVector,
    // we do not need SnS key
}

impl KeyGenResponseValues {
    pub fn request_id(&self) -> &HexVector {
        &self.request_id
    }

    pub fn public_key_digest(&self) -> &str {
        &self.public_key_digest
    }

    pub fn public_key_signature(&self) -> &HexVector {
        &self.public_key_signature
    }

    pub fn server_key_digest(&self) -> &str {
        &self.server_key_digest
    }

    pub fn server_key_signature(&self) -> &HexVector {
        &self.server_key_signature
    }
}

impl From<KeyGenResponseValues> for OperationValue {
    fn from(value: KeyGenResponseValues) -> Self {
        OperationValue::KeyGenResponse(value)
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct ReencryptResponseValues {
    #[builder(setter(into))]
    signature: HexVector,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    #[builder(setter(into))]
    payload: HexVector,
}

impl ReencryptResponseValues {
    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn payload(&self) -> &HexVector {
        &self.payload
    }
}

impl From<ReencryptResponseValues> for OperationValue {
    fn from(value: ReencryptResponseValues) -> Self {
        OperationValue::ReencryptResponse(value)
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct ZkpResponseValues {
    #[builder(setter(into))]
    signature: HexVector,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    #[builder(setter(into))]
    payload: HexVector,
}

impl ZkpResponseValues {
    pub fn signature(&self) -> &HexVector {
        &self.signature
    }

    pub fn payload(&self) -> &HexVector {
        &self.payload
    }
}

impl From<ZkpResponseValues> for OperationValue {
    fn from(value: ZkpResponseValues) -> Self {
        OperationValue::ZkpResponse(value)
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct CrsGenResponseValues {
    /// The request ID of the CRS generation.
    request_id: String,
    /// The CRS digest, which can be used to derive the storage URL for the CRS.
    digest: String,
    /// The signature on the digest.
    #[builder(setter(into))]
    signature: HexVector,
}

impl CrsGenResponseValues {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn signature(&self) -> &HexVector {
        &self.signature
    }
}

impl From<CrsGenResponseValues> for OperationValue {
    fn from(value: CrsGenResponseValues) -> Self {
        OperationValue::CrsGenResponse(value)
    }
}

#[cw_serde]
#[derive(Eq, Default)]
pub struct KeyGenPreprocValues {}

impl From<KeyGenPreprocValues> for OperationValue {
    fn from(value: KeyGenPreprocValues) -> Self {
        OperationValue::KeyGenPreproc(value)
    }
}

#[cw_serde]
#[derive(Eq, Default, TypedBuilder)]
pub struct KeyGenValues {
    /// Hex-encoded preprocessing ID.
    /// This ID refers to the request ID of a preprocessing request.
    preproc_id: HexVector,
}

impl KeyGenValues {
    pub fn preproc_id(&self) -> &HexVector {
        &self.preproc_id
    }
}

impl From<KeyGenValues> for OperationValue {
    fn from(value: KeyGenValues) -> Self {
        OperationValue::KeyGen(value)
    }
}

#[cw_serde]
#[derive(Eq, Default)]
pub struct CrsGenValues {}

impl From<CrsGenValues> for OperationValue {
    fn from(value: CrsGenValues) -> Self {
        OperationValue::CrsGen(value)
    }
}

#[cw_serde]
#[derive(Eq, EnumString, Display, EnumIter, strum_macros::EnumProperty, EnumIs, Default)]
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
    #[strum(serialize = "zkp", props(request = "true"))]
    Zkp,
    #[strum(serialize = "zkp_response", props(response = "true"))]
    ZkpResponse,
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
    #[strum(serialize = "crs_gen", props(request = "true"))]
    #[serde(rename = "crs_gen")]
    CrsGen,
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
}

#[cw_serde]
#[derive(Eq, Default, TypedBuilder)]
pub struct Proof<T> {
    pub proof: T,
    pub contract_address: String,
}

#[derive(Eq, PartialEq, Clone, Debug, TypedBuilder)]
pub struct KmsMessage<T = ()> {
    #[builder(setter(into), default = None)]
    txn_id: Option<TransactionId>,
    #[builder(setter(into), default = None)]
    proof: Option<Proof<T>>,
    #[builder(setter(into))]
    value: OperationValue,
}

pub type KmsMessageWithoutProof = KmsMessage<()>;

#[derive(Serialize)]
struct InnerKmsMessage<'a, T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    txn_id: Option<&'a TransactionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<&'a Proof<T>>,
    #[serde(flatten, skip_serializing_if = "OperationValue::has_no_inner_value")]
    value: &'a OperationValue,
}

impl<T> Serialize for KmsMessage<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let proof: Option<Proof<Vec<u8>>> = self
            .proof
            .as_ref()
            .map(|p| {
                let proof = to_json_binary(&p.proof).map_err(|e| {
                    serde::ser::Error::custom(format!("Failed to serialize proof: {}", e))
                })?;
                Ok(Proof {
                    proof: proof.to_vec(),
                    contract_address: p.contract_address.clone(),
                })
            })
            .transpose()?;
        let data = InnerKmsMessage {
            txn_id: self.txn_id.as_ref(),
            proof: proof.as_ref(),
            value: &self.value,
        };
        let operation = Box::leak(self.value.to_string().into_boxed_str());
        let mut ser = serializer.serialize_map(None)?;
        ser.serialize_entry(operation, &data)?;
        ser.end()
    }
}

impl<T> KmsMessage<T>
where
    T: Serialize,
{
    pub fn txn_id(&self) -> Option<&TransactionId> {
        self.txn_id.as_ref()
    }

    pub fn value(&self) -> &OperationValue {
        &self.value
    }

    pub fn proof(&self) -> Option<&Proof<T>> {
        self.proof.as_ref()
    }

    pub fn to_json(&self) -> Result<Value, serde_json::error::Error> {
        serde_json::to_value(self)
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
#[derive(Eq, TypedBuilder, Default)]
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
#[derive(Eq, TypedBuilder)]
pub struct TransactionEvent {
    pub tx_hash: String,
    pub event: KmsEvent,
}

#[cfg(test)]
mod tests {

    use quickcheck::{Arbitrary, Gen};
    use strum::IntoEnumIterator;

    use super::*;

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
                eip712_name: String::arbitrary(g),
                eip712_version: String::arbitrary(g),
                eip712_chain_id: HexVector::arbitrary(g),
                eip712_verifying_contract: String::arbitrary(g),
                eip712_salt: HexVector::arbitrary(g),
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
                ciphertext_handle: HexVector::arbitrary(g).into(),
                ciphertext_digest: HexVector::arbitrary(g).into(),
                eip712_name: String::arbitrary(g),
                eip712_version: String::arbitrary(g),
                eip712_chain_id: HexVector::arbitrary(g),
                eip712_verifying_contract: String::arbitrary(g),
                eip712_salt: HexVector::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ZkpValues {
        fn arbitrary(g: &mut Gen) -> ZkpValues {
            ZkpValues {
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
                eip712_salt: HexVector::arbitrary(g),
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
                server_key_digest: String::arbitrary(g),
                server_key_signature: HexVector::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptResponseValues {
        fn arbitrary(g: &mut Gen) -> ReencryptResponseValues {
            ReencryptResponseValues {
                signature: HexVector::arbitrary(g),
                payload: HexVector::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ZkpResponseValues {
        fn arbitrary(g: &mut Gen) -> ZkpResponseValues {
            ZkpResponseValues {
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
                4 => KmsOperation::Zkp,
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
        let decrypt_values = DecryptValues::builder()
            .version(1)
            .key_id("mykeyid".as_bytes().to_vec())
            .ciphertext_handles(vec![vec![1, 2, 3], vec![4, 4, 4]])
            .fhe_types(vec![FheType::Euint8, FheType::Euint16])
            .external_handles(Some(vec![vec![9, 8, 7], vec![5, 4, 3]].into()))
            .eip712_name("eip712name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![6])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![7])
            .acl_address("acl_address".to_string())
            .build();
        let proof_values = Proof::default();
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .value(decrypt_values)
            .proof(proof_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt": {
                "decrypt":{
                    "version": 1,
                    "key_id": hex::encode("mykeyid".as_bytes()),
                    "fhe_types": ["euint8", "euint16"],
                    "external_handles": [hex::encode([9,8,7]), hex::encode([5, 4, 3])],
                    "ciphertext_handles": [hex::encode([1, 2, 3]), hex::encode([4, 4, 4])],
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([6]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([7]),
                    "acl_address": "acl_address",
                },
                "proof": {
                    "proof": [110,117,108,108],
                    "contract_address": ""
                }
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_decrypt_response_event_to_json() {
        let decrypt_response_values = DecryptResponseValues::builder()
            .signature(vec![4, 5, 6])
            .payload(vec![1, 2, 3])
            .build();
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
    }

    #[test]
    fn test_reencrypt_event_to_json() {
        let reencrypt_values = ReencryptValues::builder()
            .signature(vec![1])
            .version(1)
            .client_address("0x1234".to_string())
            .enc_key(vec![4])
            .fhe_type(FheType::Ebool)
            .key_id("kid".as_bytes().to_vec())
            .ciphertext_handle(vec![5])
            .ciphertext_digest(vec![8])
            .eip712_name("eip712name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![6])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![7])
            .build();
        let proof_values = Proof::default();
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .value(reencrypt_values)
            .proof(proof_values)
            .build();

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
                    "ciphertext_handle": hex::encode(vec![5]),
                    "ciphertext_digest": hex::encode(vec![8]),
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([6]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([7]),
                },
                "proof": {
                    "proof": [110,117,108,108],
                    "contract_address": ""
                }
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_reencrypt_response_event_to_json() {
        let reencrypt_response_values = ReencryptResponseValues::builder()
            .signature(vec![1])
            .payload(vec![2])
            .build();
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(reencrypt_response_values)
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt_response": {
                "reencrypt_response": {
                    "signature": hex::encode([1]),
                    "payload": hex::encode([2]),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_zkp_event_to_json() {
        let zkp_values = ZkpValues::builder()
            .client_address("0x1234".to_string())
            .contract_address("0x4321".to_string())
            .crs_id("cid".as_bytes().to_vec())
            .key_id("kid".as_bytes().to_vec())
            .ct_proof_handle(vec![5])
            .acl_address("0xfedc".to_string())
            .eip712_name("eip712name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![6])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![7])
            .build();
        let message: KmsMessageWithoutProof = KmsMessage::builder().value(zkp_values).build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "zkp": {
                "zkp": {
                    "client_address": "0x1234",
                    "contract_address": "0x4321",
                    "acl_address": "0xfedc",
                    "crs_id": hex::encode("cid".as_bytes()),
                    "key_id": hex::encode("kid".as_bytes()),
                    "ct_proof_handle": hex::encode(vec![5]),
                    "eip712_name": "eip712name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([6]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([7]),
                },
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_zkp_response_event_to_json() {
        let zkp_response_values = ZkpResponseValues::builder()
            .signature(vec![1])
            .payload(vec![2])
            .build();
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .value(zkp_response_values)
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "zkp_response": {
                "zkp_response": {
                    "signature": hex::encode([1]),
                    "payload": hex::encode([2]),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_keygen_event_to_json() {
        let proof_values = Proof::default();
        let message: KmsMessageWithoutProof = KmsMessage::builder()
            .value(KeyGenValues::default())
            .proof(proof_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "keygen": {
                "keygen": {
                    "preproc_id": ""
                },
                "proof": {
                    "proof": [110, 117, 108, 108],
                    "contract_address": ""
                }
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_keygen_response_event_to_json() {
        let keygen_response_values = KeyGenResponseValues::builder()
            .request_id(vec![2, 2, 2])
            .public_key_digest("abc".to_string())
            .public_key_signature(vec![1, 2, 3])
            .server_key_digest("def".to_string())
            .server_key_signature(vec![4, 5, 6])
            .build();
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
                    "server_key_digest": "def",
                    "server_key_signature": hex::encode([4, 5, 6]),
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_crs_gen_event_to_json() {
        let message: KmsMessageWithoutProof =
            KmsMessage::builder().value(CrsGenValues::default()).build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "crs_gen": {  }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_crs_gen_response_event_to_json() {
        let crs_gen_response_values = CrsGenResponseValues::builder()
            .request_id("abcdef".to_string())
            .digest("123456".to_string())
            .signature(vec![1, 2, 3])
            .build();

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
                },
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
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
    fn param_choice_serialization() {
        // make sure these strings match what's in the protobuf [ParamChoice]
        for choice in FheParameter::iter() {
            match choice {
                FheParameter::Default => {
                    let conf = KmsCoreConf::Centralized(choice);
                    assert_eq!(conf.param_choice_string(), "default");
                }
                FheParameter::Test => {
                    let conf = KmsCoreConf::Centralized(choice);
                    assert_eq!(conf.param_choice_string(), "test");
                }
            }
        }
    }
}
