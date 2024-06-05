use super::conversions::*;
use cosmwasm_schema::cw_serde;
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
    pub shares_needed: usize,
    pub param_choice: FheParameter,
}

impl KmsCoreThresholdConf {
    fn calculate_threshold(&self) -> usize {
        (self.parties.len().saturating_sub(1) as u8 / 3) as usize
    }

    fn shares_needed_is_ok(&self) -> bool {
        self.shares_needed > self.calculate_threshold()
    }
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

    /// The number of shares (or responses in general)
    /// that are needed to process the result from KMS core.
    ///
    /// In the centralized setting, [shares_needed] is always 1.
    pub fn shares_needed(&self) -> usize {
        match self {
            KmsCoreConf::Centralized(_) => 1,
            KmsCoreConf::Threshold(x) => x.shares_needed,
        }
    }

    /// Check whether [shares_needed] is configured correctly.
    ///
    /// At the moment we're under the optimistic assumption,
    /// where there are no corruption, so only t+1 shares
    /// are needed to reconstruct.
    pub fn shares_needed_is_ok(&self) -> bool {
        match self {
            KmsCoreConf::Centralized(_) => true,
            KmsCoreConf::Threshold(x) => x.shares_needed_is_ok(),
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
    ///
    /// At the moment only decrypt and reencrypt needs
    /// the `shares_needed` attribute from the configuration contract.
    /// Later we may add the role assignment (for the threshold setup)
    /// into the configuration contract and this method needs to be updated.
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
        if self.operations.iter().any(|op| op == &operation) {
            return Err(anyhow::anyhow!("Operation already exists"));
        }
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
}

#[cw_serde]
#[derive(Copy, Eq, EnumString, Display)]
pub enum KmsEventAttributeKey {
    #[strum(serialize = "kmsoperation")]
    OperationType,
    #[strum(serialize = "txn_id")]
    TransactionId,
    #[strum(serialize = "proof")]
    Proof,
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct DecryptValues {
    /// key_id refers to the key that should be used for decryption
    /// created at key generation.
    #[builder(setter(into))]
    key_id: HexVector,
    #[builder(setter(into))]
    ciphertext: RedactedHexVector,
    #[builder(setter(into))]
    randomness: RedactedHexVector,
    version: u32,
    fhe_type: FheType,
}

impl DecryptValues {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn ciphertext(&self) -> &RedactedHexVector {
        &self.ciphertext
    }

    pub fn randomness(&self) -> &RedactedHexVector {
        &self.randomness
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

    // payload
    version: u32,
    #[builder(setter(into))]
    verification_key: RedactedHexVector,
    #[builder(setter(into))]
    randomness: RedactedHexVector,
    #[builder(setter(into))]
    enc_key: RedactedHexVector,
    fhe_type: FheType,
    #[builder(setter(into))]
    key_id: HexVector,
    #[builder(setter(into))]
    ciphertext: RedactedHexVector,
    #[builder(setter(into))]
    ciphertext_digest: RedactedHexVector,

    // eip712
    eip712_name: String,
    eip712_version: String,
    #[builder(setter(into))]
    eip712_chain_id: HexVector,
    eip712_verifying_contract: String,
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

    pub fn verification_key(&self) -> &RedactedHexVector {
        &self.verification_key
    }

    pub fn randomness(&self) -> &RedactedHexVector {
        &self.randomness
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

    pub fn ciphertext(&self) -> &RedactedHexVector {
        &self.ciphertext
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
    version: u32,
    servers_needed: u32,
    #[builder(setter(into))]
    verification_key: HexVector,
    #[builder(setter(into))]
    digest: HexVector,
    fhe_type: FheType,
    #[builder(setter(into))]
    signcrypted_ciphertext: HexVector,
}

impl ReencryptResponseValues {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn servers_needed(&self) -> u32 {
        self.servers_needed
    }

    pub fn verification_key(&self) -> &HexVector {
        &self.verification_key
    }

    pub fn digest(&self) -> &HexVector {
        &self.digest
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn signcrypted_ciphertext(&self) -> &HexVector {
        &self.signcrypted_ciphertext
    }
}

impl From<ReencryptResponseValues> for OperationValue {
    fn from(value: ReencryptResponseValues) -> Self {
        OperationValue::ReencryptResponse(value)
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

#[derive(Eq, PartialEq, Clone, Debug, TypedBuilder)]
pub struct KmsMessage {
    #[builder(setter(into), default = None)]
    txn_id: Option<TransactionId>,
    #[builder(setter(into))]
    proof: Proof,
    #[builder(setter(into))]
    value: OperationValue,
}

#[derive(Serialize)]
struct InnerKmsMessage<'a> {
    proof: &'a Proof,
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
            proof: &self.proof,
            txn_id: self.txn_id.as_ref(),
            value: self.value(),
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

    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    pub fn value(&self) -> &OperationValue {
        &self.value
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

#[cw_serde]
#[derive(Eq, Default)]
pub struct Proof(pub(crate) HexVector);

impl Deref for Proof {
    type Target = HexVector;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Proof {
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(Proof(HexVector::from_hex(hex)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.deref().deref().clone()
    }
}

impl From<&HexVector> for Proof {
    fn from(value: &HexVector) -> Self {
        Proof(value.clone())
    }
}

impl From<HexVector> for Proof {
    fn from(value: HexVector) -> Self {
        Proof(value)
    }
}

impl From<Vec<u8>> for Proof {
    fn from(value: Vec<u8>) -> Self {
        Proof(HexVector(value))
    }
}

impl From<Proof> for Attribute {
    fn from(value: Proof) -> Self {
        Attribute::new(KmsEventAttributeKey::Proof.to_string(), value.0.to_hex())
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct KmsEvent {
    #[builder(setter(into))]
    operation: KmsOperation,
    #[builder(setter(into))]
    txn_id: TransactionId,
    #[builder(setter(into))]
    proof: Proof,
}

impl KmsEvent {
    pub fn operation(&self) -> &KmsOperation {
        &self.operation
    }

    pub fn txn_id(&self) -> &TransactionId {
        &self.txn_id
    }

    pub fn proof(&self) -> &Proof {
        &self.proof
    }
}

impl From<KmsEvent> for Event {
    fn from(value: KmsEvent) -> Self {
        let event_type = value.operation().to_string();
        let attributes = vec![
            <TransactionId as Into<Attribute>>::into(value.txn_id),
            <Proof as Into<Attribute>>::into(value.proof),
        ];
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
            .ok_or(anyhow::anyhow!("Missing txn_id attribute"))?;
        let txn_id: TransactionId = attributes
            .get(pos_tx_id)
            .map(|a| hex::decode(a.value.as_str()))
            .transpose()?
            .map(Into::into)
            .ok_or(anyhow::anyhow!("Missing txn_id attribute"))?;
        let pos_proof_id = attributes
            .iter()
            .position(|a| a.key == "proof")
            .ok_or(anyhow::anyhow!("Missing proof attribute"))?;
        let proof = attributes
            .get(pos_proof_id)
            .map(|a| hex::decode(a.value.as_str()))
            .transpose()?
            .map(Into::into)
            .ok_or(anyhow::anyhow!("Missing proof attribute"))?;
        attributes.remove(pos_tx_id);
        let operation = event
            .ty
            .as_str()
            .strip_prefix("wasm-")
            .ok_or(anyhow::anyhow!("Invalid event type"))?;
        let operation = KmsOperation::from_str(operation)?;
        Ok(KmsEvent {
            operation,
            txn_id,
            proof,
        })
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

    #[test]
    fn test_calculate_threshold() {
        let core_conf = KmsCoreThresholdConf {
            parties: vec![],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };
        assert_eq!(core_conf.calculate_threshold(), 0);
        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default()],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };
        assert_eq!(core_conf.calculate_threshold(), 0);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 3],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };
        assert_eq!(core_conf.calculate_threshold(), 0);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 4],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };
        assert_eq!(core_conf.calculate_threshold(), 1);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 5],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };
        assert_eq!(core_conf.calculate_threshold(), 1);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 6],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };

        assert_eq!(core_conf.calculate_threshold(), 1);

        let core_conf = KmsCoreThresholdConf {
            parties: vec![KmsCoreParty::default(); 7],
            shares_needed: 1,
            param_choice: FheParameter::Test,
        };

        assert_eq!(core_conf.calculate_threshold(), 2);
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
                _ => FheType::Euint160,
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

    impl Arbitrary for DecryptValues {
        fn arbitrary(g: &mut Gen) -> DecryptValues {
            DecryptValues {
                version: u32::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                ciphertext: HexVector::arbitrary(g).into(),
                randomness: HexVector::arbitrary(g).into(),
            }
        }
    }

    impl Arbitrary for ReencryptValues {
        fn arbitrary(g: &mut Gen) -> ReencryptValues {
            ReencryptValues {
                signature: HexVector::arbitrary(g),
                version: u32::arbitrary(g),
                verification_key: HexVector::arbitrary(g).into(),
                randomness: HexVector::arbitrary(g).into(),
                enc_key: HexVector::arbitrary(g).into(),
                fhe_type: FheType::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                ciphertext: HexVector::arbitrary(g).into(),
                ciphertext_digest: HexVector::arbitrary(g).into(),
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
                version: u32::arbitrary(g),
                servers_needed: u32::arbitrary(g),
                verification_key: HexVector::arbitrary(g),
                digest: HexVector::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                signcrypted_ciphertext: HexVector::arbitrary(g),
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
                4 => KmsOperation::KeyGen,
                5 => KmsOperation::KeyGenResponse,
                6 => KmsOperation::CrsGen,
                _ => KmsOperation::CrsGenResponse,
            }
        }
    }

    impl Arbitrary for TransactionId {
        fn arbitrary(g: &mut Gen) -> TransactionId {
            TransactionId(HexVector::arbitrary(g))
        }
    }

    impl Arbitrary for Proof {
        fn arbitrary(g: &mut Gen) -> Proof {
            Proof(HexVector::arbitrary(g))
        }
    }

    impl Arbitrary for KmsEvent {
        fn arbitrary(g: &mut Gen) -> KmsEvent {
            KmsEvent {
                operation: KmsOperation::arbitrary(g),
                txn_id: TransactionId::arbitrary(g),
                proof: Proof::arbitrary(g),
            }
        }
    }

    #[test]
    fn test_create_kms_operation_event() {
        let operation = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(vec![1])
            .proof(vec![1, 2, 3])
            .build();

        let event: Event = operation.into();
        let attributes = event.attributes;

        assert_eq!(event.ty, KmsOperation::Decrypt.to_string());

        assert_eq!(attributes.len(), 2);
        let result = attributes.iter().find(move |a| {
            a.key == KmsEventAttributeKey::TransactionId.to_string()
                && a.value == hex::encode(vec![1])
        });
        assert!(result.is_some());

        let result = attributes.iter().find(move |a| {
            a.key == KmsEventAttributeKey::Proof.to_string() && a.value == hex::encode([1, 2, 3])
        });
        assert!(result.is_some());
    }

    #[test]
    fn test_decrypt_event_to_json() {
        let decrypt_values = DecryptValues::builder()
            .version(1)
            .key_id("mykeyid".as_bytes().to_vec())
            .fhe_type(FheType::Ebool)
            .ciphertext(vec![1, 2, 3])
            .randomness(vec![4, 5, 6])
            .build();
        let message = KmsMessage::builder()
            .proof(vec![1, 2, 3])
            .value(decrypt_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt": {
                "decrypt":{
                    "version": 1,
                    "key_id": hex::encode("mykeyid".as_bytes()),
                    "fhe_type": "ebool",
                    "ciphertext": hex::encode([1, 2, 3]),
                    "randomness": hex::encode([4, 5, 6]),
                },
                "proof": hex::encode([1, 2, 3]),
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
        let message = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .proof(vec![1, 2, 3])
            .value(decrypt_response_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt_response": {
                "decrypt_response": {
                    "signature": hex::encode([4, 5, 6]),
                    "payload": hex::encode([1, 2, 3]),
                },
                "proof": hex::encode([1, 2, 3]),
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
            .verification_key(vec![2])
            .randomness(vec![3])
            .enc_key(vec![4])
            .fhe_type(FheType::Ebool)
            .key_id("kid".as_bytes().to_vec())
            .ciphertext(vec![5])
            .ciphertext_digest(vec![8])
            .eip712_name("name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![6])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![7])
            .build();
        let message = KmsMessage::builder()
            .proof(vec![1, 2, 3])
            .value(reencrypt_values)
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt": {
                "reencrypt": {
                    "signature": hex::encode([1]),
                    "version": 1,
                    "verification_key": hex::encode(vec![2]),
                    "randomness": hex::encode(vec![3]),
                    "enc_key": hex::encode(vec![4]),
                    "fhe_type": "ebool",
                    "key_id": hex::encode("kid".as_bytes()),
                    "ciphertext": hex::encode(vec![5]),
                    "ciphertext_digest": hex::encode(vec![8]),
                    "eip712_name": "name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([6]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([7]),
                },
                "proof": hex::encode([1, 2, 3]),
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_reencrypt_response_event_to_json() {
        let reencrypt_response_values = ReencryptResponseValues::builder()
            .version(1)
            .servers_needed(2)
            .verification_key(vec![1])
            .digest(vec![2])
            .fhe_type(FheType::Ebool)
            .signcrypted_ciphertext(vec![3])
            .build();
        let message = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .proof(vec![1, 2, 3])
            .value(reencrypt_response_values)
            .build();
        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt_response": {
                "reencrypt_response": {
                    "version": 1,
                    "servers_needed": 2,
                    "verification_key": hex::encode([1]),
                    "digest": hex::encode([2]),
                    "fhe_type": "ebool",
                    "signcrypted_ciphertext": hex::encode([3]),
                },
                "proof": hex::encode([1, 2, 3]),
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_keygen_event_to_json() {
        let message = KmsMessage::builder()
            .proof(vec![1, 2, 3])
            .value(KeyGenValues::default())
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "keygen": {
                "keygen": {
                    "preproc_id": ""
                },
                "proof": hex::encode([1, 2, 3]),
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
        let message = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .proof(vec![1, 2, 3])
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
                "proof": hex::encode([1, 2, 3]),
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_crs_gen_event_to_json() {
        let message = KmsMessage::builder()
            .proof(vec![1, 2, 3])
            .value(CrsGenValues::default())
            .build();

        let json = message.to_json().unwrap();
        let json_str = serde_json::json!({
            "crs_gen": { "proof": hex::encode([1, 2, 3]) }
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

        let message = KmsMessage::builder()
            .txn_id(Some(vec![1].into()))
            .proof(vec![1, 2, 3])
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
                "proof": hex::encode([1, 2, 3]),
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
