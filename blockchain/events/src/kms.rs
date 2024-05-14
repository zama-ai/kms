use super::conversions::*;
use crate::{attrs_to_optionals, field_to_attr};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, Event};
use serde::de::Error as _;
use serde_json::Value;
use strum::EnumProperty;
use strum_macros::{Display, EnumIter, EnumString};
use typed_builder::TypedBuilder;

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct Transaction {
    pub block_height: u64,
    pub transaction_index: u32,
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
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct DecryptValues {
    version: u32,
    servers_needed: u32,
    /// key_id refers to the key that should be used for decryption
    /// created at key generation.
    #[builder(setter(into))]
    key_id: HexVector,
    fhe_type: FheType,
    #[builder(setter(into))]
    ciphertext: HexVector,
    #[builder(setter(into))]
    randomness: HexVector,
}

impl DecryptValues {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn servers_needed(&self) -> u32 {
        self.servers_needed
    }

    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn ciphertext(&self) -> &HexVector {
        &self.ciphertext
    }

    pub fn randomness(&self) -> &HexVector {
        &self.randomness
    }
}

impl From<DecryptValues> for KmsOperationAttribute {
    fn from(value: DecryptValues) -> Self {
        KmsOperationAttribute::Decrypt(value)
    }
}

impl From<DecryptValues> for Vec<Attribute> {
    fn from(value: DecryptValues) -> Self {
        vec![
            field_to_attr!(tostr; value, version),
            field_to_attr!(tostr; value, servers_needed),
            field_to_attr!(tohex; value, key_id),
            field_to_attr!(tostr; value, fhe_type),
            field_to_attr!(tohex; value, ciphertext),
            field_to_attr!(tohex; value, randomness),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for DecryptValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same;
            bytes ciphertext, randomness, key_id;
            generics version, servers_needed, fhe_type
        );
        Ok(DecryptValues {
            version,
            servers_needed,
            key_id,
            fhe_type,
            ciphertext,
            randomness,
        })
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct ReencryptValues {
    #[builder(setter(into))]
    signature: HexVector,

    // payload
    version: u32,
    servers_needed: u32,
    #[builder(setter(into))]
    verification_key: HexVector,
    #[builder(setter(into))]
    randomness: HexVector,
    #[builder(setter(into))]
    enc_key: HexVector,
    fhe_type: FheType,
    #[builder(setter(into))]
    key_id: HexVector,
    #[builder(setter(into))]
    ciphertext: HexVector,

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

    pub fn servers_needed(&self) -> u32 {
        self.servers_needed
    }

    pub fn verification_key(&self) -> &HexVector {
        &self.verification_key
    }

    pub fn randomness(&self) -> &HexVector {
        &self.randomness
    }

    pub fn enc_key(&self) -> &HexVector {
        &self.enc_key
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn key_id(&self) -> &HexVector {
        &self.key_id
    }

    pub fn ciphertext(&self) -> &HexVector {
        &self.ciphertext
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

impl From<ReencryptValues> for Vec<Attribute> {
    fn from(value: ReencryptValues) -> Self {
        vec![
            field_to_attr!(tohex; value, signature),
            field_to_attr!(tostr; value, version),
            field_to_attr!(tostr; value, servers_needed),
            field_to_attr!(tohex; value, verification_key),
            field_to_attr!(tohex; value, randomness),
            field_to_attr!(tohex; value, enc_key),
            field_to_attr!(tostr; value, fhe_type),
            field_to_attr!(tohex; value, key_id),
            field_to_attr!(tohex; value, ciphertext),
            field_to_attr!(same; value, eip712_name),
            field_to_attr!(same; value, eip712_version),
            field_to_attr!(tohex; value, eip712_chain_id),
            field_to_attr!(same; value, eip712_verifying_contract),
            field_to_attr!(tohex; value, eip712_salt),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for ReencryptValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same eip712_name, eip712_version, eip712_verifying_contract;
            bytes signature, verification_key, randomness, ciphertext, enc_key, eip712_chain_id, eip712_salt, key_id;
            generics version, servers_needed, fhe_type
        );

        Ok(ReencryptValues {
            signature,
            version,
            servers_needed,
            verification_key,
            randomness,
            enc_key,
            fhe_type,
            key_id,
            ciphertext,
            eip712_name,
            eip712_version,
            eip712_chain_id,
            eip712_verifying_contract,
            eip712_salt,
        })
    }
}

impl From<ReencryptValues> for KmsOperationAttribute {
    fn from(value: ReencryptValues) -> Self {
        KmsOperationAttribute::Reencrypt(value)
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

impl From<DecryptResponseValues> for Vec<Attribute> {
    fn from(value: DecryptResponseValues) -> Self {
        vec![
            field_to_attr!(tohex; value, signature),
            field_to_attr!(tohex; value, payload),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for DecryptResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same;
            bytes signature, payload;
            generics
        );

        Ok(DecryptResponseValues { signature, payload })
    }
}

impl From<DecryptResponseValues> for KmsOperationAttribute {
    fn from(value: DecryptResponseValues) -> Self {
        KmsOperationAttribute::DecryptResponse(value)
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct KeyGenPreprocResponseValues {
    // NOTE: there's no actual response except an "ok"
}

impl From<KeyGenPreprocResponseValues> for Vec<Attribute> {
    fn from(_value: KeyGenPreprocResponseValues) -> Self {
        vec![]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenPreprocResponseValues {
    type Error = anyhow::Error;
    fn try_from(_attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        Ok(KeyGenPreprocResponseValues {})
    }
}

impl From<KeyGenPreprocResponseValues> for KmsOperationAttribute {
    fn from(_value: KeyGenPreprocResponseValues) -> Self {
        KmsOperationAttribute::KeyGenPreprocResponse(KeyGenPreprocResponseValues {})
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct KeyGenResponseValues {
    request_id: String,
    public_key_digest: String,
    #[builder(setter(into))]
    public_key_signature: HexVector,
    // server key is bootstrap key
    server_key_digest: String,
    #[builder(setter(into))]
    server_key_signature: HexVector,
    // we do not need SnS key
}

impl From<KeyGenResponseValues> for Vec<Attribute> {
    fn from(value: KeyGenResponseValues) -> Self {
        vec![
            field_to_attr!(tostr; value, request_id),
            field_to_attr!(tostr; value, public_key_digest),
            field_to_attr!(tohex; value, public_key_signature),
            field_to_attr!(tostr; value, server_key_digest),
            field_to_attr!(tohex; value, server_key_signature),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same request_id, public_key_digest, server_key_digest;
            bytes public_key_signature, server_key_signature;
            generics
        );

        Ok(KeyGenResponseValues {
            request_id,
            public_key_digest,
            public_key_signature,
            server_key_digest,
            server_key_signature,
        })
    }
}

impl From<KeyGenResponseValues> for KmsOperationAttribute {
    fn from(value: KeyGenResponseValues) -> Self {
        KmsOperationAttribute::KeyGenResponse(value)
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

impl From<ReencryptResponseValues> for Vec<Attribute> {
    fn from(value: ReencryptResponseValues) -> Self {
        vec![
            field_to_attr!(tostr; value, version),
            field_to_attr!(tostr; value, servers_needed),
            field_to_attr!(tohex; value, verification_key),
            field_to_attr!(tohex; value, digest),
            field_to_attr!(tostr; value, fhe_type),
            field_to_attr!(tohex; value, signcrypted_ciphertext),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for ReencryptResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same;
            bytes verification_key, digest, signcrypted_ciphertext;
            generics version, servers_needed, fhe_type
        );

        Ok(ReencryptResponseValues {
            version,
            servers_needed,
            verification_key,
            digest,
            fhe_type,
            signcrypted_ciphertext,
        })
    }
}

impl From<ReencryptResponseValues> for KmsOperationAttribute {
    fn from(value: ReencryptResponseValues) -> Self {
        KmsOperationAttribute::ReencryptResponse(value)
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

impl From<CrsGenResponseValues> for Vec<Attribute> {
    fn from(value: CrsGenResponseValues) -> Self {
        vec![
            field_to_attr!(tostr; value, request_id),
            field_to_attr!(tostr; value, digest),
            field_to_attr!(tohex; value, signature),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for CrsGenResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same request_id, digest;
            bytes signature;
            generics
        );

        Ok(CrsGenResponseValues {
            request_id,
            digest,
            signature,
        })
    }
}

impl From<CrsGenResponseValues> for KmsOperationAttribute {
    fn from(value: CrsGenResponseValues) -> Self {
        KmsOperationAttribute::CrsGenResponse(value)
    }
}

#[cw_serde]
#[derive(Eq, Default)]
pub struct KeyGenPreprocValues {}

impl From<KeyGenPreprocValues> for Vec<Attribute> {
    fn from(_value: KeyGenPreprocValues) -> Self {
        vec![]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenPreprocValues {
    type Error = anyhow::Error;
    fn try_from(_attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        Ok(KeyGenPreprocValues {})
    }
}

impl From<KeyGenPreprocValues> for KmsOperationAttribute {
    fn from(_value: KeyGenPreprocValues) -> Self {
        KmsOperationAttribute::KeyGenPreproc(KeyGenPreprocValues {})
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

impl From<KeyGenValues> for Vec<Attribute> {
    fn from(value: KeyGenValues) -> Self {
        vec![field_to_attr!(tohex; value, preproc_id)]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        attrs_to_optionals!(
            attributes;
            same;
            bytes preproc_id;
            generics
        );
        Ok(KeyGenValues { preproc_id })
    }
}

impl From<KeyGenValues> for KmsOperationAttribute {
    fn from(value: KeyGenValues) -> Self {
        KmsOperationAttribute::KeyGen(value)
    }
}

#[cw_serde]
#[derive(Eq, Default)]
pub struct CrsGenValues {}

impl From<CrsGenValues> for Vec<Attribute> {
    fn from(_value: CrsGenValues) -> Self {
        vec![]
    }
}

impl TryFrom<Vec<Attribute>> for CrsGenValues {
    type Error = anyhow::Error;
    fn try_from(_attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        Ok(CrsGenValues {})
    }
}

impl From<CrsGenValues> for KmsOperationAttribute {
    fn from(_value: CrsGenValues) -> Self {
        KmsOperationAttribute::CrsGen(CrsGenValues {})
    }
}

#[cw_serde]
#[derive(Eq, EnumString, Display, EnumIter, strum_macros::EnumProperty)]
pub enum KmsOperationAttribute {
    #[strum(serialize = "decrypt", props(request = "true"))]
    Decrypt(DecryptValues),
    #[strum(serialize = "decrypt_response", props(response = "true"))]
    DecryptResponse(DecryptResponseValues),
    #[strum(serialize = "reencrypt", props(request = "true"))]
    Reencrypt(ReencryptValues),
    #[strum(serialize = "reencrypt_response", props(response = "true"))]
    ReencryptResponse(ReencryptResponseValues),
    #[strum(serialize = "keygen_preproc", props(request = "true"))]
    #[serde(rename = "keygen_preproc")]
    KeyGenPreproc(KeyGenPreprocValues),
    #[strum(serialize = "keygen_preproc_response", props(response = "true"))]
    #[serde(rename = "keygen_preproc_response")]
    KeyGenPreprocResponse(KeyGenPreprocResponseValues),
    #[strum(serialize = "keygen", props(request = "true"))]
    #[serde(rename = "keygen")]
    KeyGen(KeyGenValues),
    #[strum(serialize = "keygen_response", props(response = "true"))]
    #[serde(rename = "keygen_response")]
    KeyGenResponse(KeyGenResponseValues),
    #[strum(serialize = "crs_gen", props(request = "true"))]
    #[serde(rename = "crs_gen")]
    CrsGen(CrsGenValues),
    #[strum(serialize = "crs_gen_response", props(response = "true"))]
    CrsGenResponse(CrsGenResponseValues),
}

impl KmsOperationAttribute {
    pub fn is_request(&self) -> bool {
        self.get_str("request").unwrap_or("false") == "true"
    }

    pub fn is_response(&self) -> bool {
        self.get_str("response").unwrap_or("false") == "true"
    }
}

impl From<KmsOperationAttribute> for Vec<Attribute> {
    fn from(value: KmsOperationAttribute) -> Self {
        match value {
            KmsOperationAttribute::Decrypt(values) => {
                <DecryptValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::DecryptResponse(values) => {
                <DecryptResponseValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::Reencrypt(values) => {
                <ReencryptValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::ReencryptResponse(values) => {
                <ReencryptResponseValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::KeyGenPreproc(values) => {
                <KeyGenPreprocValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::KeyGenPreprocResponse(values) => {
                <KeyGenPreprocResponseValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::KeyGen(values) => {
                <KeyGenValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::KeyGenResponse(values) => {
                <KeyGenResponseValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::CrsGen(values) => {
                <CrsGenValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::CrsGenResponse(values) => {
                <CrsGenResponseValues as Into<Vec<Attribute>>>::into(values)
            }
        }
    }
}

#[cw_serde]
#[derive(Eq, Default)]
pub struct TransactionId(pub(crate) HexVector);

impl TransactionId {
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(TransactionId(HexVector::from_hex(hex)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone().into()
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
#[derive(Eq, TypedBuilder)]
pub struct KmsEvent {
    #[builder(setter(into))]
    pub operation: KmsOperationAttribute,
    #[builder(setter(into))]
    pub txn_id: TransactionId,
}

impl KmsEvent {
    pub fn to_json(&self) -> Result<Value, serde_json::error::Error> {
        let event_value = serde_json::to_value(self.operation.clone())?;
        let event_type = self.operation.to_string();
        let mut value = serde_json::json!({event_type.clone(): {}});
        if let Some(obj) = event_value.as_object() {
            if let Some(inner) = obj.get(event_type.as_str()) {
                if let Some(inner_obj) = inner.as_object() {
                    if !inner_obj.is_empty() {
                        value = serde_json::json!({event_type.clone(): event_value});
                    }
                }
            }
        }

        if self.operation.is_response() {
            value
                .as_object_mut()
                .ok_or(serde_json::Error::custom("Invalid operation"))?
                .get_mut(event_type.as_str())
                .ok_or(serde_json::Error::custom("Invalid operation"))?
                .as_object_mut()
                .ok_or(serde_json::Error::custom("Invalid operation"))?
                .insert(
                    "txn_id".to_string(),
                    serde_json::to_value(self.txn_id.0.clone())?,
                );
        }
        Ok(value)
    }
}

impl From<KmsEvent> for Event {
    fn from(value: KmsEvent) -> Self {
        let event_type = value.operation.to_string();
        let mut attributes = <KmsOperationAttribute as Into<Vec<Attribute>>>::into(value.operation);
        attributes.push(<TransactionId as Into<Attribute>>::into(value.txn_id));
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
        let txn_id = attributes
            .get(pos_tx_id)
            .map(|a| hex::decode(a.value.as_str()))
            .transpose()?
            .map(Into::into)
            .ok_or(anyhow::anyhow!("Missing txn_id attribute"))?;
        attributes.remove(pos_tx_id);
        let operation = match event.ty.as_str() {
            "wasm-decrypt" => {
                DecryptValues::try_from(attributes.clone()).map(KmsOperationAttribute::Decrypt)?
            }
            "wasm-decrypt_response" => DecryptResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::DecryptResponse)?,
            "wasm-reencrypt" => ReencryptValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::Reencrypt)?,
            "wasm-reencrypt_response" => ReencryptResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::ReencryptResponse)?,
            "wasm-keygen" => KmsOperationAttribute::KeyGen(KeyGenValues::default()),
            "wasm-keygen_response" => KeyGenResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::KeyGenResponse)?,
            "wasm-crs_gen" => KmsOperationAttribute::CrsGen(CrsGenValues::default()),
            "wasm-crs_gen_response" => CrsGenResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::CrsGenResponse)?,
            _ => return Err(anyhow::anyhow!("Invalid event type {:?}", event.ty)),
        };
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
                servers_needed: u32::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                ciphertext: HexVector::arbitrary(g),
                randomness: HexVector::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptValues {
        fn arbitrary(g: &mut Gen) -> ReencryptValues {
            ReencryptValues {
                signature: HexVector::arbitrary(g),
                version: u32::arbitrary(g),
                servers_needed: u32::arbitrary(g),
                verification_key: HexVector::arbitrary(g),
                randomness: HexVector::arbitrary(g),
                enc_key: HexVector::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                key_id: HexVector::arbitrary(g),
                ciphertext: HexVector::arbitrary(g),
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
                request_id: String::arbitrary(g),
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

    impl Arbitrary for KmsOperationAttribute {
        fn arbitrary(g: &mut Gen) -> KmsOperationAttribute {
            match u8::arbitrary(g) % 8 {
                0 => KmsOperationAttribute::Decrypt(DecryptValues::arbitrary(g)),
                1 => KmsOperationAttribute::DecryptResponse(DecryptResponseValues::arbitrary(g)),
                2 => KmsOperationAttribute::Reencrypt(ReencryptValues::arbitrary(g)),
                3 => {
                    KmsOperationAttribute::ReencryptResponse(ReencryptResponseValues::arbitrary(g))
                }
                4 => KmsOperationAttribute::KeyGen(KeyGenValues::default()),
                5 => KmsOperationAttribute::KeyGenResponse(KeyGenResponseValues::arbitrary(g)),
                6 => KmsOperationAttribute::CrsGen(CrsGenValues::default()),
                _ => KmsOperationAttribute::CrsGenResponse(CrsGenResponseValues::arbitrary(g)),
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
                operation: KmsOperationAttribute::arbitrary(g),
                txn_id: TransactionId::arbitrary(g),
            }
        }
    }

    #[test]
    fn test_create_kms_operation_event() {
        let decrypt_values = DecryptValues::builder()
            .version(1)
            .servers_needed(2)
            .key_id("key_id".as_bytes().to_vec())
            .fhe_type(FheType::Ebool)
            .ciphertext(vec![1, 2, 3])
            .randomness(vec![4, 5, 6])
            .build();
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(decrypt_values.clone()))
            .txn_id(vec![1])
            .build();

        let event: Event = operation.into();
        let attributes = event.attributes;

        assert_eq!(
            event.ty,
            KmsOperationAttribute::Decrypt(decrypt_values.clone()).to_string()
        );

        assert_eq!(attributes.len(), 7);
        let result = attributes.iter().find(move |a| {
            a.key == KmsEventAttributeKey::TransactionId.to_string()
                && a.value == hex::encode(vec![1])
        });
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "version" && a.value == "1");
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "servers_needed" && a.value == "2");
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "key_id" && a.value == hex::encode("key_id".as_bytes()));
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "fhe_type" && a.value == FheType::Ebool.to_string());
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "ciphertext" && a.value == hex::encode(vec![1, 2, 3]));
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "randomness" && a.value == hex::encode(vec![4, 5, 6]));
        assert!(result.is_some());
    }

    #[test]
    fn test_decrypt_event_to_json() {
        let decrypt_values = DecryptValues::builder()
            .version(1)
            .servers_needed(2)
            .key_id("mykeyid".as_bytes().to_vec())
            .fhe_type(FheType::Ebool)
            .ciphertext(vec![1, 2, 3])
            .randomness(vec![4, 5, 6])
            .build();
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(decrypt_values.clone()))
            .txn_id(vec![1])
            .build();

        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt": {
                "decrypt":{
                    "version": 1,
                    "servers_needed": 2,
                    "key_id": hex::encode("mykeyid".as_bytes()),
                    "fhe_type": "ebool",
                    "ciphertext": hex::encode([1, 2, 3]),
                    "randomness": hex::encode([4, 5, 6]),
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
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::DecryptResponse(
                decrypt_response_values.clone(),
            ))
            .txn_id(vec![1])
            .build();

        assert!(operation.operation.is_response());
        let json = operation.to_json().unwrap();
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
            .servers_needed(2)
            .verification_key(vec![2])
            .randomness(vec![3])
            .enc_key(vec![4])
            .fhe_type(FheType::Ebool)
            .key_id("kid".as_bytes().to_vec())
            .ciphertext(vec![5])
            .eip712_name("name".to_string())
            .eip712_version("version".to_string())
            .eip712_chain_id(vec![6])
            .eip712_verifying_contract("contract".to_string())
            .eip712_salt(vec![7])
            .build();
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::Reencrypt(reencrypt_values.clone()))
            .txn_id(vec![1])
            .build();

        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt": {
                "reencrypt": {
                    "signature": hex::encode([1]),
                    "version": 1,
                    "servers_needed": 2,
                    "verification_key": hex::encode(vec![2]),
                    "randomness": hex::encode(vec![3]),
                    "enc_key": hex::encode(vec![4]),
                    "fhe_type": "ebool",
                    "key_id": hex::encode("kid".as_bytes()),
                    "ciphertext": hex::encode(vec![5]),
                    "eip712_name": "name",
                    "eip712_version": "version",
                    "eip712_chain_id": hex::encode([6]),
                    "eip712_verifying_contract": "contract",
                    "eip712_salt": hex::encode([7]),
                }
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
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::ReencryptResponse(
                reencrypt_response_values.clone(),
            ))
            .txn_id(vec![1])
            .build();

        assert!(operation.operation.is_response());
        let json = operation.to_json().unwrap();
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
                "txn_id": hex::encode(vec![1])
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_keygen_event_to_json() {
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGen(KeyGenValues::default()))
            .txn_id(vec![1])
            .build();

        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "keygen": {
                "keygen": {
                    "preproc_id": ""
                },
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_keygen_response_event_to_json() {
        let keygen_response_values = KeyGenResponseValues::builder()
            .request_id("xyz".to_string())
            .public_key_digest("abc".to_string())
            .public_key_signature(vec![1, 2, 3])
            .server_key_digest("def".to_string())
            .server_key_signature(vec![4, 5, 6])
            .build();
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::KeyGenResponse(
                keygen_response_values.clone(),
            ))
            .txn_id(vec![1])
            .build();

        assert!(operation.operation.is_response());
        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "keygen_response": {
                "keygen_response": {
                    "request_id": "xyz",
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
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::CrsGen(CrsGenValues::default()))
            .txn_id(vec![1])
            .build();

        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "crs_gen": {}
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
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::CrsGenResponse(
                crs_gen_response_values.clone(),
            ))
            .txn_id(vec![1])
            .build();

        assert!(operation.operation.is_response());
        let json = operation.to_json().unwrap();
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
}
