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

macro_rules! field_to_attr {
    (tohex; $value:expr, $name:ident) => {
        Attribute::new(stringify!($name).to_string(), hex::encode($value.$name))
    };
    (tostr; $value:expr, $name:ident) => {
        Attribute::new(stringify!($name).to_string(), $value.$name.to_string())
    };
    (same; $value:expr, $name:ident) => {
        Attribute::new(stringify!($name).to_string(), $value.$name)
    };
}

macro_rules! attrs_to_optionals {
    ($attributes:expr; same $($str_name:ident),*;
        bytes $($byte_name:ident),*;
        generics $($generic_name:ident),*) => {

        $(
            let mut $str_name = None;
        )*
        $(
            let mut $byte_name = None;
        )*
        $(
            let mut $generic_name = None;
        )*
        for attribute in $attributes {
            match attribute.key.as_str() {
                $(
                    stringify!($str_name) => {
                        $str_name = Some(attribute.value)
                    }
                )*
                $(
                    stringify!($byte_name) => {
                        $byte_name = Some(hex::decode(attribute.value).unwrap())
                    }
                )*
                $(
                    stringify!($generic_name) => {
                        $generic_name = Some(attribute.value.parse().unwrap())
                    }
                )*
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
    };
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct DecryptValues {
    version: u32,
    servers_needed: u32,
    /// key_id refers to the key that should be used for decryption
    /// created at key generation.
    key_id: String,
    fhe_type: FheType,
    ciphertext: Vec<u8>,
    randomness: Vec<u8>,
}

impl DecryptValues {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn servers_needed(&self) -> u32 {
        self.servers_needed
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn randomness(&self) -> &[u8] {
        &self.randomness
    }
}

impl From<DecryptValues> for Vec<Attribute> {
    fn from(value: DecryptValues) -> Self {
        vec![
            field_to_attr!(tostr; value, version),
            field_to_attr!(tostr; value, servers_needed),
            field_to_attr!(same; value, key_id),
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
            same key_id;
            bytes ciphertext, randomness;
            generics version, servers_needed, fhe_type
        );
        Ok(DecryptValues {
            version: version.unwrap(),
            servers_needed: servers_needed.unwrap(),
            key_id: key_id.unwrap(),
            fhe_type: fhe_type.unwrap(),
            ciphertext: ciphertext.unwrap(),
            randomness: randomness.unwrap(),
        })
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct ReencryptValues {
    signature: Vec<u8>,

    // payload
    version: u32,
    servers_needed: u32,
    verification_key: Vec<u8>,
    randomness: Vec<u8>,
    enc_key: Vec<u8>,
    fhe_type: FheType,
    key_id: String,
    ciphertext: Vec<u8>,

    // eip712
    eip712_name: String,
    eip712_version: String,
    eip712_chain_id: Vec<u8>,
    eip712_verifying_contract: String,
    eip712_salt: Vec<u8>,
}

impl ReencryptValues {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn servers_needed(&self) -> u32 {
        self.servers_needed
    }

    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    pub fn randomness(&self) -> &[u8] {
        &self.randomness
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn eip712_name(&self) -> &str {
        &self.eip712_name
    }

    pub fn eip712_version(&self) -> &str {
        &self.eip712_version
    }

    pub fn eip712_chain_id(&self) -> &[u8] {
        &self.eip712_chain_id
    }

    pub fn eip712_verifying_contract(&self) -> &str {
        &self.eip712_verifying_contract
    }

    pub fn eip712_salt(&self) -> &[u8] {
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
            field_to_attr!(same; value, key_id),
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
            same key_id, eip712_name, eip712_version, eip712_verifying_contract;
            bytes signature, verification_key, randomness, ciphertext, enc_key, eip712_chain_id, eip712_salt;
            generics version, servers_needed, fhe_type
        );

        Ok(ReencryptValues {
            signature: signature.unwrap(),
            version: version.unwrap(),
            servers_needed: servers_needed.unwrap(),
            verification_key: verification_key.unwrap(),
            randomness: randomness.unwrap(),
            enc_key: enc_key.unwrap(),
            fhe_type: fhe_type.unwrap(),
            key_id: key_id.unwrap(),
            ciphertext: ciphertext.unwrap(),
            eip712_name: eip712_name.unwrap(),
            eip712_version: eip712_version.unwrap(),
            eip712_chain_id: eip712_chain_id.unwrap(),
            eip712_verifying_contract: eip712_verifying_contract.unwrap(),
            eip712_salt: eip712_salt.unwrap(),
        })
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct DecryptResponseValues {
    signature: Vec<u8>,
    /// This is the response payload,
    /// we keep it in the serialized form because
    /// we need to use it to verify the signature.
    payload: Vec<u8>,
}

impl DecryptResponseValues {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl From<DecryptResponseValues> for Vec<Attribute> {
    fn from(value: DecryptResponseValues) -> Self {
        vec![
            Attribute::new("signature".to_string(), hex::encode(value.signature)),
            Attribute::new("payload".to_string(), hex::encode(value.payload)),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for DecryptResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut signature = None;
        let mut payload = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "signature" => {
                    signature = Some(hex::decode(attribute.value).unwrap());
                }
                "payload" => {
                    payload = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(DecryptResponseValues {
            signature: signature.unwrap(),
            payload: payload.unwrap(),
        })
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

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct KeyGenResponseValues {
    request_id: String,
    public_key_digest: String,
    public_key_signature: Vec<u8>,
    // server key is bootstrap key
    server_key_digest: String,
    server_key_signature: Vec<u8>,
    // we do not need SnS key
}

impl From<KeyGenResponseValues> for Vec<Attribute> {
    fn from(value: KeyGenResponseValues) -> Self {
        vec![
            Attribute::new("request_id".to_string(), value.request_id),
            Attribute::new("public_key_digest".to_string(), value.public_key_digest),
            Attribute::new(
                "public_key_signature".to_string(),
                hex::encode(value.public_key_signature),
            ),
            Attribute::new("server_key_digest".to_string(), value.server_key_digest),
            Attribute::new(
                "server_key_signature".to_string(),
                hex::encode(value.server_key_signature),
            ),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut request_id = None;
        let mut public_key_digest = None;
        let mut public_key_signature = None;
        let mut server_key_digest = None;
        let mut server_key_signature = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "request_id" => {
                    request_id = Some(attribute.value);
                }
                "public_key_digest" => {
                    public_key_digest = Some(attribute.value);
                }
                "public_key_signature" => {
                    public_key_signature = Some(hex::decode(attribute.value).unwrap());
                }
                "server_key_digest" => {
                    server_key_digest = Some(attribute.value);
                }
                "server_key_signature" => {
                    server_key_signature = Some(hex::decode(attribute.value).unwrap());
                }
                _ => (),
            }
        }
        Ok(KeyGenResponseValues {
            request_id: request_id.unwrap(),
            public_key_digest: public_key_digest.unwrap(),
            public_key_signature: public_key_signature.unwrap(),
            server_key_digest: server_key_digest.unwrap(),
            server_key_signature: server_key_signature.unwrap(),
        })
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct ReencryptResponseValues {
    version: u32,
    servers_needed: u32,
    verification_key: Vec<u8>,
    digest: Vec<u8>,
    fhe_type: FheType,
    signcrypted_ciphertext: Vec<u8>,
}

impl ReencryptResponseValues {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn servers_needed(&self) -> u32 {
        self.servers_needed
    }

    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    pub fn signcrypted_ciphertext(&self) -> &[u8] {
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
            version: version.unwrap(),
            servers_needed: servers_needed.unwrap(),
            verification_key: verification_key.unwrap(),
            digest: digest.unwrap(),
            fhe_type: fhe_type.unwrap(),
            signcrypted_ciphertext: signcrypted_ciphertext.unwrap(),
        })
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
    signature: Vec<u8>,
}

impl CrsGenResponseValues {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl From<CrsGenResponseValues> for Vec<Attribute> {
    fn from(value: CrsGenResponseValues) -> Self {
        vec![
            Attribute::new("request_id".to_string(), value.request_id),
            Attribute::new("digest".to_string(), value.digest),
            Attribute::new("signature".to_string(), hex::encode(value.signature)),
        ]
    }
}

impl TryFrom<Vec<Attribute>> for CrsGenResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut request_id = None;
        let mut digest = None;
        let mut signature = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "request_id" => {
                    request_id = Some(attribute.value);
                }
                "digest" => {
                    digest = Some(attribute.value);
                }
                "signature" => signature = Some(hex::decode(attribute.value).unwrap()),
                _ => (),
            }
        }
        Ok(CrsGenResponseValues {
            request_id: request_id.unwrap(),
            digest: digest.unwrap(),
            signature: signature.unwrap(),
        })
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

#[cw_serde]
#[derive(Eq, Default, TypedBuilder)]
pub struct KeyGenValues {
    /// Hex-encoded preprocessing ID.
    /// This ID refers to the request ID of a preprocessing request.
    preproc_id: String,
}

impl KeyGenValues {
    pub fn preproc_id(&self) -> &str {
        &self.preproc_id
    }
}

impl From<KeyGenValues> for Vec<Attribute> {
    fn from(value: KeyGenValues) -> Self {
        vec![Attribute::new("preproc_id".to_string(), value.preproc_id)]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut preproc_id = None;
        for attribute in attributes {
            if let "preproc_id" = attribute.key.as_str() {
                preproc_id = Some(attribute.value);
            }
        }
        Ok(KeyGenValues {
            preproc_id: preproc_id.unwrap(),
        })
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
pub struct TransactionId(Vec<u8>);

impl TransactionId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.clone())
    }
}

impl From<Vec<u8>> for TransactionId {
    fn from(value: Vec<u8>) -> Self {
        TransactionId(value)
    }
}

impl From<TransactionId> for Attribute {
    fn from(value: TransactionId) -> Self {
        Attribute::new(
            KmsEventAttributeKey::TransactionId.to_string(),
            hex::encode(value.0),
        )
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder)]
pub struct KmsEvent {
    pub operation: KmsOperationAttribute,
    #[builder(setter(into))]
    pub txn_id: TransactionId,
}

impl KmsEvent {
    pub fn to_json(&self) -> Result<Value, serde_json::error::Error> {
        let mut object = serde_json::to_value(self.operation.clone())?;
        if self.operation.is_response() {
            object
                .as_object_mut()
                .ok_or(serde_json::Error::custom("Invalid operation"))?
                .get_mut(self.operation.to_string().as_str())
                .ok_or(serde_json::Error::custom("Invalid operation"))?
                .as_object_mut()
                .ok_or(serde_json::Error::custom("Invalid operation"))?
                .insert(
                    "txn_id".to_string(),
                    serde_json::to_value(self.txn_id.0.clone())?,
                );
        }
        Ok(object)
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
            .map(TransactionId)
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

    impl Arbitrary for DecryptValues {
        fn arbitrary(g: &mut Gen) -> DecryptValues {
            DecryptValues {
                version: u32::arbitrary(g),
                servers_needed: u32::arbitrary(g),
                key_id: String::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                ciphertext: Vec::<u8>::arbitrary(g),
                randomness: Vec::<u8>::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptValues {
        fn arbitrary(g: &mut Gen) -> ReencryptValues {
            ReencryptValues {
                signature: Vec::<u8>::arbitrary(g),
                version: u32::arbitrary(g),
                servers_needed: u32::arbitrary(g),
                verification_key: Vec::<u8>::arbitrary(g),
                randomness: Vec::<u8>::arbitrary(g),
                enc_key: Vec::<u8>::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                key_id: String::arbitrary(g),
                ciphertext: Vec::<u8>::arbitrary(g),
                eip712_name: String::arbitrary(g),
                eip712_version: String::arbitrary(g),
                eip712_chain_id: Vec::<u8>::arbitrary(g),
                eip712_verifying_contract: String::arbitrary(g),
                eip712_salt: Vec::<u8>::arbitrary(g),
            }
        }
    }

    impl Arbitrary for DecryptResponseValues {
        fn arbitrary(g: &mut Gen) -> DecryptResponseValues {
            DecryptResponseValues {
                signature: Vec::<u8>::arbitrary(g),
                payload: Vec::<u8>::arbitrary(g),
            }
        }
    }

    impl Arbitrary for KeyGenResponseValues {
        fn arbitrary(g: &mut Gen) -> KeyGenResponseValues {
            KeyGenResponseValues {
                request_id: String::arbitrary(g),
                public_key_digest: String::arbitrary(g),
                public_key_signature: Vec::<u8>::arbitrary(g),
                server_key_digest: String::arbitrary(g),
                server_key_signature: Vec::<u8>::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptResponseValues {
        fn arbitrary(g: &mut Gen) -> ReencryptResponseValues {
            ReencryptResponseValues {
                version: u32::arbitrary(g),
                servers_needed: u32::arbitrary(g),
                verification_key: Vec::<u8>::arbitrary(g),
                digest: Vec::<u8>::arbitrary(g),
                fhe_type: FheType::arbitrary(g),
                signcrypted_ciphertext: Vec::<u8>::arbitrary(g),
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
                signature: Vec::<u8>::arbitrary(g),
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
            TransactionId(Vec::<u8>::arbitrary(g))
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
            .key_id("key_id".to_string())
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
            .find(move |a| a.key == "key_id" && a.value == "key_id");
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
            .key_id("mykeyid".to_string())
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
                "version": 1,
                "servers_needed": 2,
                "key_id": "mykeyid",
                "fhe_type": "ebool",
                "ciphertext": [1, 2, 3],
                "randomness": [4, 5, 6],
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
                "signature": [4, 5, 6],
                "payload": [1, 2, 3],
                "txn_id": vec![1]
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
            .key_id("kid".to_string())
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
                "signature": vec![1],
                "version": 1,
                "servers_needed": 2,
                "verification_key": vec![2],
                "randomness": vec![3],
                "enc_key": vec![4],
                "fhe_type": "ebool",
                "key_id": "kid",
                "ciphertext": vec![5],
                "eip712_name": "name",
                "eip712_version": "version",
                "eip712_chain_id": vec![6],
                "eip712_verifying_contract": "contract",
                "eip712_salt": vec![7],
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
                "version": 1,
                "servers_needed": 2,
                "verification_key": vec![1],
                "digest": vec![2],
                "fhe_type": "ebool",
                "signcrypted_ciphertext": vec![3],
                "txn_id": vec![1],
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
            "keygen": { "preproc_id": ""}
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
                "request_id": "xyz",
                "public_key_digest": "abc",
                "public_key_signature": [1, 2, 3],
                "server_key_digest": "def",
                "server_key_signature": [4, 5, 6],
                "txn_id": vec![1]
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
                "request_id": "abcdef".to_string(),
                "digest": "123456".to_string(),
                "signature": vec![1, 2, 3],
                "txn_id": vec![1]
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
