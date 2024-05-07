use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, Event};
use serde::de::Error as _;
use serde_json::Value;
use strum::EnumProperty;
use strum_macros::{Display, EnumIter, EnumString};
use typed_builder::TypedBuilder;

#[cw_serde]
#[derive(Default, EnumString, Eq, Display)]
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
    fhe_type: FheType,
    ciphertext: Vec<u8>,
}

impl From<DecryptValues> for Vec<Attribute> {
    fn from(value: DecryptValues) -> Self {
        let fhe_type = Attribute::new("fhe_type".to_string(), value.fhe_type.to_string());
        let ciphertext = Attribute::new("ciphertext".to_string(), hex::encode(value.ciphertext));
        vec![fhe_type, ciphertext]
    }
}

impl TryFrom<Vec<Attribute>> for DecryptValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut fhe_type = None;
        let mut ciphertext = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "fhe_type" => {
                    fhe_type = Some(attribute.value.parse().unwrap());
                }
                "ciphertext" => {
                    ciphertext = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(DecryptValues {
            fhe_type: fhe_type.unwrap(),
            ciphertext: ciphertext.unwrap(),
        })
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder, Default)]
pub struct ReencryptValues {
    fhe_type: FheType,
    ciphertext: Vec<u8>,
}

impl From<ReencryptValues> for Vec<Attribute> {
    fn from(value: ReencryptValues) -> Self {
        let fhe_type = Attribute::new("fhe_type".to_string(), value.fhe_type.to_string());
        let ciphertext = Attribute::new("ciphertext".to_string(), hex::encode(value.ciphertext));
        vec![fhe_type, ciphertext]
    }
}

impl TryFrom<Vec<Attribute>> for ReencryptValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut fhe_type = None;
        let mut ciphertext = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "fhe_type" => {
                    fhe_type = Some(attribute.value.parse().unwrap());
                }
                "ciphertext" => {
                    ciphertext = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(ReencryptValues {
            fhe_type: fhe_type.unwrap(),
            ciphertext: ciphertext.unwrap(),
        })
    }
}

#[cw_serde]
#[derive(Default, Eq, TypedBuilder)]
pub struct DecryptResponseValues {
    plaintext: Vec<u8>,
}

impl From<DecryptResponseValues> for Vec<Attribute> {
    fn from(value: DecryptResponseValues) -> Self {
        vec![Attribute::new(
            "plaintext".to_string(),
            hex::encode(value.plaintext),
        )]
    }
}

impl TryFrom<Vec<Attribute>> for DecryptResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut plaintext = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "plaintext" => {
                    plaintext = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(DecryptResponseValues {
            plaintext: plaintext.unwrap(),
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
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
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
    cyphertext: Vec<u8>,
}

impl From<ReencryptResponseValues> for Vec<Attribute> {
    fn from(value: ReencryptResponseValues) -> Self {
        vec![Attribute::new(
            "cyphertext".to_string(),
            hex::encode(value.cyphertext),
        )]
    }
}

impl TryFrom<Vec<Attribute>> for ReencryptResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut cyphertext = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "cyphertext" => {
                    cyphertext = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(ReencryptResponseValues {
            cyphertext: cyphertext.unwrap(),
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
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
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
            match attribute.key.as_str() {
                "preproc_id" => {
                    preproc_id = Some(attribute.value);
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
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
                fhe_type: FheType::arbitrary(g),
                ciphertext: Vec::<u8>::arbitrary(g),
            }
        }
    }

    impl Arbitrary for ReencryptValues {
        fn arbitrary(g: &mut Gen) -> ReencryptValues {
            ReencryptValues {
                fhe_type: FheType::arbitrary(g),
                ciphertext: Vec::<u8>::arbitrary(g),
            }
        }
    }

    impl Arbitrary for DecryptResponseValues {
        fn arbitrary(g: &mut Gen) -> DecryptResponseValues {
            DecryptResponseValues {
                plaintext: Vec::<u8>::arbitrary(g),
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
                cyphertext: Vec::<u8>::arbitrary(g),
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
            .fhe_type(FheType::Ebool)
            .ciphertext(vec![1, 2, 3])
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

        assert_eq!(attributes.len(), 3);
        let result = attributes.iter().find(move |a| {
            a.key == KmsEventAttributeKey::TransactionId.to_string()
                && a.value == hex::encode(vec![1])
        });
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "fhe_type" && a.value == FheType::Ebool.to_string());
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "ciphertext" && a.value == hex::encode(vec![1, 2, 3]));
        assert!(result.is_some());
    }

    #[test]
    fn test_decrypt_event_to_json() {
        let decrypt_values = DecryptValues::builder()
            .fhe_type(FheType::Ebool)
            .ciphertext(vec![1, 2, 3])
            .build();
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::Decrypt(decrypt_values.clone()))
            .txn_id(vec![1])
            .build();

        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "decrypt": {
                "fhe_type": "ebool",
                "ciphertext": [1, 2, 3],
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_decrypt_response_event_to_json() {
        let decrypt_response_values = DecryptResponseValues::builder()
            .plaintext(vec![1, 2, 3])
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
                "plaintext": [1, 2, 3],
                "txn_id": vec![1]
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_reencrypt_event_to_json() {
        let reencrypt_values = ReencryptValues::builder()
            .fhe_type(FheType::Ebool)
            .ciphertext(vec![1, 2, 3])
            .build();
        let operation = KmsEvent::builder()
            .operation(KmsOperationAttribute::Reencrypt(reencrypt_values.clone()))
            .txn_id(vec![1])
            .build();

        let json = operation.to_json().unwrap();
        let json_str = serde_json::json!({
            "reencrypt": {
                "fhe_type": "ebool",
                "ciphertext": [1, 2, 3],
            }
        });
        assert_eq!(json, json_str);
    }

    #[test]
    fn test_reencrypt_response_event_to_json() {
        let reencrypt_response_values = ReencryptResponseValues::builder()
            .cyphertext(vec![1, 2, 3])
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
                "cyphertext": [1, 2, 3],
                "txn_id": vec![1]
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
            "keygen": {}
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
