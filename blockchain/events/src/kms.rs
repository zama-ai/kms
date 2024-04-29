use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, Event};
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
    #[strum(serialize = "txnid")]
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
        let fhe_type = Attribute::new("fhetype".to_string(), value.fhe_type.to_string());
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
                "fhetype" => {
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
        let fhe_type = Attribute::new("fhetype".to_string(), value.fhe_type.to_string());
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
                "fhetype" => {
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
pub struct KeyGenResponseValues {
    key: Vec<u8>,
}

impl From<KeyGenResponseValues> for Vec<Attribute> {
    fn from(value: KeyGenResponseValues) -> Self {
        vec![Attribute::new("key".to_string(), hex::encode(value.key))]
    }
}

impl TryFrom<Vec<Attribute>> for KeyGenResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut key = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "key" => {
                    key = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(KeyGenResponseValues { key: key.unwrap() })
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
pub struct CsrGenResponseValues {
    csr: Vec<u8>,
}

impl From<CsrGenResponseValues> for Vec<Attribute> {
    fn from(value: CsrGenResponseValues) -> Self {
        vec![Attribute::new("csr".to_string(), hex::encode(value.csr))]
    }
}

impl TryFrom<Vec<Attribute>> for CsrGenResponseValues {
    type Error = anyhow::Error;
    fn try_from(attributes: Vec<Attribute>) -> Result<Self, Self::Error> {
        let mut csr = None;
        for attribute in attributes {
            match attribute.key.as_str() {
                "csr" => {
                    csr = Some(hex::decode(attribute.value).unwrap());
                }
                _ => return Err(anyhow::anyhow!("Invalid attribute key {:?}", attribute.key)),
            }
        }
        Ok(CsrGenResponseValues { csr: csr.unwrap() })
    }
}

#[cw_serde]
#[derive(Eq, EnumString, Display, EnumIter, strum_macros::EnumProperty)]
pub enum KmsOperationAttribute {
    #[strum(serialize = "decrypt", props(request = "true"))]
    Decrypt(DecryptValues),
    #[strum(serialize = "decrypt-response", props(response = "true"))]
    DecryptResponse(DecryptResponseValues),
    #[strum(serialize = "reencrypt", props(request = "true"))]
    Reencrypt(ReencryptValues),
    #[strum(serialize = "reencrypt-response", props(response = "true"))]
    ReencryptResponse(ReencryptResponseValues),
    #[strum(serialize = "key-gen", props(request = "true"))]
    KeyGen,
    #[strum(serialize = "key-gen-response", props(response = "true"))]
    KeyGenResponse(KeyGenResponseValues),
    #[strum(serialize = "csr-gen", props(request = "true"))]
    CsrGen,
    #[strum(serialize = "csr-gen-response", props(response = "true"))]
    CsrGenResponse(CsrGenResponseValues),
}

impl KmsOperationAttribute {
    pub fn is_request(&self) -> bool {
        self.get_bool("request").unwrap_or(false)
    }

    pub fn is_response(&self) -> bool {
        self.get_bool("response").unwrap_or(false)
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
            KmsOperationAttribute::KeyGen => vec![],
            KmsOperationAttribute::KeyGenResponse(values) => {
                <KeyGenResponseValues as Into<Vec<Attribute>>>::into(values)
            }
            KmsOperationAttribute::CsrGen => vec![],
            KmsOperationAttribute::CsrGenResponse(values) => {
                <CsrGenResponseValues as Into<Vec<Attribute>>>::into(values)
            }
        }
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder)]
pub struct KmsEvent {
    pub operation: KmsOperationAttribute,
    #[builder(setter(transform = |x: Vec<u8>|  x.iter().map(|b| b.to_string()).collect::<String>()))]
    pub txn_id: String,
}

impl From<KmsEvent> for Event {
    fn from(value: KmsEvent) -> Self {
        let event_type = value.operation.to_string();
        let mut attributes = <KmsOperationAttribute as Into<Vec<Attribute>>>::into(value.operation);
        attributes.push(Attribute::new(
            KmsEventAttributeKey::TransactionId.to_string(),
            value.txn_id,
        ));
        Event::new(event_type).add_attributes(attributes)
    }
}

impl TryFrom<Event> for KmsEvent {
    type Error = anyhow::Error;
    fn try_from(event: Event) -> Result<Self, Self::Error> {
        let mut attributes = event.attributes;
        let pos_tx_id = attributes
            .iter()
            .position(|a| a.key == "txnid")
            .ok_or(anyhow::anyhow!("Missing txnid attribute"))?;
        let txn_id = attributes
            .get(pos_tx_id)
            .map(|a| a.value.clone())
            .ok_or(anyhow::anyhow!("Missing txnid attribute"))?;
        attributes.remove(pos_tx_id);
        let operation = match event.ty.as_str() {
            "wasm-decrypt" => {
                DecryptValues::try_from(attributes.clone()).map(KmsOperationAttribute::Decrypt)?
            }
            "wasm-decrypt-response" => DecryptResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::DecryptResponse)?,
            "wasm-reencrypt" => ReencryptValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::Reencrypt)?,
            "wasm-reencrypt-response" => ReencryptResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::ReencryptResponse)?,
            "wasm-key-gen" => KmsOperationAttribute::KeyGen,
            "wasm-key-gen-response" => KeyGenResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::KeyGenResponse)?,
            "wasm-csr-gen" => KmsOperationAttribute::CsrGen,
            "wasm-csr-gen-response" => CsrGenResponseValues::try_from(attributes.clone())
                .map(KmsOperationAttribute::CsrGenResponse)?,
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
                key: Vec::<u8>::arbitrary(g),
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

    impl Arbitrary for CsrGenResponseValues {
        fn arbitrary(g: &mut Gen) -> CsrGenResponseValues {
            CsrGenResponseValues {
                csr: Vec::<u8>::arbitrary(g),
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
                4 => KmsOperationAttribute::KeyGen,
                5 => KmsOperationAttribute::KeyGenResponse(KeyGenResponseValues::arbitrary(g)),
                6 => KmsOperationAttribute::CsrGen,
                _ => KmsOperationAttribute::CsrGenResponse(CsrGenResponseValues::arbitrary(g)),
            }
        }
    }

    impl Arbitrary for KmsEvent {
        fn arbitrary(g: &mut Gen) -> KmsEvent {
            KmsEvent {
                operation: KmsOperationAttribute::arbitrary(g),
                txn_id: Vec::<u8>::arbitrary(g)
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<String>(),
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
            a.key == KmsEventAttributeKey::TransactionId.to_string() && a.value == "1"
        });
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "fhetype" && a.value == FheType::Ebool.to_string());
        assert!(result.is_some());
        let result = attributes
            .iter()
            .find(move |a| a.key == "ciphertext" && a.value == hex::encode(vec![1, 2, 3]));
        assert!(result.is_some());
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
