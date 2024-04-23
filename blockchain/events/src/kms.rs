use cosmwasm_schema::cw_serde;
use cosmwasm_std::Attribute;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
pub enum KmsOperationAttributeValue {
    #[strum(serialize = "decrypt")]
    Decrypt,
    #[strum(serialize = "decrypt-response")]
    DecryptResponse,
    #[strum(serialize = "reencrypt")]
    Reencrypt,
    #[strum(serialize = "reencrypt-response")]
    ReencryptResponse,
    #[strum(serialize = "key-gen")]
    KeyGen,
    #[strum(serialize = "key-gen-response")]
    KeyGenResponse,
    #[strum(serialize = "csr-gen")]
    CsrGen,
    #[strum(serialize = "csr-gen-response")]
    CsrGenResponse,
}

#[cw_serde]
#[derive(Eq, TypedBuilder)]
pub struct EventAttribute {
    pub key: KmsEventAttributeKey,
    pub value: String,
}

impl From<EventAttribute> for Attribute {
    fn from(value: EventAttribute) -> Self {
        Attribute::new(value.key.to_string(), value.value)
    }
}

#[cw_serde]
#[derive(Eq, TypedBuilder)]
pub struct KmsOperationAttribute {
    #[builder(setter(transform = |x: KmsOperationAttributeValue| EventAttribute { key: KmsEventAttributeKey::OperationType, value: x.to_string() }))]
    pub operation: EventAttribute,
    #[builder(setter(transform = |x: Vec<u8>| EventAttribute { key: KmsEventAttributeKey::TransactionId, value: x.iter().map(|b| b.to_string()).collect::<String>()}))]
    pub txn_id: EventAttribute,
}

impl From<KmsOperationAttribute> for Vec<Attribute> {
    fn from(value: KmsOperationAttribute) -> Self {
        vec![value.operation.into(), value.txn_id.into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_kms_operation_event() {
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::Decrypt)
            .txn_id(vec![1])
            .build();

        let attributes = <KmsOperationAttribute as Into<Vec<Attribute>>>::into(operation);

        assert_eq!(attributes.len(), 2);
        assert_eq!(
            attributes[0].key,
            KmsEventAttributeKey::OperationType.to_string()
        );
        assert_eq!(
            attributes[0].value,
            KmsOperationAttributeValue::Decrypt.to_string()
        );
        assert_eq!(
            attributes[1].key,
            KmsEventAttributeKey::TransactionId.to_string()
        );
        assert_eq!(attributes[1].value, "1");
    }
}
