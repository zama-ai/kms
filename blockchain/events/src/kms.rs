use cosmwasm_std::Attribute;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
use typed_builder::TypedBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
pub enum KmsEventAttributeKey {
    #[strum(serialize = "kmsoperation")]
    OperationType,
    #[strum(serialize = "seqno")]
    Sequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
pub enum KmsOperationAttributeValue {
    #[strum(serialize = "decrypt")]
    Decrypt,
    #[strum(serialize = "reencrypt")]
    Reencrypt,
    #[strum(serialize = "key-gen")]
    KeyGen,
    #[strum(serialize = "csr-gen")]
    CsrGen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TypedBuilder)]
pub struct EventAttribute {
    pub key: KmsEventAttributeKey,
    pub value: String,
}

impl From<EventAttribute> for Attribute {
    fn from(value: EventAttribute) -> Self {
        Attribute::new(value.key.to_string(), value.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TypedBuilder)]
pub struct KmsOperationAttribute {
    #[builder(setter(transform = |x: KmsOperationAttributeValue| EventAttribute { key: KmsEventAttributeKey::OperationType, value: x.to_string() }))]
    operation: EventAttribute,
    #[builder(setter(transform = |x: u64| EventAttribute { key: KmsEventAttributeKey::Sequence, value: x.to_string() }))]
    seq_no: EventAttribute,
}

impl From<KmsOperationAttribute> for Vec<Attribute> {
    fn from(value: KmsOperationAttribute) -> Self {
        vec![value.operation.into(), value.seq_no.into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_kms_operation_event() {
        let operation = KmsOperationAttribute::builder()
            .operation(KmsOperationAttributeValue::Decrypt)
            .seq_no(1)
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
            KmsEventAttributeKey::Sequence.to_string()
        );
        assert_eq!(attributes[1].value, "1");
    }
}
