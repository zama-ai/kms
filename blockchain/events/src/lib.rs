use cosmwasm_std::{Attribute, Event};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
use typed_builder::TypedBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
pub enum EventType {
    #[strum(serialize = "kms-operation")]
    KmsOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
pub enum KmsEventAttribute {
    #[strum(serialize = "operation-type")]
    OperationType,
    #[strum(serialize = "seq-no")]
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
    pub key: KmsEventAttribute,
    pub value: String,
}

impl From<EventAttribute> for Attribute {
    fn from(value: EventAttribute) -> Self {
        Attribute::new(value.key.to_string(), value.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TypedBuilder)]
pub struct KmsOperationAttribute {
    #[builder(setter(transform = |x: KmsOperationAttributeValue| EventAttribute { key: KmsEventAttribute::OperationType, value: x.to_string() }))]
    operation: EventAttribute,
    #[builder(setter(transform = |x: u64| EventAttribute { key: KmsEventAttribute::Sequence, value: x.to_string() }))]
    seq_no: EventAttribute,
}

impl From<KmsOperationAttribute> for Vec<Attribute> {
    fn from(value: KmsOperationAttribute) -> Self {
        vec![value.operation.into(), value.seq_no.into()]
    }
}

/// Create a new KMS operation event
///
/// # Arguments
/// * `operation` - The KMS operation type and sequence number
///
/// # Example
/// ```no_run
/// use cosmwasm_std::Event;
/// use events::{KmsOperationAttribute, KmsOperationAttributeValue, KmsEventAttribute, EventType};
///
/// let operation = KmsOperationAttribute::builder()
///    .operation(KmsOperationAttributeValue::Decrypt)
///    .seq_no(1)
///    .build();
///
/// let event: Event = operation.into();
///
/// assert_eq!(event.ty, EventType::KmsOperation.to_string());
/// assert_eq!(event.attributes.len(), 2);
/// assert_eq!(event.attributes[0].key, KmsEventAttribute::OperationType.to_string());
/// assert_eq!(event.attributes[0].value, KmsOperationAttributeValue::Decrypt.to_string());
/// assert_eq!(event.attributes[1].key, KmsEventAttribute::Sequence.to_string());
/// assert_eq!(event.attributes[1].value, "1");
///
/// ```
///
///
impl From<KmsOperationAttribute> for Event {
    fn from(value: KmsOperationAttribute) -> Self {
        Event::new(EventType::KmsOperation.to_string())
            .add_attributes(<KmsOperationAttribute as Into<Vec<Attribute>>>::into(value))
    }
}

pub fn create_event<T: Into<Event>>(event: T) -> Event {
    event.into()
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

        let event: Event = operation.into();

        assert_eq!(event.ty, EventType::KmsOperation.to_string());
        assert_eq!(event.attributes.len(), 2);
        assert_eq!(
            event.attributes[0].key,
            KmsEventAttribute::OperationType.to_string()
        );
        assert_eq!(
            event.attributes[0].value,
            KmsOperationAttributeValue::Decrypt.to_string()
        );
        assert_eq!(
            event.attributes[1].key,
            KmsEventAttribute::Sequence.to_string()
        );
        assert_eq!(event.attributes[1].value, "1");
    }
}
