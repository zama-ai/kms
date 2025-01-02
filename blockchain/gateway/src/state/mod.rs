use events::kms::FheType;
use serde::{Deserialize, Serialize};

use crate::events::manager::{
    ApiReencryptValues, ApiVerifyProvenCtValues, DecryptionEvent, KmsEventWithHeight,
};

pub mod file_state;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptKmsEventState {
    pub event: KmsEventWithHeight,
    pub fhe_types: Vec<FheType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KmsEventState {
    Decrypt(DecryptKmsEventState),
    // This variant is a place holder for implementing future
    // stuff to save in state (e.g. verify and decrypt requests)
    Dummy,
}

impl KmsEventState {
    pub fn get_kms_height(&self) -> u64 {
        match &self {
            KmsEventState::Decrypt(decrypt_kms_event_state) => decrypt_kms_event_state.event.height,
            KmsEventState::Dummy => todo!(),
        }
    }
}

// State only monitor the various events (KmsEvent),
// it does not care about the full responses (OperationValue)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayEventState {
    // The event has been received
    Received,
    // The event has been received, and sent to the KMS BC.
    // This is thus a Request event
    SentToKmsBc(KmsEventState),
    // The event has been received, sent to the KMS BC, and we collected the KMS BC answer
    // This is thus a Response event
    ResultFromKmsBc(KmsEventState),
}

// Have to redefine this from GatewayEvent
// to exclude the channels in the Reencrypt and Verify events
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GatewayInnerEvent {
    Decryption(DecryptionEvent),
    Reencryption(ApiReencryptValues),
    VerifyProvenCt(ApiVerifyProvenCtValues),
}
