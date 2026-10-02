//! The user decryption result in the form non-ECDSA schemes sign it.
//!
//! A wasm client verifies user decryption results, and [`super::base`] is not compiled
//! for wasm, so this module holds the user decryption payload. The payloads of the other
//! result kinds are in `base`.

use serde::{Deserialize, Serialize};
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe_versionable::VersionsDispatch;

/// The result payload that every non-ECDSA scheme signs for a user decryption
/// result.
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum UserDecSignedPayloadVersions {
    V0(UserDecSignedPayload),
}

/// The user decryption result, in the form non-ECDSA schemes sign it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(UserDecSignedPayloadVersions)]
pub struct UserDecSignedPayload {
    pub response_bytes: Vec<u8>,
    pub extra_data: Vec<u8>,
}

impl Named for UserDecSignedPayload {
    const NAME: &'static str = "UserDecSignedPayload";
}

/// What every non-ECDSA scheme signs for a user decryption result.
pub(crate) fn user_dec_payload(response_bytes: &[u8], extra_data: &[u8]) -> UserDecSignedPayload {
    UserDecSignedPayload {
        response_bytes: response_bytes.to_vec(),
        extra_data: extra_data.to_vec(),
    }
}
