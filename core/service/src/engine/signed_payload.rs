//! The user decryption result in the form non-ECDSA schemes sign it, and the
//! serialization every signed result payload uses.
//!
//! A wasm client verifies user decryption results, and [`super::base`] is not compiled
//! for wasm, so this module holds the user decryption payload. The payloads of the other
//! result kinds are in `base`.

use crate::consts::SAFE_SER_SIZE_LIMIT;
use serde::{Deserialize, Serialize};
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_serialize;
use tfhe_versionable::VersionsDispatch;

/// The canonical bytes a non-ECDSA scheme signs for a public result.
///
/// Serialized with `safe_serialize`, so the type name and version are part of
/// what gets signed: changing a payload's layout later produces a new version
/// tag rather than silently making old signatures unverifiable against the new
/// reconstruction.
pub(crate) fn signed_payload_bytes<T>(payload: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize + Versionize + Named,
{
    let mut buf = Vec::new();
    safe_serialize(payload, &mut buf, SAFE_SER_SIZE_LIMIT)?;
    Ok(buf)
}

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

/// The canonical bytes a non-ECDSA scheme signs for a user decryption result.
///
/// See [`super::base::public_dec_payload_bytes`]; this is the user-decryption twin.
pub(crate) fn user_dec_payload_bytes(
    response_bytes: &[u8],
    extra_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    signed_payload_bytes(&UserDecSignedPayload {
        response_bytes: response_bytes.to_vec(),
        extra_data: extra_data.to_vec(),
    })
}
