//! this is a simple wrapper around the bincode v2 API
//! that uses the legacy config to be compatible with v1 encodings
//! and that ignores the length info that v2 provides.
//! This mimics the old bincode v1 API and thus can be used as a drop-in replacement for the existing codebase.

/// wrapper around bincode::serde::encode_to_vec that uses the legacy config
/// (using bincode v2 underneath)
pub fn serialize<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

/// wrapper around bincode::serde::decode_from_slice that discards the length info and uses the legacy config
/// (using bincode v2 underneath)
pub fn deserialize<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, bincode::error::DecodeError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::legacy()).map(|t| t.0)
}
