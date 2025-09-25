//! this is a simple wrapper around the bincode v2 API
//! that uses the legacy config to be compatible with v1 encodings
//! and that ignores the length info that v2 provides.
//! This mimics the old bincode v1 API and thus can be used as a drop-in replacement for the existing codebase.

// Setting the limit to 4GB because some tests try to deserialize a big keyset at once
// which is at least 3GB of data
pub const BINCODE_BIG_DESER_SIZE_LIMIT: usize = 1024 * 1024 * 1024 * 4;

// Setting the limit to 2GB as no network message should ever be bigger than this
// (i.e. matches the MAX_EN_DECODE_MESSAGE_SIZE constant in core/threshold)
pub const BINCODE_SMALL_DESER_SIZE_LIMIT: usize = 1024 * 1024 * 1024 * 2;

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
    bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<BINCODE_BIG_DESER_SIZE_LIMIT>(),
    )
    .map(|t| t.0)
}

pub fn deserialize_safe<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, bincode::error::DecodeError> {
    bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<BINCODE_SMALL_DESER_SIZE_LIMIT>(),
    )
    .map(|t| t.0)
}
