//! this is a simple wrapper around the bincode v2 API
//! that uses the legacy config to be compatible with v1 encodings
//! and that ignores the length info that v2 provides.
//! This mimics the old bincode v1 API and thus can be used as a drop-in replacement for the existing codebase.

use bincode::error::{DecodeError, EncodeError};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};

// Setting the limit to 2GB as no network message should ever be bigger than this
// (i.e. matches the MAX_EN_DECODE_MESSAGE_SIZE constant in core/threshold-networking)
pub const BINCODE_SMALL_DESER_SIZE_LIMIT: usize = 1024 * 1024 * 1024 * 2;

/// Wrapper around bincode::serde::encode_to_vec that uses the legacy config
/// (using bincode v2 underneath)
pub fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

/// Wrapper around [`bincode::serde::encode_into_std_write`] that uses the legacy config
/// (using bincode v2 underneath)
pub fn serialize_into<T, W>(value: &T, w: &mut W) -> Result<usize, EncodeError>
where
    T: Serialize + ?Sized,
    W: Write,
{
    bincode::serde::encode_into_std_write(value, w, bincode::config::legacy())
}

/// wrapper around bincode::serde::decode_from_slice that discards the length info and uses the legacy config
/// (using bincode v2 underneath).
/// This is unsafe as it does not limit the size of the deserialized object and thus may lead to OOM errors.
pub fn deserialize_unsafe<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::legacy()).map(|t| t.0)
}

/// wrapper around bincode::serde::decode_from_slice that uses the legacy config
/// and a size limit of [`BINCODE_SMALL_DESER_SIZE_LIMIT`] bytes for safer deserialization (avoid exhausting memory errors)
pub fn deserialize_safe<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<BINCODE_SMALL_DESER_SIZE_LIMIT>(),
    )
    .map(|t| t.0)
}

pub fn deserialize_from<T, R>(mut reader: R) -> Result<T, DecodeError>
where
    T: DeserializeOwned,
    R: Read,
{
    bincode::serde::decode_from_std_read(
        &mut reader,
        bincode::config::legacy().with_limit::<BINCODE_SMALL_DESER_SIZE_LIMIT>(),
    )
}
