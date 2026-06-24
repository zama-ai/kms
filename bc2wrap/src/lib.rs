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

/// Deserialize a value from a byte slice, capped at [`BINCODE_SMALL_DESER_SIZE_LIMIT`] bytes
/// (legacy config, bincode v2 underneath; the length info is discarded).
///
/// Use this when the bytes are already in memory (e.g. a network message or a value fetched
/// from a store). To read from an I/O source without buffering it all first, use
/// [`deserialize_from`].
pub fn deserialize_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<BINCODE_SMALL_DESER_SIZE_LIMIT>(),
    )
    .map(|t| t.0)
}

/// Deserialize a value directly from a [`Read`] source, capped at
/// [`BINCODE_SMALL_DESER_SIZE_LIMIT`] bytes.
///
/// The [`std::io::Read`] is internally wrapped in a [`std::io::BufReader`], so
/// callers can pass an unbuffered source such as a [`std::fs::File`] directly.
pub fn deserialize_from<T, R>(reader: R) -> Result<T, DecodeError>
where
    T: DeserializeOwned,
    R: Read,
{
    let mut reader = std::io::BufReader::new(reader);
    bincode::serde::decode_from_std_read(
        &mut reader,
        bincode::config::legacy().with_limit::<BINCODE_SMALL_DESER_SIZE_LIMIT>(),
    )
}
