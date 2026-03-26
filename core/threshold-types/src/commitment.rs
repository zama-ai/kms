use serde::{Deserialize, Serialize};

/// Byte size of a typical key or opening value (currently 16 byte = 128 bit)
pub const KEY_BYTE_LEN: usize = 16;

/// Byte size of a commitment value - twice the size of the opening value (currently 32 byte = 256 bit)
pub const COMMITMENT_BYTE_LEN: usize = 2 * KEY_BYTE_LEN;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct Commitment(pub [u8; COMMITMENT_BYTE_LEN]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct Opening(pub [u8; KEY_BYTE_LEN]);
