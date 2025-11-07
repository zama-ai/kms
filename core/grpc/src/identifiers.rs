//! This module defines strongly-typed identifiers used throughout the KMS system.
//! When identifiers are passed into the KMS via gRPC, they are represented as RequestId types from
//! the kms_grpc crate (this is not the RequestId defined in this module).
//! Upon receiving such identifiers, they should be converted into the appropriate identifier types
//! defined in this module for internal use.
//!
//! Ideally the types should be present in the gRPC proto files as well, but we wish to
//! maintain compatibility with currently deployed connectors, we do not use strongly typed
//! identifiers in the gRPC interface for now.
use crate::kms::v1;
use alloy_primitives::hex;
use anyhow::{Error, Result};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use tfhe::{Unversionize, Versionize};
use tfhe_versionable::{NotVersioned, VersionizeOwned};
use threshold_fhe::{
    hashing::unsafe_hash_list_w_size,
    session_id::{SessionId, DSEP_SESSION_ID, SESSION_ID_BYTES},
};
use tracing;

/// Standard length for identifiers in bytes
pub const ID_LENGTH: usize = 32;

/// Error types for identifier operations
#[derive(Debug, thiserror::Error)]
pub enum IdentifierError {
    #[error("Invalid identifier length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid hex format in identifier: {0}")]
    InvalidHexFormat(#[from] hex::FromHexError),

    #[error("Identifier validation failure")]
    ValidationFailure,

    #[error("Cannot convert to identifier because Option is None")]
    MissingIdentifier,
}

/// KeyId represents a unique identifier for a key in the system
///
/// This type provides a strongly-typed wrapper around a fixed-size byte array
/// with consistent conversion methods to/from various representations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct KeyId([u8; ID_LENGTH]);

/// RequestId represents a unique identifier for a request in the system
///
/// This type provides a strongly-typed wrapper around a fixed-size byte array
/// with consistent conversion methods to/from various representations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct RequestId([u8; ID_LENGTH]);

/// EpochId represents a unique identifier for an epoch/PRSS.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct EpochId([u8; ID_LENGTH]);

/// ContextId represents a unique identifier for a context,
/// which is usually an operator context in the KMS,
/// defined by [crate::engine::context::ContextInfo].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct ContextId([u8; ID_LENGTH]);

/// The default is 1 in most significant byte and the rest 0.
impl Default for RequestId {
    fn default() -> Self {
        let mut res = [0; ID_LENGTH];
        res[0] = 1;
        RequestId(res)
    }
}

/// Compared the request ID as if it is an integer
impl PartialOrd for RequestId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RequestId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Common implementation for identifier types
macro_rules! impl_identifiers {
    ($request_id:ident, $key_id:ident, $context_id:ident, $epoch_id:ident) => {
        // Implement common methods for each type
        macro_rules! impl_identifier_common {
            ($type:ident) => {
                impl Versionize for $type {
                    type Versioned<'vers> = &'vers $type;

                    fn versionize(&self) -> Self::Versioned<'_> {
                        self
                    }
                }

                impl VersionizeOwned for $type {
                    type VersionedOwned = $type;
                    fn versionize_owned(self) -> Self::VersionedOwned {
                        self
                    }
                }

                impl Unversionize for $type {
                    fn unversionize(
                        versioned: Self::VersionedOwned,
                    ) -> Result<Self, tfhe_versionable::UnversionizeError> {
                        Ok(versioned)
                    }
                }

                impl NotVersioned for $type {}

                impl $type {
                    /// Creates a new identifier from raw bytes
                    pub fn from_bytes(bytes: [u8; ID_LENGTH]) -> Self {
                        Self(bytes)
                    }

                    /// Creates a new random identifier
                    pub fn new_random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
                        let mut bytes = [0u8; ID_LENGTH];
                        rng.fill_bytes(&mut bytes);
                        Self(bytes)
                    }

                    /// Returns the raw bytes of the identifier
                    pub fn as_bytes(&self) -> &[u8; ID_LENGTH] {
                        &self.0
                    }

                    /// Consumes the identifier and returns the inner byte array
                    pub fn into_bytes(self) -> [u8; ID_LENGTH] {
                        self.0
                    }

                    /// Validates that the identifier meets the required constraints
                    ///
                    /// For a RequestId or KeyId to be valid:
                    /// 1. It must not be all zeros (to prevent default/uninitialized values)
                    /// 2. It must contain only valid hexadecimal characters when represented as a string
                    /// 3. It must have the correct length when decoded from hex
                    pub fn is_valid(&self) -> bool {
                        // Check that the identifier is not all zeros
                        if self.0.iter().all(|&b| b == 0) {
                            tracing::warn!("RequestId contains all zeros");
                            return false;
                        }

                        let hex_str = self.to_string();
                        let decoded = match hex::decode(&hex_str) {
                            Ok(hex) => hex,
                            Err(e) => {
                                tracing::warn!(
                                    "Input {} is not a valid hex string: {}",
                                    &hex_str,
                                    e
                                );
                                return false;
                            }
                        };

                        if decoded.len() != ID_LENGTH {
                            tracing::warn!(
                                "Decoded value length is {}, but {} is expected",
                                decoded.len(),
                                ID_LENGTH
                            );
                            return false;
                        }

                        true
                    }

                    /// Returns the identifier as a hex string
                    pub fn as_str(&self) -> String {
                        self.to_string()
                    }

                    /// Returns a zeroed identifier
                    pub fn zeros() -> Self {
                        Self([0u8; ID_LENGTH])
                    }

                    /// Derive MPC SessionId by hashins [`self`] and the given counter
                    pub fn derive_session_id_with_counter(
                        &self,
                        ctr: u64,
                    ) -> anyhow::Result<SessionId> {
                        if !self.is_valid() {
                            anyhow::bail!("invalid request ID: {}", self);
                        }

                        // Get the raw bytes from RequestId
                        let req_id_bytes = self.as_bytes();
                        let ctr_bytes = ctr.to_le_bytes();

                        // Create a buffer to hold both the request ID and counter
                        let mut combined = Vec::with_capacity(req_id_bytes.len() + ctr_bytes.len());
                        combined.extend_from_slice(req_id_bytes);
                        combined.extend_from_slice(&ctr_bytes);

                        // Hash the combined data using unsafe_hash_list_w_size with a slice containing a reference to combined
                        let digest = unsafe_hash_list_w_size(
                            &DSEP_SESSION_ID,
                            &[&combined[..]],
                            SESSION_ID_BYTES,
                        );

                        Ok(SessionId::from(u128::from_le_bytes(
                            digest.try_into().map_err(|_| {
                                anyhow::anyhow!("Failed to convert digest to SessionId")
                            })?,
                        )))
                    }

                    /// Wrapper around [`derive_session_id_with_counter`] with counter
                    /// set to 0
                    pub fn derive_session_id(&self) -> anyhow::Result<SessionId> {
                        self.derive_session_id_with_counter(0)
                    }
                }

                // Display implementation for human-readable output (hex format without 0x prefix)
                impl fmt::Display for $type {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "{}", hex::encode(&self.0))
                    }
                }

                // FromStr implementation for parsing from string
                impl FromStr for $type {
                    type Err = IdentifierError;

                    fn from_str(s: &str) -> Result<Self, Self::Err> {
                        // Trim whitespace and remove 0x prefix if present
                        let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());

                        // Decode hex string
                        let bytes = match hex::decode(s) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!("Input {} is not a valid hex string: {}", s, e);
                                return Err(IdentifierError::InvalidHexFormat(e));
                            }
                        };

                        // Validate length
                        if bytes.len() != ID_LENGTH {
                            tracing::warn!(
                                "Decoded value length is {}, but {} is expected",
                                bytes.len(),
                                ID_LENGTH
                            );
                            return Err(IdentifierError::InvalidLength {
                                expected: ID_LENGTH,
                                actual: bytes.len(),
                            });
                        }

                        // Convert to fixed-size array
                        let mut array = [0u8; ID_LENGTH];
                        array.copy_from_slice(&bytes);

                        Ok(Self(array))
                    }
                }

                // AsRef implementation for easy access to the underlying bytes
                impl AsRef<[u8]> for $type {
                    fn as_ref(&self) -> &[u8] {
                        &self.0
                    }
                }

                // TryFrom implementation for &[u8]
                impl TryFrom<&[u8]> for $type {
                    type Error = IdentifierError;

                    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                        if bytes.len() != ID_LENGTH {
                            return Err(IdentifierError::InvalidLength {
                                expected: ID_LENGTH,
                                actual: bytes.len(),
                            });
                        }

                        let mut array = [0u8; ID_LENGTH];
                        array.copy_from_slice(bytes);
                        Ok(Self(array))
                    }
                }

                // TryFrom implementation for Vec<u8>
                impl TryFrom<Vec<u8>> for $type {
                    type Error = IdentifierError;

                    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                        Self::try_from(bytes.as_slice())
                    }
                }

                // TryFrom implementation for converting from a u128
                impl TryFrom<u128> for $type {
                    type Error = IdentifierError;

                    fn try_from(value: u128) -> Result<Self, Self::Error> {
                        let mut array = [0u8; ID_LENGTH];
                        // Fill the last 16 bytes (16-32) with the u128 value
                        array[ID_LENGTH - 16..ID_LENGTH].copy_from_slice(&value.to_be_bytes());
                        Ok(Self(array))
                    }
                }

                // TryFrom implementation for converting to u128
                impl TryFrom<$type> for u128 {
                    type Error = Error;

                    fn try_from(id: $type) -> Result<Self, Self::Error> {
                        // Use the last 16 bytes (16-32)
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&id.0[ID_LENGTH - 16..ID_LENGTH]);
                        Ok(u128::from_be_bytes(bytes))
                    }
                }

                // &str/String/&String/Option<String> conversion implementations
                impl TryFrom<&str> for $type {
                    type Error = IdentifierError;

                    fn try_from(s: &str) -> Result<Self, Self::Error> {
                        Self::from_str(s)
                    }
                }

                impl TryFrom<String> for $type {
                    type Error = IdentifierError;

                    fn try_from(s: String) -> Result<Self, Self::Error> {
                        Self::from_str(&s)
                    }
                }

                impl TryFrom<&String> for $type {
                    type Error = IdentifierError;

                    fn try_from(s: &String) -> Result<Self, Self::Error> {
                        Self::from_str(&s)
                    }
                }

                impl TryFrom<Option<String>> for $type {
                    type Error = IdentifierError;

                    fn try_from(opt: Option<String>) -> Result<Self, Self::Error> {
                        match opt {
                            Some(s) => Self::from_str(&s),
                            None => Err(IdentifierError::InvalidLength {
                                expected: ID_LENGTH,
                                actual: 0,
                            }),
                        }
                    }
                }

                // Protobuf conversions
                impl From<$type> for v1::RequestId {
                    fn from(id: $type) -> Self {
                        v1::RequestId {
                            request_id: id.to_string(),
                        }
                    }
                }

                // Additional reverse conversion implementations
                impl From<$type> for String {
                    fn from(id: $type) -> Self {
                        id.to_string()
                    }
                }

                impl<'a> From<&'a $type> for String {
                    fn from(id: &'a $type) -> Self {
                        id.to_string()
                    }
                }

                impl TryFrom<v1::RequestId> for $type {
                    type Error = IdentifierError;

                    fn try_from(proto: v1::RequestId) -> Result<Self, Self::Error> {
                        let out = Self::from_str(&proto.request_id)?;
                        if !out.is_valid() {
                            return Err(Self::Error::ValidationFailure);
                        }
                        Ok(out)
                    }
                }

                impl<'a> TryFrom<&'a v1::RequestId> for $type {
                    type Error = IdentifierError;

                    fn try_from(proto: &'a v1::RequestId) -> Result<Self, Self::Error> {
                        let out = Self::from_str(&proto.request_id)?;
                        if !out.is_valid() {
                            return Err(Self::Error::ValidationFailure);
                        }
                        Ok(out)
                    }
                }

                impl TryFrom<Option<v1::RequestId>> for $type {
                    type Error = IdentifierError;

                    fn try_from(opt: Option<v1::RequestId>) -> Result<Self, Self::Error> {
                        match opt {
                            Some(proto) => $type::try_from(proto),
                            None => Err(IdentifierError::MissingIdentifier),
                        }
                    }
                }

                impl From<$type> for tfhe::Tag {
                    fn from(value: $type) -> Self {
                        let mut tag = tfhe::Tag::default();
                        tag.set_data(value.as_bytes());
                        tag
                    }
                }

                impl From<&$type> for tfhe::Tag {
                    fn from(value: &$type) -> Self {
                        let mut tag = tfhe::Tag::default();
                        tag.set_data(value.as_bytes());
                        tag
                    }
                }
            };
        }

        // Implement common methods for all types
        impl_identifier_common!($request_id);
        impl_identifier_common!($key_id);
        impl_identifier_common!($context_id);
        impl_identifier_common!($epoch_id);

        // Implement conversions between request_id and the rest
        // Both types have the same internal representation, so we can just copy the bytes
        impl From<$request_id> for $key_id {
            fn from(other: $request_id) -> Self {
                Self(other.into_bytes())
            }
        }

        impl From<$key_id> for $request_id {
            fn from(other: $key_id) -> Self {
                Self(other.into_bytes())
            }
        }

        impl From<$request_id> for $context_id {
            fn from(other: $request_id) -> Self {
                Self(other.into_bytes())
            }
        }

        impl From<$context_id> for $request_id {
            fn from(other: $context_id) -> Self {
                Self(other.into_bytes())
            }
        }

        impl From<$request_id> for $epoch_id {
            fn from(other: $request_id) -> Self {
                Self(other.into_bytes())
            }
        }

        impl From<$epoch_id> for $request_id {
            fn from(other: $epoch_id) -> Self {
                Self(other.into_bytes())
            }
        }
    };
}

// Implement common methods for both identifier types with a single macro call
impl_identifiers!(RequestId, KeyId, ContextId, EpochId);

// Add tests
#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_request_id_random() {
        let mut rng = thread_rng();
        let id = RequestId::new_random(&mut rng);
        assert!(id.is_valid());
    }

    #[test]
    fn test_key_id_from_str() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let id = KeyId::from_str(hex_str).unwrap();
        assert_eq!(id.to_string(), hex_str);
    }

    #[test]
    fn test_invalid_id_all_zeros() {
        // Create an all-zeros ID
        let id = RequestId([0u8; ID_LENGTH]);
        assert!(!id.is_valid(), "All-zeros ID should be invalid");

        // Create a non-zero ID
        let mut bytes = [0u8; ID_LENGTH];
        bytes[0] = 1;
        let id = RequestId(bytes);
        assert!(id.is_valid(), "ID with some non-zero bytes should be valid");
    }

    #[test]
    fn test_valid_hex_characters() {
        // Create a valid ID with hex characters
        let hex_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let id = RequestId::from_str(hex_str).unwrap();
        assert!(
            id.is_valid(),
            "ID with VALID hex characters should be valid"
        );

        // Test that the from_str method rejects invalid hex characters
        let invalid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcg!$";
        let result = RequestId::from_str(invalid_hex);
        assert!(result.is_err(), "Invalid hex string should be rejected");

        // Verify the error type
        match result {
            Err(IdentifierError::InvalidHexFormat(_)) => {
                // This is the expected error type
            }
            _ => panic!("Expected InvalidHexFormat error"),
        }
    }

    #[test]
    fn test_invalid_hex_length() {
        let hex_str = "0102030405"; // Too short
        let result = RequestId::from_str(hex_str);
        assert!(result.is_err());

        if let Err(IdentifierError::InvalidLength { expected, actual }) = result {
            assert_eq!(expected, ID_LENGTH);
            assert_eq!(actual, 5);
        } else {
            panic!("Expected InvalidLength error");
        }
    }

    #[test]
    fn test_key_id_protobuf_conversion() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let id = KeyId::from_str(hex_str).unwrap();

        // Convert to protobuf
        let proto_id: v1::RequestId = id.into();
        assert_eq!(proto_id.request_id, hex_str);

        // Convert back from protobuf
        let id2 = KeyId::try_from(proto_id).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_id_type_conversions() {
        // Create a KeyId
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let key_id = KeyId::from_str(hex_str).unwrap();

        // Convert KeyId to RequestId
        let request_id: RequestId = key_id.into();

        // Verify the conversion preserved the bytes
        assert_eq!(request_id.to_string(), hex_str);

        // Create another KeyId for the reverse conversion test
        let key_id = KeyId::from_str(hex_str).unwrap();

        // Convert RequestId to KeyId
        let request_id = RequestId::from_str(hex_str).unwrap();
        let key_id2: KeyId = request_id.into();

        // Verify the conversion preserved the bytes
        assert_eq!(key_id, key_id2);
        assert_eq!(key_id2.to_string(), hex_str);

        // Test with a different value
        let hex_str2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let key_id = KeyId::from_str(hex_str2).unwrap();
        let request_id: RequestId = key_id.into();
        assert_eq!(request_id.to_string(), hex_str2);

        // Test with zeros (invalid but should still convert)
        let zeros_id = KeyId::zeros();
        let request_zeros: RequestId = zeros_id.into();
        assert!(!request_zeros.is_valid());
        assert_eq!(
            request_zeros.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_v1_request_id_conversion() {
        // Create a new RequestId
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let id = RequestId::from_str(hex_str).unwrap();

        // Convert to v1::RequestId
        let proto_id: v1::RequestId = id.into();

        // Verify the conversion preserved the value
        assert_eq!(proto_id.request_id, hex_str);

        // Convert back to RequestId
        let id2 = RequestId::try_from(proto_id).unwrap();

        // Verify the conversion preserved the value
        assert_eq!(id, id2);
        assert_eq!(id2.to_string(), hex_str);
    }

    #[test]
    fn test_v1_request_id_with_whitespace() {
        // Create a v1::RequestId with whitespace
        let proto_id = v1::RequestId {
            request_id: "  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20  "
                .to_string(),
        };

        // Convert to RequestId (which should trim whitespace)
        let id = RequestId::try_from(proto_id).unwrap();

        // Verify the conversion trimmed whitespace
        assert_eq!(
            id.to_string(),
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );

        // Convert back to v1::RequestId
        let proto_id2: v1::RequestId = id.into();

        // Verify the conversion preserved the trimmed value
        assert_eq!(
            proto_id2.request_id,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
    }

    #[test]
    fn test_v1_request_id_with_prefix() {
        // Create a v1::RequestId with 0x prefix
        let proto_id = v1::RequestId {
            request_id: "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        };

        // Convert to RequestId (which should handle the 0x prefix)
        let id = RequestId::try_from(proto_id).unwrap();

        // Verify the conversion handled the prefix
        assert_eq!(
            id.to_string(),
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );

        // Convert back to v1::RequestId
        let proto_id2: v1::RequestId = id.into();

        // Verify the conversion preserved the value without the prefix
        assert_eq!(
            proto_id2.request_id,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
    }

    #[test]
    fn test_v1_request_id_to_u128_conversion() {
        // Create a v1::RequestId
        let proto_id = v1::RequestId {
            request_id: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        };

        // Convert to RequestId
        let id = RequestId::try_from(proto_id).unwrap();

        // Convert to u128 (using the last 16 bytes)
        let value: u128 = id.try_into().unwrap();

        // Verify the conversion preserved the value
        let expected = u128::from_be_bytes([
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ]);
        assert_eq!(value, expected);
    }

    #[test]
    fn test_invalid_v1_request_id() {
        // Create an invalid v1::RequestId (too short)
        let proto_id = v1::RequestId {
            request_id: "0102030405".to_string(),
        };

        // Convert to RequestId (should fail)
        RequestId::try_from(proto_id).unwrap_err();

        // Create an invalid v1::RequestId (non-hex characters)
        let proto_id = v1::RequestId {
            request_id: "01020304050607080X0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        };

        // Convert to RequestId (should fail)
        RequestId::try_from(proto_id).unwrap_err();
    }

    #[test]
    fn request_id_ordering() {
        let base = v1::RequestId {
            request_id: "0102030405060708091011121314151617181920".to_string(),
        };
        let base_larger_1 = v1::RequestId {
            request_id: "0102030405060708091011121314151617181921".to_string(),
        };
        let base_larger_2 = v1::RequestId {
            request_id: "1102030405060708091011121314151617181920".to_string(),
        };
        let base_smaller_1 = v1::RequestId {
            request_id: "0002030405060708091011121314151617181920".to_string(),
        };
        let base_smaller_2 = v1::RequestId {
            request_id: "0102030405060708091011121314151617181919".to_string(),
        };
        assert!(base < base_larger_1);
        assert!(base < base_larger_2);
        assert!(base > base_smaller_1);
        assert!(base > base_smaller_2);
    }
}
