//! Solidity types used in EIP-712 signing and verification.
//! WARNING: any changes to these structures is a breaking change.

use alloy_primitives::U256;

use crate::RequestId;

alloy_sol_types::sol! {
    struct UserDecryptResponseVerification {
        bytes publicKey;
        bytes32[] ctHandles;
        bytes userDecryptedShare;
        bytes extraData;
    }
}

// This is used internally to link a request and a response.
alloy_sol_types::sol! {
    struct UserDecryptionLinker {
        bytes publicKey;
        bytes32[] handles;
        address userAddress;
    }
}

// Solidity struct for decryption result signature
// Struct needs to match what is in
// https://github.com/zama-ai/gateway-l2/blob/main/contracts/DecryptionManager.sol#L18
// and the name must be what is defined under `EIP712_PUBLIC_DECRYPT_TYPE`
alloy_sol_types::sol! {
    struct PublicDecryptVerification {
        bytes32[] ctHandles;
        bytes decryptedResult;
        bytes extraData;
    }
}
#[allow(dead_code)]
// Ensure PublicDecryptVerification implements Debug for test assertions
impl std::fmt::Debug for PublicDecryptVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicDecryptVerification")
            .field("ctHandles", &self.ctHandles)
            .field("decryptedResult", &self.decryptedResult)
            .field("extraData", &self.extraData)
            .finish()
    }
}

alloy_sol_types::sol! {
    struct CrsgenVerification {
        /// @notice The ID of the generated CRS.
        uint256 crsId;
        /// @notice The max bit length of the generated CRS.
        uint256 maxBitLength;
        /// @notice The digest of the generated CRS.
        bytes crsDigest;
    }
}

impl CrsgenVerification {
    pub fn new(crs_id: &RequestId, max_bit_length: usize, crs_digest: Vec<u8>) -> Self {
        Self {
            crsId: U256::from_be_slice(crs_id.as_bytes()),
            maxBitLength: U256::from_be_slice(&max_bit_length.to_be_bytes()),
            crsDigest: crs_digest.into(),
        }
    }
}

alloy_sol_types::sol! {
    struct PrepKeygenVerification {
        /// @notice The ID of the preprocessing keygen step.
        uint256 prepKeygenId;
    }
}

impl PrepKeygenVerification {
    pub fn new(preproc_id: &RequestId) -> Self {
        Self {
            prepKeygenId: U256::from_be_slice(preproc_id.as_bytes()),
        }
    }
}

alloy_sol_types::sol! {
    enum KeyType {
        SERVER,
        PUBLIC,
        COMPRESSED_PUBLIC,
        COMPRESSED_KEYSET,
    }

    struct KeyDigest {
        /// @notice The type of the generated key.
        KeyType keyType;
        /// @notice The digest of the generated key.
        bytes digest;
    }

    struct KeygenVerification {
        /// @notice The ID of the preprocessing keygen request.
        uint256 prepKeygenId;
        /// @notice The ID of the generated key.
        uint256 keyId;
        /// @notice The generated digests of keys.
        KeyDigest[] keyDigests;
    }
}

impl KeygenVerification {
    pub fn new_standard(
        preproc_id: &RequestId,
        key_id: &RequestId,
        server_key_digest: Vec<u8>,
        public_key_digest: Vec<u8>,
    ) -> Self {
        Self {
            prepKeygenId: U256::from_be_slice(preproc_id.as_bytes()),
            keyId: U256::from_be_slice(key_id.as_bytes()),
            // NOTE: order should be in the order of the enum KeyType
            keyDigests: vec![
                KeyDigest {
                    keyType: KeyType::SERVER,
                    digest: server_key_digest.into(),
                },
                KeyDigest {
                    keyType: KeyType::PUBLIC,
                    digest: public_key_digest.into(),
                },
            ],
        }
    }
    pub fn new_compressed(
        preproc_id: &RequestId,
        key_id: &RequestId,
        compressed_keyset_digest: Vec<u8>,
        compressed_pk_digest: Vec<u8>,
    ) -> Self {
        Self {
            prepKeygenId: U256::from_be_slice(preproc_id.as_bytes()),
            keyId: U256::from_be_slice(key_id.as_bytes()),
            // NOTE: order should be in the order of the enum KeyType
            keyDigests: vec![
                KeyDigest {
                    keyType: KeyType::COMPRESSED_KEYSET,
                    digest: compressed_keyset_digest.into(),
                },
                KeyDigest {
                    keyType: KeyType::COMPRESSED_PUBLIC,
                    digest: compressed_pk_digest.into(),
                },
            ],
        }
    }
}

// Solidity struct for DecompressionUpgradeKey
// TODO(zama-ai/kms-internal#2714) this is a placeholder since gateway does not support this yet.
alloy_sol_types::sol! {
    struct FheDecompressionUpgradeKey {
        bytes decompressionUpgradeKeyDigest;
    }
}
