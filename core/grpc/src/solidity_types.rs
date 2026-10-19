//! Solidity types used in EIP-712 signing and verification.
//! WARNING: any changes to these structures is a breaking change.

use alloy_primitives::{B256, U256};

use crate::{ContextId, RequestId};

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
        /// @notice Extra data for client-specific context.
        bytes extraData;
    }
}

impl CrsgenVerification {
    pub fn new(
        crs_id: &RequestId,
        max_bit_length: usize,
        crs_digest: Vec<u8>,
        extra_data: Vec<u8>,
    ) -> Self {
        Self {
            crsId: U256::from_be_slice(crs_id.as_bytes()),
            maxBitLength: U256::from_be_slice(&max_bit_length.to_be_bytes()),
            crsDigest: crs_digest.into(),
            extraData: extra_data.into(),
        }
    }
}

alloy_sol_types::sol! {
    struct PrepKeygenVerification {
        /// @notice The ID of the preprocessing keygen step.
        uint256 prepKeygenId;
        /// @notice Extra data for client-specific context.
        bytes extraData;
    }
}

impl PrepKeygenVerification {
    pub fn new(preproc_id: &RequestId, extra_data: Vec<u8>) -> Self {
        Self {
            prepKeygenId: U256::from_be_slice(preproc_id.as_bytes()),
            extraData: extra_data.into(),
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
        /// @notice Extra data for client-specific context.
        bytes extraData;
    }
}

// Struct needs to match `ContextCreationConfirmation` in the canonical
// ProtocolConfig contract.
alloy_sol_types::sol! {
    struct ContextCreationConfirmation {
        /// @notice The ID of the context that was active when the new context was defined.
        uint256 previousContextId;
        /// @notice The ID of the new context.
        uint256 newContextId;
        /// @notice keccak256(abi.encode(KmsNode[] nodes, KmsThresholds thresholds)) of the new context.
        bytes32 nodeConfigHash;
        /// @notice Extra data for client-specific context.
        bytes extraData;
    }
}

impl ContextCreationConfirmation {
    pub fn new(
        previous_context_id: &ContextId,
        new_context_id: &ContextId,
        node_config_hash: B256,
        extra_data: Vec<u8>,
    ) -> Self {
        Self {
            previousContextId: U256::from_be_slice(previous_context_id.as_bytes()),
            newContextId: U256::from_be_slice(new_context_id.as_bytes()),
            nodeConfigHash: node_config_hash,
            extraData: extra_data.into(),
        }
    }
}

/// Version 13.20 (Q2 2026) layouts of the Solidity structs grew an
/// `extraData` field. The Q1 26 versions below reflect the old version,
/// kept available so the backward-compatibility harness
/// can reproduce signatures that were generated before that change.
///
/// The Solidity struct names inside this module MUST hence NOT be changed!
mod legacy_q126 {
    alloy_sol_types::sol! {
        enum KeyType {
            SERVER,
            PUBLIC,
            COMPRESSED_PUBLIC,
            COMPRESSED_KEYSET,
        }

        struct KeyDigest {
            KeyType keyType;
            bytes digest;
        }

        struct KeygenVerification {
            uint256 prepKeygenId;
            uint256 keyId;
            KeyDigest[] keyDigests;
        }

        struct CrsgenVerification {
            uint256 crsId;
            uint256 maxBitLength;
            bytes crsDigest;
        }
    }
}

pub use legacy_q126::CrsgenVerification as CrsgenVerificationQ126;
pub use legacy_q126::KeygenVerification as KeygenVerificationQ126;

impl CrsgenVerificationQ126 {
    pub fn new(crs_id: &RequestId, max_bit_length: usize, crs_digest: Vec<u8>) -> Self {
        Self {
            crsId: U256::from_be_slice(crs_id.as_bytes()),
            maxBitLength: U256::from_be_slice(&max_bit_length.to_be_bytes()),
            crsDigest: crs_digest.into(),
        }
    }
}

impl KeygenVerification {
    pub fn new_uncompressed(
        preproc_id: &RequestId,
        key_id: &RequestId,
        server_key_digest: Vec<u8>,
        public_key_digest: Vec<u8>,
        extra_data: Vec<u8>,
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
            extraData: extra_data.into(),
        }
    }
    pub fn new_compressed(
        preproc_id: &RequestId,
        key_id: &RequestId,
        compressed_keyset_digest: Vec<u8>,
        public_key_digest: Vec<u8>,
        extra_data: Vec<u8>,
    ) -> Self {
        Self {
            prepKeygenId: U256::from_be_slice(preproc_id.as_bytes()),
            keyId: U256::from_be_slice(key_id.as_bytes()),
            // NOTE: order should be in the order of the enum KeyType
            keyDigests: vec![
                KeyDigest {
                    keyType: KeyType::PUBLIC,
                    digest: public_key_digest.into(),
                },
                KeyDigest {
                    keyType: KeyType::COMPRESSED_KEYSET,
                    digest: compressed_keyset_digest.into(),
                },
            ],
            extraData: extra_data.into(),
        }
    }
}

impl KeygenVerificationQ126 {
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
                legacy_q126::KeyDigest {
                    keyType: legacy_q126::KeyType::SERVER,
                    digest: server_key_digest.into(),
                },
                legacy_q126::KeyDigest {
                    keyType: legacy_q126::KeyType::PUBLIC,
                    digest: public_key_digest.into(),
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
        /// @notice Extra data for client-specific context.
        bytes extraData;
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolStruct;

    use super::*;

    #[test]
    fn context_creation_confirmation_type_matches_rfc() {
        assert_eq!(
            ContextCreationConfirmation::eip712_encode_type(),
            "ContextCreationConfirmation(uint256 previousContextId,uint256 newContextId,bytes32 nodeConfigHash,bytes extraData)"
        );
    }

    #[test]
    fn context_creation_confirmation_new() {
        let mut previous = [0u8; 32];
        previous[31] = 1;
        let mut new = [0u8; 32];
        new[0] = 2;
        let previous_context_id = ContextId::from_bytes(previous);
        let new_context_id = ContextId::from_bytes(new);
        let node_config_hash = B256::repeat_byte(0xab);

        let confirmation = ContextCreationConfirmation::new(
            &previous_context_id,
            &new_context_id,
            node_config_hash,
            vec![0x01, 0x02],
        );

        assert_eq!(confirmation.previousContextId, U256::from(1));
        assert_eq!(confirmation.newContextId, U256::from(2) << 248);
        assert_eq!(confirmation.nodeConfigHash, node_config_hash);
        assert_eq!(confirmation.extraData.to_vec(), vec![0x01, 0x02]);
    }
}
