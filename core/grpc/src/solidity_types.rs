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
    struct KeygenVerification {
        /// @notice The ID of the preprocessed step.
        uint256 prepKeygenId;
        /// @notice The ID of the generated key.
        uint256 keyId;
        /// @notice The digest of the generated server key.
        bytes serverKeyDigest;
        /// @notice The digest of the generated public key.
        bytes publicKeyDigest;
    }
}

impl KeygenVerification {
    pub fn new(
        preproc_id: &RequestId,
        key_id: &RequestId,
        server_key_digest: Vec<u8>,
        public_key_digest: Vec<u8>,
    ) -> Self {
        Self {
            prepKeygenId: U256::from_be_slice(preproc_id.as_bytes()),
            keyId: U256::from_be_slice(key_id.as_bytes()),
            serverKeyDigest: server_key_digest.into(),
            publicKeyDigest: public_key_digest.into(),
        }
    }
}

// Solidity struct for DecompressionUpgradeKey
// This is a placeholder since gateway does not support this yet.
alloy_sol_types::sol! {
    struct FheDecompressionUpgradeKey {
        bytes decompressionUpgradeKeyDigest;
    }
}
