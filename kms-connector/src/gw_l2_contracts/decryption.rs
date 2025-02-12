use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IDecryptionManager {
        struct CiphertextContract {
            uint256 ciphertextHandle;
            address contractAddress;
        }

        function publicDecryptionRequest(uint256[] calldata ciphertextHandles) external;

        function publicDecryptionResponse(
            uint256 publicDecryptionId,
            bytes calldata decryptedResult,
            bytes calldata signature
        ) external;

        function userDecryptionRequest(
            CiphertextContract[] calldata ciphertextContracts,
            address userAddress,
            bytes calldata publicKey,
            uint256 eip712ChainId,
            address[] calldata eip712Contracts,
            bytes calldata eip712Signature
        ) external;

        function userDecryptionResponse(
            uint256 userDecryptionId,
            bytes calldata decryptedResult,
            bytes calldata signature
        ) external;

        event PublicDecryptionRequest(
            uint256 indexed publicDecryptionId,
            uint256[] ciphertextHandles
        );

        event PublicDecryptionResponse(
            uint256 indexed publicDecryptionId,
            bytes decryptedResult,
            bytes[] signatures
        );

        event UserDecryptionRequest(
            uint256 indexed userDecryptionId,
            CiphertextContract[] ciphertextContracts,
            address userAddress
        );

        event UserDecryptionResponse(
            uint256 indexed userDecryptionId,
            bytes decryptedResult,
            bytes[] signatures
        );
    }
}

pub use IDecryptionManager::*;

/// Represents a public decryption request data
#[derive(Debug, Clone)]
pub struct PublicDecryptionRequestData {
    pub id: U256,
    pub ciphertext_handles: Vec<U256>,
}

/// Represents a user decryption request data
#[derive(Debug, Clone)]
pub struct UserDecryptionRequestData {
    pub id: U256,
    pub ciphertext_contracts: Vec<CiphertextContract>,
    pub user_address: Address,
}

impl From<PublicDecryptionRequest> for PublicDecryptionRequestData {
    fn from(event: PublicDecryptionRequest) -> Self {
        Self {
            id: event.publicDecryptionId,
            ciphertext_handles: event.ciphertextHandles,
        }
    }
}

impl From<UserDecryptionRequest> for UserDecryptionRequestData {
    fn from(event: UserDecryptionRequest) -> Self {
        Self {
            id: event.userDecryptionId,
            ciphertext_contracts: event.ciphertextContracts,
            user_address: event.userAddress,
        }
    }
}
