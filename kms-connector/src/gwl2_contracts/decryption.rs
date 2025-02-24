use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IDecryptionManager {
        struct CtHandleContractPair {
            uint256 ctHandle;
            address contractAddress;
        }

        struct CiphertextMaterial {
            uint256 ctHandle;
            uint256 keyId;
            bytes ciphertext128;
        }

        error InvalidKmsSigner(address invalidSigner);
        error KmsSignerAlreadySigned(uint256 publicDecryptionId, address signer);

        function publicDecryptionRequest(uint256[] calldata ciphertextHandles) external;

        function publicDecryptionResponse(
            uint256 publicDecryptionId,
            bytes calldata decryptedResult,
            bytes calldata signature
        ) external;

        function userDecryptionRequest(
            CtHandleContractPair[] calldata ctHandleContractPairs,
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

        function isPublicDecryptionDone(uint256 publicDecryptionId) external view returns (bool);

        event PublicDecryptionRequest(
            uint256 indexed publicDecryptionId,
            CiphertextMaterial[] ctMaterials
        );

        event PublicDecryptionResponse(
            uint256 indexed publicDecryptionId,
            bytes decryptedResult,
            bytes[] signatures
        );

        event UserDecryptionRequest(
            uint256 indexed userDecryptionId,
            CtHandleContractPair[] ctHandleContractPairs,
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
