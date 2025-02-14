use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IACLManager {
        struct CtHandleCiphertext128Pair {
            uint256 ctHandle;
            bytes ciphertext128;
        }

        function allowUserDecrypt(uint256 chainId, uint256 ctHandle, address allowedAddress) external;
        function allowPublicDecrypt(uint256 ctHandle) external;
        function delegateAccount(
            uint256 chainId,
            address delegator,
            address delegatee,
            address[] calldata allowedContracts
        ) external;
        function getUserCiphertexts(
            uint256 chainId,
            address userAddress,
            IDecryptionManager.CtHandleContractPair[] calldata ctHandleContractPairs
        ) external view returns (CtHandleCiphertext128Pair[] calldata);
        function getPublicCiphertexts(
            uint256[] calldata ctHandles
        ) external view returns (CtHandleCiphertext128Pair[] calldata);
    }

    #[sol(rpc)]
    #[derive(Debug)]
    interface IDecryptionManager {
        struct CtHandleContractPair {
            uint256 ciphertextHandle;
            address contractAddress;
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

        event PublicDecryptionRequest(
            uint256 indexed publicDecryptionId,
            IACLManager.CtHandleCiphertext128Pair[] ctHandleCiphertext128Pairs
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
