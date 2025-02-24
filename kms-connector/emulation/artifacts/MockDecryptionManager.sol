// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.28;

contract MockDecryptionManager {
    struct CiphertextMaterial {
        uint256 ctHandle;
        uint256 keyId;
        bytes ciphertext128;
    }

    struct CtHandleContractPair {
        uint256 ctHandle;
        address contractAddress;
    }

    event PublicDecryptionRequest(uint256 indexed publicDecryptionId, CiphertextMaterial[] ctMaterials);
    event UserDecryptionRequest(
        uint256 indexed userDecryptionId,
        CtHandleContractPair[] ctHandleContractPairs,
        address userAddress
    );
    event PublicDecryptionResponse(uint256 indexed publicDecryptionId, bytes decryptedResult, bytes[] signatures);
    event UserDecryptionResponse(uint256 indexed userDecryptionId, bytes decryptedResult, bytes[] signatures);

    uint256 private nextId;

    constructor() {
        nextId = 1;
    }

    function emitEvents() public {
        // Emit public decryption request
        CiphertextMaterial[] memory ctMaterials = new CiphertextMaterial[](1);
        ctMaterials[0] = CiphertextMaterial({
            ctHandle: nextId,
            keyId: 1,
            ciphertext128: hex"0102030405060708090a0b0c0d0e0f10"
        });
        emit PublicDecryptionRequest(nextId, ctMaterials);

        // Emit user decryption request
        CtHandleContractPair[] memory ctHandleContractPairs = new CtHandleContractPair[](1);
        ctHandleContractPairs[0] = CtHandleContractPair({
            ctHandle: nextId,
            contractAddress: msg.sender
        });
        emit UserDecryptionRequest(nextId, ctHandleContractPairs, msg.sender);

        nextId++;
    }

    function publicDecryptionResponse(
        uint256 publicDecryptionId,
        bytes calldata decryptedResult,
        bytes calldata signature
    ) public {
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        emit PublicDecryptionResponse(publicDecryptionId, decryptedResult, signatures);
    }

    function userDecryptionResponse(
        uint256 userDecryptionId,
        bytes calldata decryptedResult,
        bytes calldata signature
    ) public {
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        emit UserDecryptionResponse(userDecryptionId, decryptedResult, signatures);
    }
}