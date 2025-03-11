// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.28;

contract MockDecryptionManager {
    struct SnsCiphertextMaterial {
        uint256 ctHandle;
        uint256 keyId;
        bytes snsCiphertext;
    }

    struct CiphertextMaterial {
        uint256 ctHandle;
        uint256 keyId;
        bytes ciphertext;
    }

    struct CtHandleContractPair {
        uint256 ctHandle;
        address contractAddress;
    }

    event PublicDecryptionRequest(uint256 indexed publicDecryptionId, SnsCiphertextMaterial[] snsCtMaterials);
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
        SnsCiphertextMaterial[] memory snsCtMaterials = new SnsCiphertextMaterial[](1);
        snsCtMaterials[0] = SnsCiphertextMaterial({
            ctHandle: nextId,
            keyId: 1,
            snsCiphertext: hex"0102030405060708090a0b0c0d0e0f10"  // Example SNS ciphertext
        });
        emit PublicDecryptionRequest(nextId, snsCtMaterials);

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