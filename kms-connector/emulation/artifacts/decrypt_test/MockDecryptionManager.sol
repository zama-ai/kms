// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.28;

contract MockDecryptionManager {
    struct SnsCiphertextMaterial {
        uint256 ctHandle;
        uint256 keyId;
        bytes snsCiphertext;
    }

    event PublicDecryptionRequest(uint256 indexed publicDecryptionId, SnsCiphertextMaterial[] snsCtMaterials);
    event PublicDecryptionResponse(uint256 indexed publicDecryptionId, bytes decryptedResult, bytes[] signatures);
    
    // Simple event that doesn't require complex memory structures
    event RawDataReceived(uint256 indexed requestId, uint256 keyId, uint256 dataSize);

    // Modified function that avoids creating large memory arrays when possible
    function emitEvents(uint256 next_id, uint256 key_id, bytes calldata cipher_text) public {
        // First log the receipt of data without using arrays
        emit RawDataReceived(next_id, key_id, cipher_text.length);
        
        // For compatibility, create the smallest possible array
        // This still creates a memory array but with minimal overhead
        SnsCiphertextMaterial[] memory snsCtMaterials = new SnsCiphertextMaterial[](1);
        
        // Store references without copying data to minimize memory usage
        snsCtMaterials[0].ctHandle = next_id;
        snsCtMaterials[0].keyId = key_id;
        snsCtMaterials[0].snsCiphertext = cipher_text;
        
        // Emit the event required by the interface
        emit PublicDecryptionRequest(next_id, snsCtMaterials);
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
}
