// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./lib/TFHE.sol";

// This contract is used to test the storage layout of a contract
contract SimpleStorageFhevm {
    euint32 storageSlot0 = TFHE.asEuint32(42); // 32 bytes of data
    euint16 storageSlot1 = TFHE.asEuint16(43); // 16 bytes of data
    euint8 storageSlot3 = TFHE.asEuint8(0xff); // 8 bytes of data
    ebool storageSlot4 = TFHE.asEbool(true); // 1 byte of data

    bool storageSlot5 = true; // 1 bit of data
    uint256 storageSlot6 = 0x10d9e; // 32 bytes of data
    uint8 storageSlot7 = 0xff; // 1 byte of data
}
