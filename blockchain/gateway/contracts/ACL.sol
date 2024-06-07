// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity ^0.8.25;

import "./FHEVMCoprocessor.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ACL {
    FHEVMCoprocessor public immutable fhEVMcoprocessor;

    mapping(uint256 => bool) public allowedForDecryption;

    // A set of (handle, address) pairs.
    // If address A is in the set for handle H, full access is granted to H for A.
    mapping(uint256 handle => mapping(address account => bool isAllowed)) public persistedAllowedPairs;

    mapping(address account => mapping(address delegatee => bool isDelegate)) public delegates;

    constructor(address _coprocessorAddress) {
        fhEVMcoprocessor = FHEVMCoprocessor(_coprocessorAddress);
    }

    // allowTransient use of `handle` for address `account`.
    // The caller must be allowed to use `handle` for allowTransient() to succeed. If not, allowTransient() reverts.
    // @note: The Coprocessor contract can always `allowTransient`, contrarily to `allow`
    function allowTransient(uint256 handle, address account) public {
        if (msg.sender != address(fhEVMcoprocessor)) {
            require(isAllowed(handle, msg.sender), "sender isn't allowed");
        }
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            tstore(key, 1)
            let length := tload(0)
            let lengthPlusOne := add(length, 1)
            tstore(lengthPlusOne, key)
            tstore(0, lengthPlusOne)
        }
    }

    function allowedTransient(uint256 handle, address account) public view returns (bool) {
        bool isAllowedTransient;
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            isAllowedTransient := tload(key)
        }
        return isAllowedTransient;
    }

    function cleanAllTransientAllowed() external {
        // this function removes the transient allowances, could be useful for integration with Account Abstraction when bundling several UserOps calling the FHEVMCoprocessor
        assembly {
            let length := tload(0)
            tstore(0, 0)
            let lengthPlusOne := add(length, 1)
            for {
                let i := 1
            } lt(i, lengthPlusOne) {
                i := add(i, 1)
            } {
                let handle := tload(i)
                tstore(i, 0)
                tstore(handle, 0)
            }
        }
    }

    // Allow use of `handle` for address `account`.
    // The caller must be allowed to use `handle` for allow() to succeed. If not, allow() reverts.
    function allow(uint256 handle, address account) external {
        require(isAllowed(handle, msg.sender), "sender isn't allowed");
        persistedAllowedPairs[handle][account] = true;
    }

    // Returns true if address `a` is allowed to use `c` and false otherwise.
    function persistAllowed(uint256 handle, address account) public view returns (bool) {
        return persistedAllowedPairs[handle][account];
    }

    function isAllowed(uint256 handle, address account) public view returns (bool) {
        return allowedTransient(handle, account) || persistAllowed(handle, account);
    }

    function delegateAccount(address delegatee) external {
        delegates[msg.sender][delegatee] = true;
    }

    function removeDelegation(address delegatee) external {
        delegates[msg.sender][delegatee] = false;
    }

    function allowedOnBehalf(address delegatee, uint256 handle, address account) external view returns (bool) {
        return persistedAllowedPairs[handle][account] && delegates[account][delegatee];
    }

    function allowForDecryption(uint256[] memory ctsHandles) external {
        uint256 len = ctsHandles.length;
        for (uint256 k = 0; k < len; k++) {
            uint256 handle = ctsHandles[k];
            require(isAllowed(handle, msg.sender), "sender isn't allowed");
            allowedForDecryption[handle] = true;
        }
    }
}
