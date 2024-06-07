// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import "./ACL.sol";

contract FHEVMCoprocessor is EIP712 {
    struct CiphertextVerification {
        uint256 handle;
        uint8 handleType;
        address dAppAddress;
        address callerAddress;
        bytes4 functionSignature;
    }

    string public constant CIPHERTEXTVERIFICATION_TYPE =
        "CiphertextVerification(uint256 handle,uint8 handleType,address dAppAddress,address callerAddress,bytes4 functionSignature)";
    bytes32 private constant CIPHERTEXTVERIFICATION_TYPE_HASH = keccak256(bytes(CIPHERTEXTVERIFICATION_TYPE));

    ACL immutable acl;
    address immutable coprocessorAccountAddress;

    uint256 counterRand; // counter used for computing handles of randomness operators
    uint256 counterRandBounded; // counter used for computing handles of bounded randomness operators

    enum Operators {
        fheAdd,
        fheSub,
        fheMul,
        fheDiv,
        fheRem,
        fheBitAnd,
        fheBitOr,
        fheBitXor,
        fheShl,
        fheShr,
        fheRotl,
        fheRotr,
        fheEq,
        fheNe,
        fheGe,
        fheGt,
        fheLe,
        fheLt,
        fheMin,
        fheMax,
        fheNeg,
        fheNot,
        verifyCiphertext,
        cast,
        trivialEncrypt,
        fheIfThenElse,
        fheRand,
        fheRandBounded
    }

    constructor(address _aclAddress, address _coprocessorAccountAddress) EIP712("FHEVMCoprocessor", "1") {
        acl = ACL(_aclAddress);
        coprocessorAccountAddress = _coprocessorAccountAddress;
    }

    function unaryOp(Operators op, uint256 ct) internal returns (uint256 result) {
        require(acl.isAllowed(ct, msg.sender), "sender doesn't own ct on op");
        result = uint256(keccak256(abi.encodePacked(op, ct)));
        acl.allowTransient(result, msg.sender);
    }

    function binaryOp(Operators op, uint256 lhs, uint256 rhs, bytes1 scalarByte) internal returns (uint256 result) {
        bytes1 scalar = scalarByte & 0x01;
        require(acl.isAllowed(lhs, msg.sender), "sender doesn't own lhs on op");
        if (scalar == 0x00) require(acl.isAllowed(rhs, msg.sender), "sender doesn't own rhs on op");
        result = uint256(keccak256(abi.encodePacked(op, lhs, rhs, scalar)));
        acl.allowTransient(result, msg.sender);
    }

    function ternaryOp(Operators op, uint256 lhs, uint256 middle, uint256 rhs) internal returns (uint256 result) {
        require(acl.isAllowed(lhs, msg.sender), "sender doesn't own lhs on op");
        require(acl.isAllowed(middle, msg.sender), "sender doesn't own middle on op");
        require(acl.isAllowed(rhs, msg.sender), "sender doesn't own rhs on op");
        result = uint256(keccak256(abi.encodePacked(op, lhs, middle, rhs)));
        acl.allowTransient(result, msg.sender);
    }

    function fheAdd(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheAdd, lhs, rhs, scalarByte);
    }

    function fheSub(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheSub, lhs, rhs, scalarByte);
    }

    function fheMul(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheMul, lhs, rhs, scalarByte);
    }

    function fheDiv(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheDiv, lhs, rhs, scalarByte);
    }

    function fheRem(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheRem, lhs, rhs, scalarByte);
    }

    function fheBitAnd(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheBitAnd, lhs, rhs, scalarByte);
    }

    function fheBitOr(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheBitOr, lhs, rhs, scalarByte);
    }

    function fheBitXor(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheBitXor, lhs, rhs, scalarByte);
    }

    function fheShl(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheShl, lhs, rhs, scalarByte);
    }

    function fheShr(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheShr, lhs, rhs, scalarByte);
    }

    function fheRotl(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheRotl, lhs, rhs, scalarByte);
    }

    function fheRotr(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheRotr, lhs, rhs, scalarByte);
    }

    function fheEq(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheEq, lhs, rhs, scalarByte);
    }

    function fheNe(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheNe, lhs, rhs, scalarByte);
    }

    function fheGe(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheGe, lhs, rhs, scalarByte);
    }

    function fheGt(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheGt, lhs, rhs, scalarByte);
    }

    function fheLe(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheLe, lhs, rhs, scalarByte);
    }

    function fheLt(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheLt, lhs, rhs, scalarByte);
    }

    function fheMin(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheMin, lhs, rhs, scalarByte);
    }

    function fheMax(uint256 lhs, uint256 rhs, bytes1 scalarByte) external returns (uint256 result) {
        result = binaryOp(Operators.fheMax, lhs, rhs, scalarByte);
    }

    function fheNeg(uint256 ct) external returns (uint256 result) {
        result = unaryOp(Operators.fheNeg, ct);
    }

    function fheNot(uint256 ct) external returns (uint256 result) {
        result = unaryOp(Operators.fheNot, ct);
    }

    function fhePubKey(bytes1) external pure returns (bytes memory result) {
        return hex"00010203040506070809"; // TODO : replace with real key
    }

    function hashCiphertextVerification(CiphertextVerification memory cv) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        CIPHERTEXTVERIFICATION_TYPE_HASH,
                        cv.handle,
                        cv.handleType,
                        cv.dAppAddress,
                        cv.callerAddress,
                        cv.functionSignature
                    )
                )
            );
    }

    function verifyEIP712(CiphertextVerification memory cv, bytes memory signature) internal view {
        bytes32 digest = hashCiphertextVerification(cv);
        address signer = ECDSA.recover(digest, signature);
        require(signer == coprocessorAccountAddress, "Signer address mismatch");
    }

    function verifyCiphertext(bytes memory input) external returns (uint256 result) {
        // input is supposed to be of length 32+65+20+4+1 byte (handle+signature+callerAddress+functionSignature+type)
        require(input.length == 122, "input of wrong size");

        assembly {
            result := mload(add(input, 32))
        }

        bytes memory signature = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            signature[i] = input[i + 32];
        }

        address callerAddress;
        bytes4 functionSignature;
        uint8 handleType;
        assembly {
            let startPos := add(input, 128)
            let word := mload(startPos)
            callerAddress := shr(96, word)

            startPos := add(input, 148)
            word := mload(startPos)
            functionSignature := shr(224, word)

            startPos := add(input, 153)
            word := mload(startPos)
            handleType := byte(0, word)
        }

        CiphertextVerification memory cv;
        cv.handle = result;
        cv.handleType = handleType;
        cv.dAppAddress = msg.sender;
        cv.callerAddress = callerAddress;
        cv.functionSignature = functionSignature;

        verifyEIP712(cv, signature);
        acl.allowTransient(result, msg.sender);
    }

    function cast(uint256 ct, bytes1 toType) external returns (uint256 result) {
        require(acl.isAllowed(ct, msg.sender), "sender doesn't own lhs on op");
        result = uint256(keccak256(abi.encodePacked(Operators.cast, ct, toType)));
        acl.allowTransient(result, msg.sender);
    }

    function trivialEncrypt(uint256 pt, bytes1 toType) external returns (uint256 result) {
        result = uint256(keccak256(abi.encodePacked(Operators.trivialEncrypt, pt, toType)));
        acl.allowTransient(result, msg.sender);
    }

    function fheIfThenElse(uint256 control, uint256 ifTrue, uint256 ifFalse) external returns (uint256 result) {
        result = ternaryOp(Operators.fheIfThenElse, control, ifTrue, ifFalse);
    }

    function fheRand(bytes1 randType) external returns (uint256 result) {
        result = uint256(keccak256(abi.encodePacked(Operators.fheRand, randType, counterRand)));
        acl.allowTransient(result, msg.sender);
        counterRand++;
    }

    function fheRandBounded(uint256 upperBound, bytes1 randType) external returns (uint256 result) {
        result = uint256(
            keccak256(abi.encodePacked(Operators.fheRandBounded, upperBound, randType, counterRandBounded))
        );
        acl.allowTransient(result, msg.sender);
        counterRandBounded++;
    }
}
