//! Pins the user-decryption link of each kind of user address.
//!
//! The link binds a response to its request, and every KMS party and client must compute the same
//! bytes. A one-byte change to a digest splits threshold aggregation for every user of that kind,
//! so the goldens below refuse any change. The handles carry a host chain id as fhevm handles do;
//! the KMS only hashes them.

#![cfg(feature = "non-wasm")]

use alloy_primitives::{U256, hex};
use alloy_sol_types::SolStruct;
use kms_grpc::{
    kms::v1::{Eip712DomainMsg, TypedCiphertext, UserDecryptionRequest},
    rpc_types::PlaintextReceiver,
    solidity_types::{SolanaUserDecryptionLinker, UserDecryptionLinker},
};

/// EIP-712 linker digest for [`evm_request`].
const EVM_LINK_GOLDEN: &str = "29a3b39870e4a170cfd96b0a4cafedf71c03a2d3cab23139bc4c423c5b0742e1";
const EVM_LINKER_TYPE: &str =
    "UserDecryptionLinker(bytes publicKey,bytes32[] handles,address userAddress)";
const EVM_USER_ADDRESS: &str = "0xdadB0d80178819F2319190D340ce9A924f783711";
const EVM_HOST_CHAIN_ID: u64 = 8006;

/// EIP-712 linker digest for [`solana_request`].
const SOLANA_LINK_GOLDEN: &str = "a12c4152651c477aa4c0a27c670250ae9d80ad51a1b0de0361c0606dbe792331";
const SOLANA_LINKER_TYPE: &str =
    "SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userAddress)";
/// The base58 form of the 32-byte key `[0x11; 32]`.
const SOLANA_USER_ADDRESS: &str = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
/// A Solana host chain id: top byte 0x01, then a 56-bit cluster tag.
const SOLANA_HOST_CHAIN_ID: u64 = (0x01 << 56) | 12_345;

/// The gateway `Decryption` contract the link is domain-separated by.
const VERIFYING_CONTRACT: &str = "0x66f9664f97F2b50F62D13eA064982f936dE76657";

/// Mirrors the repository's standard test domain, spelled out rather than imported: a frozen
/// digest must not move because a shared test helper was edited.
fn frozen_domain() -> Eip712DomainMsg {
    Eip712DomainMsg {
        name: "Authorization token".to_string(),
        version: "1".to_string(),
        chain_id: U256::from(EVM_HOST_CHAIN_ID).to_be_bytes_vec(),
        verifying_contract: VERIFYING_CONTRACT.to_string(),
        salt: None,
    }
}

/// A ciphertext handle embedding `host_chain_id` in bytes `[22..30]`, big-endian.
fn frozen_handle(host_chain_id: u64, discriminator: u8) -> Vec<u8> {
    let mut handle = [discriminator; 32];
    handle[22..30].copy_from_slice(&host_chain_id.to_be_bytes());
    handle.to_vec()
}

/// A deterministic request. `enc_key` is opaque to the linker (it is hashed as bytes, never
/// deserialized here), so a fixed pattern is enough.
fn frozen_request(user_address: &str, host_chain_id: u64) -> UserDecryptionRequest {
    UserDecryptionRequest {
        request_id: None,
        typed_ciphertexts: [0xa1, 0xa2]
            .map(|discriminator| TypedCiphertext {
                ciphertext: vec![].into(),
                fhe_type: 0,
                external_handle: frozen_handle(host_chain_id, discriminator),
                ciphertext_format: 0,
            })
            .to_vec(),
        key_id: None,
        client_address: user_address.to_string(),
        enc_key: (0u16..800).map(|byte| byte as u8).collect(),
        domain: Some(frozen_domain()),
        extra_data: vec![],
        context_id: None,
        epoch_id: None,
        signing_schemes: vec![],
    }
}

fn evm_request() -> UserDecryptionRequest {
    frozen_request(EVM_USER_ADDRESS, EVM_HOST_CHAIN_ID)
}

fn solana_request() -> UserDecryptionRequest {
    frozen_request(SOLANA_USER_ADDRESS, SOLANA_HOST_CHAIN_ID)
}

#[test]
fn linker_type_strings_are_frozen() {
    assert_eq!(UserDecryptionLinker::eip712_encode_type(), EVM_LINKER_TYPE);
    assert_eq!(
        SolanaUserDecryptionLinker::eip712_encode_type(),
        SOLANA_LINKER_TYPE
    );
}

#[test]
fn evm_link_is_byte_frozen() {
    let (link, _, receiver) = evm_request()
        .compute_link_checked()
        .expect("the frozen EVM request must validate");

    assert_eq!(hex::encode(&link), EVM_LINK_GOLDEN);
    assert!(matches!(receiver, PlaintextReceiver::Evm(_)));
}

#[test]
fn solana_link_is_byte_frozen() {
    let (link, _, receiver) = solana_request()
        .compute_link_checked()
        .expect("the frozen Solana request must validate");

    assert_eq!(hex::encode(&link), SOLANA_LINK_GOLDEN);
    assert_eq!(receiver, PlaintextReceiver::Solana([0x11; 32]));
}
