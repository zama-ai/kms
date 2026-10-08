//! Pins the user-decryption link of each kind of user address.
//!
//! The link binds a response to its request, and every KMS party and client must compute the same
//! bytes. A one-byte change to a digest splits threshold aggregation for every user of that kind,
//! so the goldens below refuse any change.

#![cfg(feature = "non-wasm")]

use alloy_primitives::{U256, hex};
use alloy_sol_types::SolStruct;
use kms_grpc::{
    kms::v1::{Eip712DomainMsg, TypedCiphertext, UserDecryptionRequest},
    rpc_types::ClientAddress,
    solidity_types::{SolanaUserDecryptionLinker, UserDecryptionLinker},
};

/// EIP-712 link digest for [`evm_request`].
const EVM_LINK_GOLDEN: &str = "29a3b39870e4a170cfd96b0a4cafedf71c03a2d3cab23139bc4c423c5b0742e1";
const EVM_LINKER_TYPE: &str =
    "UserDecryptionLinker(bytes publicKey,bytes32[] handles,address userAddress)";
const EVM_USER_ADDRESS: &str = "0xdadB0d80178819F2319190D340ce9A924f783711";
/// The handles of [`evm_request`]. The KMS treats a handle as opaque bytes.
const EVM_HANDLES: [&str; 2] = [
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000001f46a1a1",
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20000000000001f46a2a2",
];

/// EIP-712 link digest for [`solana_request`].
const SOLANA_LINK_GOLDEN: &str = "a12c4152651c477aa4c0a27c670250ae9d80ad51a1b0de0361c0606dbe792331";
const SOLANA_LINKER_TYPE: &str =
    "SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userAddress)";
/// The base58 form of the 32-byte key `[0x11; 32]`.
const SOLANA_USER_ADDRESS: &str = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
/// The handles of [`solana_request`]. The KMS treats a handle as opaque bytes.
const SOLANA_HANDLES: [&str; 2] = [
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10100000000003039a1a1",
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20100000000003039a2a2",
];

/// The base58 form of the Solana key that is 12 zero bytes followed by the 20 bytes of
/// [`EVM_USER_ADDRESS`].
const PADDED_EVM_SOLANA_USER_ADDRESS: &str = "11111111111143qvqLoRCyWvikzEuL8UBgqubLPS";
/// EIP-712 link digest for [`evm_request`] with [`PADDED_EVM_SOLANA_USER_ADDRESS`] as the user.
const PADDED_EVM_SOLANA_LINK_GOLDEN: &str =
    "0ff75eb646d980563d4d0dba823c23848ec78ff549d005d4c59977b6d46994bc";

/// The gateway chain and `Decryption` contract the link is domain-separated by.
const GATEWAY_CHAIN_ID: u64 = 8006;
const VERIFYING_CONTRACT: &str = "0x66f9664f97F2b50F62D13eA064982f936dE76657";

/// Mirrors the repository's standard test domain, spelled out rather than imported: a frozen
/// digest must not move because a shared test helper was edited.
fn frozen_domain() -> Eip712DomainMsg {
    Eip712DomainMsg {
        name: "Authorization token".to_string(),
        version: "1".to_string(),
        chain_id: U256::from(GATEWAY_CHAIN_ID).to_be_bytes_vec(),
        verifying_contract: VERIFYING_CONTRACT.to_string(),
        salt: None,
    }
}

/// A deterministic request. `enc_key` is opaque to the linker (it is hashed as bytes, never
/// deserialized here), so a fixed pattern is enough.
fn frozen_request(user_address: &str, handles: [&str; 2]) -> UserDecryptionRequest {
    UserDecryptionRequest {
        request_id: None,
        typed_ciphertexts: handles
            .map(|handle| TypedCiphertext {
                ciphertext: vec![].into(),
                fhe_type: 0,
                external_handle: hex::decode(handle).unwrap(),
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
    frozen_request(EVM_USER_ADDRESS, EVM_HANDLES)
}

fn solana_request() -> UserDecryptionRequest {
    frozen_request(SOLANA_USER_ADDRESS, SOLANA_HANDLES)
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
    let (link, _, client_address) = evm_request()
        .compute_link_checked()
        .expect("the frozen EVM request must validate");

    assert_eq!(hex::encode(&link), EVM_LINK_GOLDEN);
    assert!(matches!(client_address, ClientAddress::Evm(_)));
}

#[test]
fn solana_link_is_byte_frozen() {
    let (link, _, client_address) = solana_request()
        .compute_link_checked()
        .expect("the frozen Solana request must validate");

    assert_eq!(hex::encode(&link), SOLANA_LINK_GOLDEN);
    assert_eq!(client_address, ClientAddress::Solana([0x11; 32]));
}

/// The same 20 bytes as an EVM address and, left-padded with zeros, as a Solana key give two
/// links: the two link structs have different type hashes.
#[test]
fn evm_and_solana_links_of_the_same_bytes_differ() {
    let mut padded_key = [0u8; 32];
    padded_key[12..].copy_from_slice(&hex::decode(EVM_USER_ADDRESS).unwrap());
    let request = UserDecryptionRequest {
        client_address: PADDED_EVM_SOLANA_USER_ADDRESS.to_string(),
        ..evm_request()
    };

    let (link, _, client_address) = request
        .compute_link_checked()
        .expect("the padded Solana request must validate");

    assert_eq!(client_address, ClientAddress::Solana(padded_key));
    assert_eq!(hex::encode(&link), PADDED_EVM_SOLANA_LINK_GOLDEN);
    assert_ne!(PADDED_EVM_SOLANA_LINK_GOLDEN, EVM_LINK_GOLDEN);
}
