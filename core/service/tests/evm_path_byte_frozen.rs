//! Byte-freeze gate for the EVM user-decryption path.
//!
//! The Solana user-decryption branch is additive: it lands beside the EVM path and never
//! modifies it. Existing EVM payloads, the EIP-712 request<->response linker digest and the
//! 20-byte receiver id must stay byte-identical, including across a mixed-version upgrade where
//! KMS parties run different versions — a one-byte divergence in an EVM digest would split
//! threshold aggregation for all EVM traffic, in production, at once.
//!
//! This file is green from its first run: the constants below capture what the tree already
//! produces. That is deliberate, and it is the one case where reading a golden off the
//! implementation is the correct method — the reference *is* today's output, and the test's job
//! is to refuse any change to it. Goldens for new (Solana) constructions are not allowed to be
//! captured this way: they are assembled independently from the specification and cross-checked
//! against a second implementation.
//!
//! The gate has a second half that cannot live in a test: no commit may edit an existing EVM
//! test or vector file. That is enforced by review and by a CI diff-path check.

#![cfg(feature = "non-wasm")]

use alloy_primitives::{U256, hex};
use alloy_sol_types::SolStruct;
use kms_grpc::{
    kms::v1::{Eip712DomainMsg, TypedCiphertext, UserDecryptionRequest},
    solidity_types::UserDecryptionLinker,
};

/// EIP-712 linker digest for [`frozen_request`]. Frozen: see the module comment.
const EVM_LINK_GOLDEN: &str = "29a3b39870e4a170cfd96b0a4cafedf71c03a2d3cab23139bc4c423c5b0742e1";

/// The EIP-712 type string the linker digest is computed over. Frozen together with the digest:
/// a change to the `UserDecryptionLinker` struct changes the type hash and therefore every
/// existing EVM digest, which is exactly what this gate forbids.
const EVM_LINKER_TYPE: &str =
    "UserDecryptionLinker(bytes publicKey,bytes32[] handles,address userAddress)";

/// A checksummed EVM user address, distinct from the verifying contract.
const CLIENT_ADDRESS: &str = "0xdadB0d80178819F2319190D340ce9A924f783711";

/// The gateway `Decryption` contract the response signature is domain-separated by.
const VERIFYING_CONTRACT: &str = "0x66f9664f97F2b50F62D13eA064982f936dE76657";

const HOST_CHAIN_ID: u64 = 8006;

/// Mirrors the repository's standard test domain, spelled out rather than imported: a frozen
/// digest must not move because a shared test helper was edited.
fn frozen_domain() -> Eip712DomainMsg {
    Eip712DomainMsg {
        name: "Authorization token".to_string(),
        version: "1".to_string(),
        chain_id: U256::from(HOST_CHAIN_ID).to_be_bytes_vec(),
        verifying_contract: VERIFYING_CONTRACT.to_string(),
        salt: None,
    }
}

/// A fixed EVM ciphertext handle: chain id in bytes `[22..30]` with the chain-kind bit clear.
fn frozen_handle(discriminator: u8) -> Vec<u8> {
    let mut handle = [discriminator; 32];
    handle[22..30].copy_from_slice(&HOST_CHAIN_ID.to_be_bytes());
    handle.to_vec()
}

/// A deterministic EVM user-decryption request. `enc_key` is opaque to the linker (it is hashed
/// as bytes, never deserialized here), so a fixed pattern is enough and keeps the fixture
/// independent of the encryption key format.
fn frozen_request() -> UserDecryptionRequest {
    UserDecryptionRequest {
        request_id: None,
        typed_ciphertexts: vec![
            TypedCiphertext {
                ciphertext: vec![],
                fhe_type: 0,
                external_handle: frozen_handle(0xa1),
                ciphertext_format: 0,
            },
            TypedCiphertext {
                ciphertext: vec![],
                fhe_type: 0,
                external_handle: frozen_handle(0xa2),
                ciphertext_format: 0,
            },
        ],
        key_id: None,
        client_address: CLIENT_ADDRESS.to_string(),
        enc_key: (0u16..800).map(|byte| byte as u8).collect(),
        domain: Some(frozen_domain()),
        extra_data: vec![],
        context_id: None,
        epoch_id: None,
        solana_pubkey: None,
        solana_verifying_program_id: None,
        // Empty, so this fixture keeps exercising the legacy scalar signature fields the frozen
        // digests were taken over.
        signing_schemes: vec![],
    }
}

#[test]
fn evm_linker_type_string_is_frozen() {
    assert_eq!(UserDecryptionLinker::eip712_encode_type(), EVM_LINKER_TYPE);
}

#[test]
fn evm_linker_digest_is_byte_frozen() {
    let (link, domain) = frozen_request()
        .compute_link_checked()
        .expect("the frozen EVM request must validate");

    assert_eq!(link.len(), 32, "the EVM linker digest is keccak256");
    assert_eq!(hex::encode(&link), EVM_LINK_GOLDEN);
    assert_eq!(domain.chain_id, Some(U256::from(HOST_CHAIN_ID)));
    assert_eq!(
        domain
            .verifying_contract
            .map(|address| address.to_checksum(None)),
        Some(VERIFYING_CONTRACT.to_string()),
    );
}

#[test]
fn evm_linker_digest_ignores_the_solana_request_fields() {
    let baseline = frozen_request().compute_link_checked().expect("baseline").0;

    // Every field the Solana branch reads must be invisible to the EVM digest. A party that
    // receives a request carrying them — including one that predates them and ignores them as
    // unknown protobuf fields — computes the same EVM bytes as one that does not.
    let mut with_solana_fields = frozen_request();
    with_solana_fields.solana_pubkey = Some(vec![0x11; 32]);
    with_solana_fields.solana_verifying_program_id = Some(vec![0x22; 32]);
    with_solana_fields.extra_data = vec![0x02; 65];
    with_solana_fields.context_id = Some(kms_grpc::kms::v1::RequestId {
        request_id: "a".repeat(64),
    });
    with_solana_fields.epoch_id = Some(kms_grpc::kms::v1::RequestId {
        request_id: "b".repeat(64),
    });

    assert_eq!(
        with_solana_fields
            .compute_link_checked()
            .expect("variant")
            .0,
        baseline,
        "a Solana-only field must not perturb the EVM linker digest",
    );
}

#[test]
fn evm_path_rejects_handles_of_the_solana_chain_kind() {
    // The chain-kind backstop keeps a Solana-embedded handle off the EVM path entirely, so the
    // two linkers can never be asked to bind the same handle.
    let mut solana_kind = frozen_request();
    let mut handle = [0xa1u8; 32];
    handle[22..30].copy_from_slice(&((1u64 << 63) | HOST_CHAIN_ID).to_be_bytes());
    solana_kind.typed_ciphertexts[0].external_handle = handle.to_vec();

    let error = solana_kind
        .compute_link_checked()
        .expect_err("a Solana-kind handle must not reach the EVM linker")
        .to_string();
    assert!(
        error.contains("embeds Solana chain ID"),
        "unexpected error: {error}",
    );
}
