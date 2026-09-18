//! Byte-freeze gate for the Solana user-decryption linker.
//!
//! The type string, its keccak-256 type hash, the EIP-712 encoding of every field, the domain
//! separator and the digest below are frozen together with the published vectors
//! (`core/grpc/test-vectors/solana_linker_v2.json`): other implementations reproduce these bytes,
//! so changing any of them is a new type name, not an edit.
//!
//! Unlike `evm_path_byte_frozen.rs`, whose goldens were read off the already-shipped EVM
//! implementation, the expected preimage here is assembled by hand from the EIP-712 specification
//! — `encodeData`, `hashStruct`, the domain separator and the `0x1901` prefix — with the linker
//! not involved; `compute_link` is required to agree and is never the source of the expectation.
//! Fixtures are spelled out locally: a frozen golden must not move because a shared test helper
//! was edited.

use std::path::PathBuf;

use alloy_primitives::{Address, U256, address, keccak256};
use alloy_sol_types::Eip712Domain;
use kms_grpc::solana_binding::{SOLANA_IDENTITY_LEN, SolanaUserDecryptBinding};

// ---------------------------------------------------------------------------
// Frozen constants
// ---------------------------------------------------------------------------

/// The EIP-712 type string: the versioned name of this construction. A layout change is a new
/// type name, never a reinterpretation of the same bytes.
const FROZEN_TYPE_STRING: &str = "SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userPubkey,bytes32 verifyingProgramId)";

/// `keccak256(FROZEN_TYPE_STRING)`, the first word of every `encodeData`.
const FROZEN_TYPE_HASH: &str = "295b0d606d30fca99f65a509411d7fbe11187e2c4414905bea1b41b9880619dc";

/// The EIP-712 domain type the Gateway `Decryption` contract's domain is hashed as: name,
/// version, chain id and verifying contract, no salt.
const FROZEN_DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// The deployment-time chain-id rule, frozen with the vector schema: type byte `0x01` followed by
/// the first seven bytes of the cluster genesis hash.
///
/// Not used by any KMS code path — a party reads the chain id out of the handles — but the vectors
/// pair a genesis hash with a derived id, and a change to the rule would silently change every
/// published pair.
const FROZEN_CHAIN_ID_DERIVATION_RULE: &str =
    "chain_id = be_u64(0x01 || base58_decode(genesis_hash)[0..7])";

/// The linker digest over [`frozen_request`] under [`frozen_domain`]. Frozen: see the module
/// comment. Pinned after the hand-assembled preimage and `compute_link` agreed on it independently.
const FROZEN_LINK: &str = "499d945afe8af9d26963e5a97cfb7ad15a986c2b0ddd7d672e80785488497a3f";

// ---------------------------------------------------------------------------
// The frozen fixture, spelled out
// ---------------------------------------------------------------------------

/// The Gateway `Decryption` contract's domain: its name and version as the contract declares them,
/// a gateway chain id, a fixed contract address.
const FROZEN_DOMAIN_NAME: &str = "Decryption";
const FROZEN_DOMAIN_VERSION: &str = "1";
const FROZEN_GATEWAY_CHAIN_ID: u64 = 54_321;
const FROZEN_VERIFYING_CONTRACT: Address = address!("66f9664f97F2b50F62D13eA064982f936dE76657");

/// The same host chain number as the EVM freeze fixture, with the Solana type byte set.
///
/// Deliberate: the two frozen digests are then visibly taken over the same deployment number, and
/// the only thing separating the request families is the type byte — which is precisely the claim.
const FROZEN_CHAIN_ID: u64 = kms_grpc::solana_binding::solana_host_chain_id(8006);

const FROZEN_PROGRAM_ID: [u8; SOLANA_IDENTITY_LEN] = [0x22; SOLANA_IDENTITY_LEN];
const FROZEN_RECEIVER: [u8; SOLANA_IDENTITY_LEN] = [0x33; SOLANA_IDENTITY_LEN];

/// Byte range of the chain id embedded in a ciphertext handle, restated locally.
const HANDLE_CHAIN_ID: std::ops::Range<usize> = 22..30;

/// A fixed ciphertext handle: `discriminator` everywhere except the embedded chain id.
fn frozen_handle(discriminator: u8) -> [u8; SOLANA_IDENTITY_LEN] {
    let mut handle = [discriminator; SOLANA_IDENTITY_LEN];
    handle[HANDLE_CHAIN_ID].copy_from_slice(&FROZEN_CHAIN_ID.to_be_bytes());
    handle
}

/// A deterministic 800-byte transport key, matching the EVM freeze fixture's `enc_key` pattern.
/// Opaque to the linker, which hashes it as `bytes`.
fn frozen_transport_key() -> Vec<u8> {
    (0u16..800).map(|byte| byte as u8).collect()
}

fn frozen_handles() -> [[u8; SOLANA_IDENTITY_LEN]; 2] {
    [frozen_handle(0xa1), frozen_handle(0xa2)]
}

fn frozen_domain() -> Eip712Domain {
    Eip712Domain::new(
        Some(FROZEN_DOMAIN_NAME.into()),
        Some(FROZEN_DOMAIN_VERSION.into()),
        Some(U256::from(FROZEN_GATEWAY_CHAIN_ID)),
        Some(FROZEN_VERIFYING_CONTRACT),
        None,
    )
}

fn frozen_request() -> SolanaUserDecryptBinding {
    let handles = frozen_handles();

    SolanaUserDecryptBinding::new(
        &FROZEN_PROGRAM_ID,
        &FROZEN_RECEIVER,
        handles.iter().map(|handle| handle.as_slice()),
        &frozen_transport_key(),
    )
    .expect("the frozen Solana request must validate")
}

// ---------------------------------------------------------------------------
// The hand-assembled preimage
// ---------------------------------------------------------------------------

fn frozen_bytes(hex_string: &str) -> Vec<u8> {
    hex::decode(hex_string).expect("a hex literal in this file")
}

/// `encodeData` per EIP-712, written out field by field: the type hash, then one 32-byte word per
/// field — `bytes` and `bytes32[]` as the keccak-256 of their contents, `bytes32` as itself.
fn expected_encode_data() -> Vec<u8> {
    let mut handles = Vec::with_capacity(2 * SOLANA_IDENTITY_LEN);
    for handle in frozen_handles() {
        handles.extend_from_slice(&handle);
    }

    let mut encoded = Vec::with_capacity(struct_offset::TOTAL);
    encoded.extend_from_slice(&frozen_bytes(FROZEN_TYPE_HASH));
    encoded.extend_from_slice(keccak256(frozen_transport_key()).as_slice());
    encoded.extend_from_slice(keccak256(&handles).as_slice());
    encoded.extend_from_slice(&FROZEN_RECEIVER);
    encoded.extend_from_slice(&FROZEN_PROGRAM_ID);
    encoded
}

/// `hashStruct(linker) = keccak256(encodeData)`.
fn expected_hash_struct() -> [u8; 32] {
    keccak256(expected_encode_data()).0
}

/// `hashStruct(EIP712Domain)`: the domain type hash, the keccak-256 of the two strings, the chain
/// id as a 32-byte big-endian word, the address left-padded to 32 bytes.
fn expected_domain_separator() -> [u8; 32] {
    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(keccak256(FROZEN_DOMAIN_TYPE_STRING.as_bytes()).as_slice());
    encoded.extend_from_slice(keccak256(FROZEN_DOMAIN_NAME.as_bytes()).as_slice());
    encoded.extend_from_slice(keccak256(FROZEN_DOMAIN_VERSION.as_bytes()).as_slice());
    encoded.extend_from_slice(&U256::from(FROZEN_GATEWAY_CHAIN_ID).to_be_bytes::<32>());
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(FROZEN_VERIFYING_CONTRACT.as_slice());
    keccak256(encoded).0
}

/// `0x1901 ‖ domainSeparator ‖ hashStruct(linker)`, assembled from the specification.
fn expected_preimage() -> Vec<u8> {
    let mut preimage = Vec::with_capacity(offset::TOTAL);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(&expected_domain_separator());
    preimage.extend_from_slice(&expected_hash_struct());
    preimage
}

/// Offsets into `encodeData`, in field order. Constants, not computed sums: an offset table that
/// derives itself from the same widths it is checking would move along with a layout change.
mod struct_offset {
    pub const TYPE_HASH: usize = 0;
    pub const PUBLIC_KEY: usize = 32;
    pub const HANDLES: usize = 64;
    pub const USER_PUBKEY: usize = 96;
    pub const VERIFYING_PROGRAM_ID: usize = 128;
    /// The type hash and four fields, one word each.
    pub const TOTAL: usize = 160;
}

/// Offsets into the signing preimage.
mod offset {
    pub const PREFIX: usize = 0;
    pub const DOMAIN_SEPARATOR: usize = 2;
    pub const HASH_STRUCT: usize = 34;
    pub const TOTAL: usize = 66;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn type_string_and_type_hash_are_frozen() {
    // The type string is the version boundary, and its hash is the first word of every preimage.
    // Both are published; a consumer reproducing the link from the JSON alone starts here.
    assert_eq!(
        FROZEN_TYPE_STRING,
        "SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userPubkey,bytes32 verifyingProgramId)",
    );
    assert_eq!(
        hex::encode(keccak256(FROZEN_TYPE_STRING.as_bytes())),
        FROZEN_TYPE_HASH,
    );
}

#[test]
fn encode_data_sits_at_its_frozen_offsets() {
    // The specified field order and encodings, checked against the hand-assembled encodeData. A
    // layout change fails here with a legible byte diff before it fails as an opaque digest
    // mismatch below.
    let encoded = expected_encode_data();

    assert_eq!(encoded.len(), struct_offset::TOTAL);
    assert_eq!(
        &encoded[struct_offset::TYPE_HASH..struct_offset::PUBLIC_KEY],
        frozen_bytes(FROZEN_TYPE_HASH).as_slice(),
    );
    assert_eq!(
        &encoded[struct_offset::PUBLIC_KEY..struct_offset::HANDLES],
        keccak256(frozen_transport_key()).as_slice(),
        "`bytes publicKey` is hashed to one word, so no field boundary depends on its width",
    );
    let mut handles = Vec::new();
    for handle in frozen_handles() {
        handles.extend_from_slice(&handle);
    }
    assert_eq!(
        &encoded[struct_offset::HANDLES..struct_offset::USER_PUBKEY],
        keccak256(&handles).as_slice(),
        "`bytes32[] handles` is the keccak-256 of the concatenated handles, in request order",
    );
    assert_eq!(
        &encoded[struct_offset::USER_PUBKEY..struct_offset::VERIFYING_PROGRAM_ID],
        &FROZEN_RECEIVER,
        "`bytes32 userPubkey` is the full 32-byte recipient, as is",
    );
    assert_eq!(
        &encoded[struct_offset::VERIFYING_PROGRAM_ID..],
        &FROZEN_PROGRAM_ID,
        "`bytes32 verifyingProgramId` is the host program, as is",
    );
}

#[test]
fn chain_id_has_no_word_of_its_own() {
    // The host chain is bound through the handle bytes, not as a separate field: the struct has
    // exactly five words, and none of them is the chain id. A layout that reintroduced one would
    // grow encodeData by a word and fail here by length before anything else.
    let encoded = expected_encode_data();
    let chain_id_word = {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&FROZEN_CHAIN_ID.to_be_bytes());
        word
    };

    assert_eq!(encoded.len() / 32, 5, "the type hash and four fields");
    assert!(
        !encoded.chunks(32).any(|word| word == chain_id_word),
        "the chain id must not appear as a word of its own",
    );
    assert_eq!(
        &frozen_handle(0xa1)[HANDLE_CHAIN_ID],
        &FROZEN_CHAIN_ID.to_be_bytes(),
        "it enters through bytes [22..30] of every handle",
    );
}

#[test]
fn domain_separator_is_the_gateway_domain_without_salt() {
    // The domain is the Gateway Decryption contract's, hashed as EIP712Domain(name, version,
    // chainId, verifyingContract): four fields, no salt. Hand-assembled first; the library's own
    // separator for the same domain is then required to agree.
    let separator = expected_domain_separator();

    assert_eq!(
        FROZEN_DOMAIN_TYPE_STRING,
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    assert_eq!(frozen_domain().separator().0, separator);
}

#[test]
fn preimage_sits_at_its_frozen_offsets() {
    let preimage = expected_preimage();

    assert_eq!(preimage.len(), offset::TOTAL);
    assert_eq!(
        &preimage[offset::PREFIX..offset::DOMAIN_SEPARATOR],
        &[0x19, 0x01],
        "the EIP-712 signing prefix",
    );
    assert_eq!(
        &preimage[offset::DOMAIN_SEPARATOR..offset::HASH_STRUCT],
        &expected_domain_separator(),
    );
    assert_eq!(&preimage[offset::HASH_STRUCT..], &expected_hash_struct());
}

#[test]
fn hand_assembled_preimage_hashes_to_frozen_link() {
    // The independent half: keccak-256 over bytes this file wrote, with the linker not involved.
    assert_eq!(hex::encode(keccak256(expected_preimage())), FROZEN_LINK);
}

#[test]
fn linker_digest_is_byte_frozen() {
    // The dependent half: the implementation must agree with the specification read by hand.
    let link = frozen_request().compute_link(&frozen_domain());

    assert_eq!(link.len(), 32, "the link is 32 bytes");
    assert_eq!(hex::encode(&link), FROZEN_LINK);
}

#[test]
fn link_moves_with_the_domain() {
    // The domain is an input, not a label: the same request under another Gateway's domain is
    // another link. Every other frozen input is covered by the sensitivity suite; the domain is
    // pinned here as well because it is the one input that reaches the linker from configuration
    // rather than from the request.
    let mut other_gateway = frozen_domain();
    other_gateway.chain_id = Some(U256::from(FROZEN_GATEWAY_CHAIN_ID + 1));

    assert_ne!(
        hex::encode(frozen_request().compute_link(&other_gateway)),
        FROZEN_LINK,
    );
}

#[test]
fn published_vector_set_frozen_at_same_constants() {
    // The freeze and the vectors are one decision. Read as raw text rather than through the vector
    // runner's schema types, so that a rename there cannot quietly relax this.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("solana_linker_v2.json");
    let set = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the published vector set must exist at {path:?}: {error}"));

    for frozen in [
        FROZEN_TYPE_STRING,
        FROZEN_TYPE_HASH,
        FROZEN_DOMAIN_TYPE_STRING,
        FROZEN_CHAIN_ID_DERIVATION_RULE,
    ] {
        assert!(
            set.contains(&format!("\"{frozen}\"")),
            "the published set no longer names {frozen}",
        );
    }
}

#[test]
fn frozen_chain_id_carries_solana_type_byte() {
    // The backstop that keeps Solana handles off the EVM linker and vice versa. The low bits are
    // the EVM freeze fixture's host chain id, so the two frozen digests cover the same deployment
    // number under two different chain kinds.
    assert_eq!(
        kms_grpc::solana_binding::chain_type_byte(FROZEN_CHAIN_ID),
        kms_grpc::solana_binding::SOLANA_CHAIN_TYPE,
    );
    assert_eq!(
        FROZEN_CHAIN_ID & kms_grpc::solana_binding::CLUSTER_TAG_MASK,
        8006
    );
    assert_eq!(
        &frozen_handle(0xa1)[HANDLE_CHAIN_ID],
        &FROZEN_CHAIN_ID.to_be_bytes(),
    );
}
