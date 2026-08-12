//! Byte-freeze gate for Solana user-decryption linker v1.
//!
//! What freezing means, stated once so the next reader does not have to infer it: before this
//! point the preimage layout, the scheme tag and the call separator could move freely — v1 shipped
//! nowhere and no cross-version compatibility existed. With the normative vectors published
//! (`core/grpc/test-vectors/solana_linker_v1.json`) a second party now depends on these bytes.
//! From here, changing any of them is a **deliberate version bump in the scheme tag**, not an
//! edit: five implementations reproduce this construction, and a silent reinterpretation of the
//! same bytes is exactly the failure the tag exists to prevent.
//!
//! **This test failing is the signal, not the accident.** If it fails, the question is never "what
//! constant do I paste here" — it is "did I mean to define v2".
//!
//! Method, and the one way this file differs from `evm_path_byte_frozen.rs`: the EVM goldens there
//! were legitimately read off the implementation, because the EVM path already shipped and the
//! reference *is* today's output. Solana v1 is new, so its goldens may not be captured that way.
//! The expected hasher input below is assembled by hand, element by element, from the specified
//! preimage layout, and only the hashing of that hand-assembled sequence uses the SHAKE-256
//! primitive. `compute_link` is then required to agree — it is the thing under test, never the
//! source of the expectation.
//!
//! Fixtures are spelled out locally and this file imports no test helper on purpose: a frozen
//! golden must not move because a shared helper was edited.

use std::path::PathBuf;

use hashing::{DomainSep, hash_element_w_size};
use kms_grpc::solana_binding::{
    DSEP_SOLANA_LINKER, SOLANA_IDENTITY_LEN, SOLANA_LINKER_SCHEME_TAG, SolanaUserDecryptBinding,
};

// ---------------------------------------------------------------------------
// Frozen constants
// ---------------------------------------------------------------------------

/// The linker's call separator, frozen together with the vectors: it opens the preimage and is
/// this construction's one versioned domain.
const FROZEN_DSEP: [u8; 8] = *b"SOLLNK01";

/// The list-setting separator the KMS list hash prepends ahead of the call separator.
const FROZEN_DSEP_LIST: [u8; 8] = *b"HASH_LST";

/// The linker's scheme and version tag — the versioned name of this construction.
const FROZEN_SCHEME_TAG: &str = "SolanaUserDecryptionLinker:v1";

/// Its length. Frozen as its own fact: every element before the transport key has a
/// position-determined width, and that is what makes the list construction injective.
const FROZEN_SCHEME_TAG_LEN: usize = 29;

/// Tag of the deployment-time chain-id derivation rule, frozen with the vector schema.
///
/// Not used by any KMS code path — a party reads the chain id out of the handles — but the vectors
/// pair a genesis hash with a derived id, and a change to the tag would silently change every
/// published pair.
const FROZEN_CHAIN_ID_DERIVATION_TAG: &str = "zama-solana-chain-id-v1";

/// The linker digest over [`frozen_request`]. Frozen: see the module comment.
const FROZEN_LINK: &str = "a5378dec03acd0455d38fe7a57bc07f1a71aa7cb1ad7d7462e3983b3de17212e";

// ---------------------------------------------------------------------------
// The frozen fixture, spelled out
// ---------------------------------------------------------------------------

/// The same host chain number as the EVM freeze fixture, with the Solana chain-kind bit set.
///
/// Deliberate: the two frozen digests are then visibly taken over the same deployment number, and
/// the only thing separating the request families is bit 63 — which is precisely the claim.
const FROZEN_CHAIN_ID: u64 = (1 << 63) | 8006;

const FROZEN_PROGRAM_ID: [u8; SOLANA_IDENTITY_LEN] = [0x22; SOLANA_IDENTITY_LEN];
const FROZEN_RECEIVER: [u8; SOLANA_IDENTITY_LEN] = [0x33; SOLANA_IDENTITY_LEN];
const FROZEN_CONTEXT_ID: [u8; SOLANA_IDENTITY_LEN] = [0x44; SOLANA_IDENTITY_LEN];
const FROZEN_EPOCH_ID: [u8; SOLANA_IDENTITY_LEN] = [0x55; SOLANA_IDENTITY_LEN];

/// Byte range of the chain id embedded in a ciphertext handle, restated locally.
const HANDLE_CHAIN_ID: std::ops::Range<usize> = 22..30;

/// A fixed ciphertext handle: `discriminator` everywhere except the embedded chain id.
fn frozen_handle(discriminator: u8) -> [u8; SOLANA_IDENTITY_LEN] {
    let mut handle = [discriminator; SOLANA_IDENTITY_LEN];
    handle[HANDLE_CHAIN_ID].copy_from_slice(&FROZEN_CHAIN_ID.to_be_bytes());
    handle
}

/// A deterministic 800-byte transport key, matching the EVM freeze fixture's `enc_key` pattern.
/// Opaque to the linker, which hashes it verbatim.
fn frozen_transport_key() -> Vec<u8> {
    (0u16..800).map(|byte| byte as u8).collect()
}

fn frozen_handles() -> [[u8; SOLANA_IDENTITY_LEN]; 2] {
    [frozen_handle(0xa1), frozen_handle(0xa2)]
}

fn frozen_request() -> SolanaUserDecryptBinding {
    let handles = frozen_handles();

    SolanaUserDecryptBinding::new(
        &FROZEN_PROGRAM_ID,
        &FROZEN_RECEIVER,
        &FROZEN_CONTEXT_ID,
        &FROZEN_EPOCH_ID,
        handles.iter().map(|handle| handle.as_slice()),
        &frozen_transport_key(),
    )
    .expect("the frozen Solana request must validate")
}

// ---------------------------------------------------------------------------
// The hand-assembled preimage
// ---------------------------------------------------------------------------

/// The hashed elements, in the order the specified preimage layout lists them, written out rather
/// than derived.
fn expected_elements() -> Vec<Vec<u8>> {
    let mut elements: Vec<Vec<u8>> = vec![
        FROZEN_SCHEME_TAG.as_bytes().to_vec(),
        FROZEN_PROGRAM_ID.to_vec(),
        FROZEN_CHAIN_ID.to_be_bytes().to_vec(),
        FROZEN_RECEIVER.to_vec(),
        FROZEN_CONTEXT_ID.to_vec(),
        FROZEN_EPOCH_ID.to_vec(),
    ];
    elements.extend(frozen_handles().iter().map(|handle| handle.to_vec()));
    elements.push(frozen_transport_key());
    elements
}

/// `HASH_LST ‖ SOLLNK01 ‖ u64le(7 + n) ‖ elements…`, assembled from the specification.
fn expected_hasher_input() -> Vec<u8> {
    let elements = expected_elements();

    let mut input = Vec::new();
    input.extend_from_slice(&FROZEN_DSEP_LIST);
    input.extend_from_slice(&FROZEN_DSEP);
    input.extend_from_slice(&(elements.len() as u64).to_le_bytes());
    for element in &elements {
        input.extend_from_slice(element);
    }
    input
}

/// SHAKE-256 with a 32-byte output, over `bytes` in full.
///
/// The codebase's helper computes `SHAKE256(separator ‖ element)`, so feeding it the input's first
/// eight bytes as the separator and the rest as the element hashes exactly `bytes`. Using the
/// primitive to hash a hand-assembled sequence is allowed by the method above; using the linker to
/// produce the expectation is not.
fn shake256_32(bytes: &[u8]) -> Vec<u8> {
    let (separator, rest) = bytes.split_at(8);
    hash_element_w_size(
        &DomainSep::try_from(separator).expect("split at eight bytes"),
        rest,
        32,
    )
}

/// Offsets into the preimage, in element order. Constants, not computed sums: an offset table that
/// derives itself from the same widths it is checking would move along with a layout change.
mod offset {
    pub const DSEP_LIST: usize = 0;
    pub const DSEP_CALL: usize = 8;
    pub const COUNT: usize = 16;
    pub const SCHEME_TAG: usize = 24;
    pub const PROGRAM_ID: usize = 53;
    pub const CHAIN_ID: usize = 85;
    pub const RECEIVER: usize = 93;
    pub const CONTEXT_ID: usize = 125;
    pub const EPOCH_ID: usize = 157;
    pub const FIRST_HANDLE: usize = 189;
    pub const SECOND_HANDLE: usize = 221;
    pub const TRANSPORT_KEY: usize = 253;
    /// Two handles and an 800-byte transport key.
    pub const TOTAL: usize = 1053;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn the_call_separator_is_frozen() {
    // One explicit versioned domain per cryptographic purpose. This value is now published.
    assert_eq!(&DSEP_SOLANA_LINKER, &FROZEN_DSEP);
    assert_eq!(&DSEP_SOLANA_LINKER, b"SOLLNK01");
    assert_eq!(DSEP_SOLANA_LINKER.len(), 8);
}

#[test]
fn the_scheme_tag_and_its_length_are_frozen() {
    // Length carries meaning of its own: the tag is a fixed-width element, so a shorter or longer
    // one shifts every byte that follows it into the hash.
    assert_eq!(
        SOLANA_LINKER_SCHEME_TAG.as_slice(),
        FROZEN_SCHEME_TAG.as_bytes()
    );
    assert_eq!(SOLANA_LINKER_SCHEME_TAG.len(), FROZEN_SCHEME_TAG_LEN);
    assert_eq!(FROZEN_SCHEME_TAG_LEN, 29);
}

#[test]
fn the_element_layout_sits_at_its_frozen_offsets() {
    // The specified element order and widths, checked against the hand-assembled preimage. A
    // layout change fails here with a legible byte diff before it fails as an opaque digest
    // mismatch below.
    let input = expected_hasher_input();

    assert_eq!(input.len(), offset::TOTAL);
    assert_eq!(
        &input[offset::DSEP_LIST..offset::DSEP_CALL],
        &FROZEN_DSEP_LIST
    );
    assert_eq!(&input[offset::DSEP_CALL..offset::COUNT], &FROZEN_DSEP);
    assert_eq!(
        &input[offset::COUNT..offset::SCHEME_TAG],
        &9u64.to_le_bytes(),
        "seven fixed elements plus two handles, little-endian per the KMS engine convention",
    );
    assert_eq!(
        &input[offset::SCHEME_TAG..offset::PROGRAM_ID],
        FROZEN_SCHEME_TAG.as_bytes(),
    );
    assert_eq!(
        &input[offset::PROGRAM_ID..offset::CHAIN_ID],
        &FROZEN_PROGRAM_ID
    );
    assert_eq!(
        &input[offset::CHAIN_ID..offset::RECEIVER],
        &FROZEN_CHAIN_ID.to_be_bytes(),
        "the chain id is big-endian, the form the handles embed",
    );
    assert_eq!(
        &input[offset::RECEIVER..offset::CONTEXT_ID],
        &FROZEN_RECEIVER
    );
    assert_eq!(
        &input[offset::CONTEXT_ID..offset::EPOCH_ID],
        &FROZEN_CONTEXT_ID
    );
    assert_eq!(
        &input[offset::EPOCH_ID..offset::FIRST_HANDLE],
        &FROZEN_EPOCH_ID
    );
    assert_eq!(
        &input[offset::FIRST_HANDLE..offset::SECOND_HANDLE],
        &frozen_handle(0xa1),
    );
    assert_eq!(
        &input[offset::SECOND_HANDLE..offset::TRANSPORT_KEY],
        &frozen_handle(0xa2),
    );
    assert_eq!(
        &input[offset::TRANSPORT_KEY..],
        frozen_transport_key().as_slice()
    );
}

#[test]
fn the_hand_assembled_preimage_hashes_to_the_frozen_link() {
    // The independent half: SHAKE-256 over bytes this file wrote, with the linker not involved.
    assert_eq!(
        hex::encode(shake256_32(&expected_hasher_input())),
        FROZEN_LINK,
    );
}

#[test]
fn the_linker_digest_is_byte_frozen() {
    // The dependent half: the implementation must agree with the specification read by hand.
    let link = frozen_request().compute_link();

    assert_eq!(link.len(), 32, "the link is 32 bytes");
    assert_eq!(hex::encode(&link), FROZEN_LINK);
}

#[test]
fn the_published_hasher_input_is_the_frozen_preimage() {
    // The vectors publish this field so that implementations can compare their construction before
    // comparing digests. It is frozen with everything else.
    assert_eq!(
        frozen_request().linker_hasher_input(),
        expected_hasher_input(),
    );
}

#[test]
fn the_frozen_chain_id_carries_the_solana_kind_bit() {
    // The backstop that keeps Solana handles off the EVM linker and vice versa. The low bits are
    // the EVM freeze fixture's host chain id, so the two frozen digests cover the same deployment
    // number under two different chain kinds.
    assert_ne!(FROZEN_CHAIN_ID & (1 << 63), 0);
    assert_eq!(FROZEN_CHAIN_ID & !(1u64 << 63), 8006);
    assert_eq!(
        &frozen_handle(0xa1)[HANDLE_CHAIN_ID],
        &FROZEN_CHAIN_ID.to_be_bytes(),
    );
}

#[test]
fn the_published_vector_set_is_frozen_at_the_same_constants() {
    // The freeze and the vectors are one decision. Read as raw text rather than through the vector
    // runner's schema types, so that a rename there cannot quietly relax this.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("solana_linker_v1.json");
    let set = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the published vector set must exist at {path:?}: {error}"));

    for frozen in [
        FROZEN_SCHEME_TAG,
        "SOLLNK01",
        "HASH_LST",
        FROZEN_CHAIN_ID_DERIVATION_TAG,
    ] {
        assert!(
            set.contains(&format!("\"{frozen}\"")),
            "the published set no longer names {frozen}",
        );
    }
}
