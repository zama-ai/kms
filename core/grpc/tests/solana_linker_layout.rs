//! Byte layout of Solana linker v1.
//!
//! The expected hasher input is assembled here by hand, element by element, and never by calling
//! the code under test. That is the whole point: the test is meant to read like the specification,
//! so that a layout change fails with a legible byte diff instead of an opaque digest mismatch,
//! and so that nothing can be "fixed" by pasting a new constant.
//!
//! What this file cannot catch, stated plainly: if the implementation and this test share the same
//! misreading of the layout, both agree and both are wrong. Only a second, independent
//! implementation closes that gap — the published vectors and the SDK that consumes them. Until
//! those exist, no digest is hard-coded here: pinning one now would buy confidence this layer
//! cannot supply, and would double the cost of the layout changes that are still expected.

mod common;

use common::{
    CONTEXT_ID, DSEP_LIST, EPOCH_ID, PROGRAM_ID, RECEIVER, Request, handle, shake256_32,
    transport_key,
};
use hashing::{DomainSep, unsafe_hash_list_w_size};
use kms_grpc::solana_binding::{
    DSEP_SOLANA_LINKER, SOLANA_LINKER_SCHEME_TAG, SolanaUserDecryptBinding,
};

use common::CHAIN_ID;

/// Offsets into the hasher input, in the order the elements are hashed.
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
    /// First handle; handles run to the end, followed by the transport key.
    pub const HANDLES: usize = 189;
}

/// The hashed elements, in order, as the specification lists them.
fn expected_elements(handles: &[[u8; 32]]) -> Vec<Vec<u8>> {
    let mut elements: Vec<Vec<u8>> = vec![
        SOLANA_LINKER_SCHEME_TAG.to_vec(),
        PROGRAM_ID.to_vec(),
        CHAIN_ID.to_be_bytes().to_vec(),
        RECEIVER.to_vec(),
        CONTEXT_ID.to_vec(),
        EPOCH_ID.to_vec(),
    ];
    elements.extend(handles.iter().map(|handle| handle.to_vec()));
    elements.push(transport_key());
    elements
}

/// The full byte sequence the hasher consumes, assembled from the specification by hand.
fn expected_hasher_input(handles: &[[u8; 32]]) -> Vec<u8> {
    let elements = expected_elements(handles);

    let mut input = Vec::new();
    input.extend_from_slice(&DSEP_LIST);
    input.extend_from_slice(&DSEP_SOLANA_LINKER);
    input.extend_from_slice(&(elements.len() as u64).to_le_bytes());
    for element in &elements {
        input.extend_from_slice(element);
    }
    input
}

fn hasher_input(handles: &[[u8; 32]]) -> Vec<u8> {
    Request::canonical()
        .with_handles(handles.to_vec())
        .build()
        .linker_hasher_input()
}

#[test]
fn list_hash_helper_matches_the_specified_construction() {
    // Pins the specification's description of the shared helper: `HASH_LST ‖ call separator ‖
    // u64le(element count) ‖ elements`, SHAKE-256 to 32 bytes. Independent of the linker, so this
    // stays green throughout; if it ever fails, the layout tests below are measuring the wrong
    // construction and the specification, not the linker, is what needs revisiting.
    let dsep: DomainSep = *b"TESTTEST";
    let first = [0xaau8; 4];
    let second = [0xbbu8; 6];

    let mut manual = Vec::new();
    manual.extend_from_slice(&DSEP_LIST);
    manual.extend_from_slice(&dsep);
    manual.extend_from_slice(&2u64.to_le_bytes());
    manual.extend_from_slice(&first);
    manual.extend_from_slice(&second);

    assert_eq!(
        unsafe_hash_list_w_size(&dsep, &[first.as_slice(), second.as_slice()], 32),
        shake256_32(&manual),
    );
}

#[test]
fn hasher_input_is_exactly_the_specified_layout() {
    let handles = [handle(1), handle(2)];

    assert_eq!(hasher_input(&handles), expected_hasher_input(&handles));
}

#[test]
fn link_is_shake256_of_the_hasher_input() {
    // Ties the two published artifacts together: the vector's "hasher input bytes" field must be
    // what the digest is actually taken over, otherwise a consumer reproducing the input would
    // reproduce a different digest and have no way to tell which side is wrong.
    let binding = Request::canonical().build();

    assert_eq!(
        binding.compute_link(),
        shake256_32(&binding.linker_hasher_input()),
    );
}

#[test]
fn link_matches_the_shared_list_hash_helper() {
    // The linker must be the codebase's list hash over the specified elements — not a private
    // re-implementation that happens to agree today.
    let handles = [handle(1), handle(2)];
    let elements = expected_elements(&handles);
    let element_refs: Vec<&[u8]> = elements.iter().map(|element| element.as_slice()).collect();

    assert_eq!(
        Request::canonical().link(),
        unsafe_hash_list_w_size(&DSEP_SOLANA_LINKER, &element_refs, 32),
    );
}

#[test]
fn element_count_is_seven_plus_the_handle_count_little_endian() {
    // Six fixed elements plus the transport key, plus one per handle. The count is what makes the
    // construction injective for the reader: everything before the last element has a
    // position-determined length, so `n = count - 7` recovers the handle count exactly.
    for handle_count in [1usize, 2, 5] {
        let handles: Vec<[u8; 32]> = (0..handle_count).map(|i| handle(i as u8)).collect();
        let input = hasher_input(&handles);

        assert_eq!(
            &input[offset::COUNT..offset::COUNT + 8],
            &(7 + handle_count as u64).to_le_bytes(),
            "the element count is little-endian, per the KMS engine convention",
        );
    }
}

#[test]
fn chain_id_element_is_big_endian_u64() {
    // Deliberate asymmetry with the element count above: the chain id is big-endian because that
    // is the form embedded in ciphertext handles, while the count follows the hashing helper's
    // little-endian convention. Both are pinned so neither can drift into the other.
    let input = hasher_input(&[handle(1)]);

    assert_eq!(
        &input[offset::CHAIN_ID..offset::CHAIN_ID + 8],
        &CHAIN_ID.to_be_bytes(),
    );
    assert_eq!(
        &input[offset::CHAIN_ID..offset::CHAIN_ID + 8],
        &handle(1)[22..30],
        "the linker's chain id is the one the handles embed",
    );
}

#[test]
fn separators_and_scheme_tag_open_the_input() {
    let input = hasher_input(&[handle(1)]);

    assert_eq!(&input[offset::DSEP_LIST..offset::DSEP_LIST + 8], &DSEP_LIST);
    assert_eq!(
        &input[offset::DSEP_CALL..offset::DSEP_CALL + 8],
        &DSEP_SOLANA_LINKER,
    );
    assert_eq!(
        &input[offset::SCHEME_TAG..offset::PROGRAM_ID],
        SOLANA_LINKER_SCHEME_TAG.as_slice(),
        "the scheme tag is the first hashed element, immediately after the count",
    );
}

#[test]
fn fixed_width_elements_sit_at_their_specified_offsets() {
    let input = hasher_input(&[handle(1)]);

    assert_eq!(&input[offset::PROGRAM_ID..offset::CHAIN_ID], &PROGRAM_ID);
    assert_eq!(&input[offset::RECEIVER..offset::CONTEXT_ID], &RECEIVER);
    assert_eq!(&input[offset::CONTEXT_ID..offset::EPOCH_ID], &CONTEXT_ID);
    assert_eq!(&input[offset::EPOCH_ID..offset::HANDLES], &EPOCH_ID);
}

#[test]
fn handles_are_hashed_in_request_order_before_the_transport_key() {
    let handles = [handle(1), handle(2), handle(3)];
    let input = hasher_input(&handles);

    for (index, handle) in handles.iter().enumerate() {
        let start = offset::HANDLES + index * 32;
        assert_eq!(&input[start..start + 32], handle, "handle {index}");
    }

    let transport_start = offset::HANDLES + handles.len() * 32;
    assert_eq!(&input[transport_start..], transport_key().as_slice());
}

#[test]
fn the_transport_key_is_the_only_variable_length_element() {
    // The list hash guarantees injectivity for at most one variable-length element, and only if it
    // is unambiguous where that element starts. Every element before it has a constant length, so
    // the input length is a function of the handle count and the transport key length alone.
    for transport_len in [1usize, 800, 1_568] {
        let mut request = Request::canonical();
        request.transport_key = vec![0x66; transport_len];

        assert_eq!(
            request.build().linker_hasher_input().len(),
            offset::HANDLES + request.handles.len() * 32 + transport_len,
        );
    }
}

#[test]
fn link_is_thirty_two_bytes_and_deterministic() {
    let link = Request::canonical().link();

    assert_eq!(link.len(), 32);
    assert_eq!(link, Request::canonical().link());
}

#[test]
fn the_binding_exposes_the_validated_request_back_to_its_caller() {
    // The adapter reads the recipient and chain id back off the binding rather than keeping its
    // own copies, so a value that failed validation cannot reach signcryption by a side path.
    let binding: SolanaUserDecryptBinding = Request::canonical().build();

    assert_eq!(binding.receiver_id(), &RECEIVER);
    assert_eq!(binding.chain_id(), CHAIN_ID);
    assert_eq!(binding.handles(), &[handle(1), handle(2)]);
}
