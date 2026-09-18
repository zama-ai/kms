//! What the Solana linker binds, demonstrated by changing one thing at a time.
//!
//! The linker exists to make response substitution detectable: a response computed for request A
//! must not verify against request B. Every bound input therefore needs a test showing that
//! changing it alone moves the 32 bytes. An input with no such test is an input that could quietly
//! stop being bound.
//!
//! These tests assert difference, never a particular digest. The bytes are frozen by the published
//! vectors (`core/grpc/test-vectors/solana_linker_v2.json`, `solana_frozen_constants.rs`), but
//! this suite stays digest-free on purpose: difference is the property that survives a deliberate
//! type change, and it is the property a reviewer can check by reading. Every class enumerated here
//! has a matching negative record in the published set — this file says the link *moves*, the
//! vectors say *to what*.
//!
//! What is deliberately absent: `extra_data`. It is not a linker input, so there is no difference
//! to show here; that a change to it leaves the link alone and fails the external response
//! signature instead is tested where that signature is verified, in core/service.

mod common;

use alloy_primitives::{Address, U256};
use common::{CHAIN_ID, RECEIVER, Request, handle, handle_for_chain};

/// Every variant below must produce a link distinct from the canonical one *and* from each other.
fn assert_all_distinct(links: &[(&str, Vec<u8>)]) {
    for (i, (left_name, left)) in links.iter().enumerate() {
        assert_eq!(left.len(), 32, "{left_name} produced a non-32-byte link");
        for (right_name, right) in &links[i + 1..] {
            assert_ne!(left, right, "{left_name} and {right_name} share a link");
        }
    }
}

#[test]
fn swapping_handles_changes_link() {
    // Order is bound: a relayer that reorders a batch produces a request the client did not make,
    // and the mismatch has to surface as a link mismatch rather than as a reordered result.
    let canonical = Request::canonical();
    let swapped = Request::canonical().with_handles(vec![handle(2), handle(1)]);

    assert_ne!(canonical.link(), swapped.link());
}

#[test]
fn inserting_handle_changes_link() {
    let canonical = Request::canonical();
    let inserted = Request::canonical().with_handles(vec![handle(1), handle(3), handle(2)]);

    assert_ne!(canonical.link(), inserted.link());
}

#[test]
fn removing_handle_changes_link() {
    // Oversize input must be rejected, never truncated. The linker is what makes a truncated
    // request detectable instead of silently answered as a request the client never made.
    let canonical = Request::canonical();
    let truncated = Request::canonical().with_handles(vec![handle(1)]);

    assert_ne!(canonical.link(), truncated.link());
}

#[test]
fn duplicate_handle_differs_from_single_occurrence() {
    // Duplicates are legal upstream, so they must be bound positionally rather than collapsed:
    // [h, h] and [h] are different requests and cannot share a link.
    let once = Request::canonical().with_handles(vec![handle(1)]);
    let twice = Request::canonical().with_handles(vec![handle(1), handle(1)]);

    assert_ne!(once.link(), twice.link());
}

#[test]
fn changing_transport_key_changes_link() {
    // The substitution this closes: an attacker swapping in their own transport key would receive
    // the result sealed to a key they hold.
    let canonical = Request::canonical();
    let mut substituted = Request::canonical();
    substituted.transport_key[0] ^= 0xff;

    assert_ne!(canonical.link(), substituted.link());
}

#[test]
fn different_length_transport_key_changes_link() {
    // The key is hashed as `bytes`, so its length is part of what is bound, not just its content.
    let canonical = Request::canonical();
    let mut shorter = Request::canonical();
    shorter.transport_key.pop();

    assert_ne!(canonical.link(), shorter.link());
}

#[test]
fn changing_recipient_changes_link() {
    let canonical = Request::canonical();
    let mut other = Request::canonical();
    other.receiver_id[0] ^= 0xff;

    assert_ne!(canonical.link(), other.link());
}

#[test]
fn same_cluster_other_program_changes_link() {
    // The host program is bound explicitly: the same handles under a different program are a
    // different deployment, even on the same cluster.
    let canonical = Request::canonical();
    let mut other = Request::canonical();
    other.verifying_program_id[0] ^= 0xff;

    assert_ne!(canonical.link(), other.link());
}

#[test]
fn same_program_other_cluster_changes_link() {
    // The host chain has no field of its own: it is bound through bytes [22..30] of every handle,
    // so a second cluster necessarily changes the handles too. That is the deployment identity
    // working as intended — one program id deployed to two clusters yields two distinct links.
    let canonical = Request::canonical();
    let other_cluster = Request::canonical().with_handles(vec![
        handle_for_chain(CHAIN_ID + 1, 1),
        handle_for_chain(CHAIN_ID + 1, 2),
    ]);

    assert_ne!(canonical.link(), other_cluster.link());
}

#[test]
fn changing_domain_changes_link() {
    // The Gateway domain is a link input. A response computed for another Gateway — another
    // contract name, version, chain id or address — answers a different request, and each of the
    // four domain fields must move the link on its own.
    let mut other_name = Request::canonical();
    other_name.domain.name = Some("NotDecryption".into());

    let mut other_version = Request::canonical();
    other_version.domain.version = Some("2".into());

    let mut other_gateway_chain = Request::canonical();
    other_gateway_chain.domain.chain_id = Some(U256::from(54_322u64));

    let mut other_contract = Request::canonical();
    other_contract.domain.verifying_contract = Some(Address::ZERO);

    assert_all_distinct(&[
        ("canonical", Request::canonical().link()),
        ("other domain name", other_name.link()),
        ("other domain version", other_version.link()),
        ("other gateway chain id", other_gateway_chain.link()),
        ("other verifying contract", other_contract.link()),
    ]);
}

#[test]
fn same_width_fields_are_not_interchangeable() {
    // The program id, the receiver and every handle are 32 bytes wide. If any two were hashed in
    // the wrong order, or one were read from the other's slot, this swap would leave the link
    // unchanged.
    let canonical = Request::canonical();

    let mut program_and_receiver_swapped = Request::canonical();
    std::mem::swap(
        &mut program_and_receiver_swapped.verifying_program_id,
        &mut program_and_receiver_swapped.receiver_id,
    );

    assert_ne!(canonical.link(), program_and_receiver_swapped.link());
}

#[test]
fn single_field_variant_links_are_unique() {
    // Pairwise, not just against the canonical request: two different requests colliding with
    // each other is the same failure as either colliding with the original.
    let mut other_receiver = Request::canonical();
    other_receiver.receiver_id[0] ^= 0xff;

    let mut other_program = Request::canonical();
    other_program.verifying_program_id[0] ^= 0xff;

    let mut other_transport = Request::canonical();
    other_transport.transport_key[0] ^= 0xff;

    let mut other_domain = Request::canonical();
    other_domain.domain.chain_id = Some(U256::from(54_322u64));

    assert_all_distinct(&[
        ("canonical", Request::canonical().link()),
        (
            "swapped handles",
            Request::canonical()
                .with_handles(vec![handle(2), handle(1)])
                .link(),
        ),
        (
            "extra handle",
            Request::canonical()
                .with_handles(vec![handle(1), handle(2), handle(3)])
                .link(),
        ),
        (
            "one handle",
            Request::canonical().with_handles(vec![handle(1)]).link(),
        ),
        (
            "duplicated handle",
            Request::canonical()
                .with_handles(vec![handle(1), handle(1)])
                .link(),
        ),
        (
            "other cluster",
            Request::canonical()
                .with_handles(vec![
                    handle_for_chain(CHAIN_ID + 1, 1),
                    handle_for_chain(CHAIN_ID + 1, 2),
                ])
                .link(),
        ),
        ("other receiver", other_receiver.link()),
        ("other program", other_program.link()),
        ("other transport key", other_transport.link()),
        ("other gateway domain", other_domain.link()),
    ]);
}

#[test]
fn recipient_stored_as_raw_key() {
    // The recipient reaches signcryption as the exact 32 bytes the request carried, never a
    // derivative of them: two keys colliding under a hash-and-truncate would be one recipient to
    // signcryption, and the result would be readable by the wrong key.
    assert_eq!(Request::canonical().build().receiver_id(), &RECEIVER);
}
