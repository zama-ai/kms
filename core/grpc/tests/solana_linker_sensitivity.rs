//! What the Solana linker binds, demonstrated by changing one thing at a time.
//!
//! The linker exists to make response substitution detectable: a response computed for request A
//! must not verify against request B. Every bound field therefore needs a test showing that
//! changing it alone moves the 32 bytes. A field with no such test is a field that could quietly
//! stop being bound.
//!
//! These tests assert difference, never a particular digest — the layout is not frozen until the
//! vectors are published, and difference is the property that survives a layout change.

mod common;

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
fn swapping_two_handles_changes_the_link() {
    // Order is bound: a relayer that reorders a batch produces a request the client did not make,
    // and the mismatch has to surface as a link mismatch rather than as a reordered result.
    let canonical = Request::canonical();
    let swapped = Request::canonical().with_handles(vec![handle(2), handle(1)]);

    assert_ne!(canonical.link(), swapped.link());
}

#[test]
fn inserting_a_handle_changes_the_link() {
    let canonical = Request::canonical();
    let inserted = Request::canonical().with_handles(vec![handle(1), handle(3), handle(2)]);

    assert_ne!(canonical.link(), inserted.link());
}

#[test]
fn removing_a_handle_changes_the_link() {
    // Oversize input must be rejected, never truncated. The linker is what makes a truncated
    // request detectable instead of silently answered as a request the client never made.
    let canonical = Request::canonical();
    let truncated = Request::canonical().with_handles(vec![handle(1)]);

    assert_ne!(canonical.link(), truncated.link());
}

#[test]
fn a_duplicated_handle_differs_from_a_single_occurrence() {
    // Duplicates are legal upstream, so they must be bound positionally rather than collapsed:
    // [h, h] and [h] are different requests and cannot share a link.
    let once = Request::canonical().with_handles(vec![handle(1)]);
    let twice = Request::canonical().with_handles(vec![handle(1), handle(1)]);

    assert_ne!(once.link(), twice.link());
}

#[test]
fn changing_the_transport_key_changes_the_link() {
    // The substitution this closes: an attacker swapping in their own transport key would receive
    // the result sealed to a key they hold.
    let canonical = Request::canonical();
    let mut substituted = Request::canonical();
    substituted.transport_key[0] ^= 0xff;

    assert_ne!(canonical.link(), substituted.link());
}

#[test]
fn a_transport_key_of_a_different_length_changes_the_link() {
    let canonical = Request::canonical();
    let mut shorter = Request::canonical();
    shorter.transport_key.pop();

    assert_ne!(canonical.link(), shorter.link());
}

#[test]
fn changing_the_recipient_changes_the_link() {
    let canonical = Request::canonical();
    let mut other = Request::canonical();
    other.receiver_id[0] ^= 0xff;

    assert_ne!(canonical.link(), other.link());
}

#[test]
fn changing_the_verifying_program_id_changes_the_link() {
    // One half of the deployment domain: the same handles under a different program are a
    // different deployment, even on the same cluster.
    let canonical = Request::canonical();
    let mut other = Request::canonical();
    other.verifying_program_id[0] ^= 0xff;

    assert_ne!(canonical.link(), other.link());
}

#[test]
fn changing_the_chain_id_changes_the_link() {
    // The other half, and it does not travel as its own field: it is read out of the handles, so
    // this variant necessarily changes the handles too. That is the deployment pair working as
    // intended — one program id deployed to two clusters yields two distinct links.
    let canonical = Request::canonical();
    let other_cluster = Request::canonical().with_handles(vec![
        handle_for_chain(CHAIN_ID + 1, 1),
        handle_for_chain(CHAIN_ID + 1, 2),
    ]);

    assert_ne!(canonical.link(), other_cluster.link());
}

#[test]
fn changing_the_kms_context_changes_the_link() {
    // The party set that produced the result. A response from a different context answers a
    // different question, however similar the request looks.
    let canonical = Request::canonical();
    let mut other = Request::canonical();
    other.kms_context_id[0] ^= 0xff;

    assert_ne!(canonical.link(), other.link());
}

#[test]
fn changing_the_kms_epoch_changes_the_link() {
    let canonical = Request::canonical();
    let mut other = Request::canonical();
    other.kms_epoch_id[0] ^= 0xff;

    assert_ne!(canonical.link(), other.link());
}

#[test]
fn same_width_fields_are_not_interchangeable() {
    // Five elements are 32 bytes wide. If any two were hashed in the wrong order, or one were
    // read from the other's slot, this swap would leave the link unchanged.
    let canonical = Request::canonical();

    let mut context_and_epoch_swapped = Request::canonical();
    std::mem::swap(
        &mut context_and_epoch_swapped.kms_context_id,
        &mut context_and_epoch_swapped.kms_epoch_id,
    );

    let mut program_and_receiver_swapped = Request::canonical();
    std::mem::swap(
        &mut program_and_receiver_swapped.verifying_program_id,
        &mut program_and_receiver_swapped.receiver_id,
    );

    assert_ne!(canonical.link(), context_and_epoch_swapped.link());
    assert_ne!(canonical.link(), program_and_receiver_swapped.link());
    assert_ne!(
        context_and_epoch_swapped.link(),
        program_and_receiver_swapped.link(),
    );
}

#[test]
fn no_two_single_field_variants_share_a_link() {
    // Pairwise, not just against the canonical request: two different requests colliding with
    // each other is the same failure as either colliding with the original.
    let mut other_receiver = Request::canonical();
    other_receiver.receiver_id[0] ^= 0xff;

    let mut other_program = Request::canonical();
    other_program.verifying_program_id[0] ^= 0xff;

    let mut other_context = Request::canonical();
    other_context.kms_context_id[0] ^= 0xff;

    let mut other_epoch = Request::canonical();
    other_epoch.kms_epoch_id[0] ^= 0xff;

    let mut other_transport = Request::canonical();
    other_transport.transport_key[0] ^= 0xff;

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
        ("other context", other_context.link()),
        ("other epoch", other_epoch.link()),
        ("other transport key", other_transport.link()),
    ]);
}

#[test]
fn the_recipient_is_stored_as_the_raw_key() {
    // The recipient reaches signcryption as the exact 32 bytes the request carried, never a
    // derivative of them: two keys colliding under a hash-and-truncate would be one recipient to
    // signcryption, and the result would be readable by the wrong key.
    assert_eq!(Request::canonical().build().receiver_id(), &RECEIVER);
}
