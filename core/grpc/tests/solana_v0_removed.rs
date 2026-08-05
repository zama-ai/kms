//! Linker v0 does not exist.
//!
//! v0 is deleted rather than deprecated: it shipped nowhere, carries no compatibility obligation,
//! and a second live construction for the same purpose is exactly the shape that lets a fix be
//! bypassed by downgrading. Compilation is the primary evidence — a deleted symbol cannot be
//! called — but compilation says nothing about the residue: doc comments describing the old
//! construction, a receiver derivation copied into a client, a tag left in a string. Residue is
//! what makes a reader believe the old thing is still the contract, so it is scanned for here.
//!
//! **Names in this file are spelled in pieces.** A scanner that contains the strings it forbids
//! reports itself, and the reader chases a phantom. If a future edit spells one of them literally
//! in a comment here, these tests fail — correctly: the rule is that the name is gone from the
//! tree, and this file is part of the tree.
//!
//! Out of scope: the attestation tag of the old transport path. It is deleted by the
//! specification too, but it belongs to the relayer, and the end-to-end test that still names it
//! stays transport-stale until that work lands.

mod common;

use common::rust_sources;

/// Sanity bound on the corpus: a scan that finds nothing because it read nothing is a scan that
/// passes forever. Every absence assertion below is only meaningful above this floor.
const MINIMUM_SOURCE_FILES: usize = 200;

/// The v0 helper that computed a link without validating anything.
fn v0_link_helper() -> String {
    ["compute_link", "_solana"].concat()
}

/// The v0 scheme tag.
fn v0_scheme_tag() -> String {
    ["SolanaUserDecryptionLinker", ":v0"].concat()
}

/// The server-side derivation that turned a 32-byte wallet key into a 20-byte pseudo-address.
fn v0_client_id_helper() -> String {
    ["solana_user_decrypt", "_client_id"].concat()
}

/// The tail of a hash-and-truncate identity derivation.
fn truncation_suffix() -> String {
    ["[12", "..]"].concat()
}

fn sources() -> Vec<(String, String)> {
    let sources = rust_sources();
    assert!(
        sources.len() >= MINIMUM_SOURCE_FILES,
        "the scan found only {} source files; it is not reading the tree, so every absence \
         assertion in this file is vacuous",
        sources.len(),
    );
    sources
}

/// Files that mention Solana at all — the only ones the identity rule applies to.
fn solana_sources() -> Vec<(String, String)> {
    let solana: Vec<_> = sources()
        .into_iter()
        .filter(|(path, contents)| {
            path.to_lowercase().contains("solana") || contents.to_lowercase().contains("solana")
        })
        .collect();

    assert!(
        !solana.is_empty(),
        "no source mentions Solana, so the identity rule below is checking nothing",
    );
    solana
}

fn hits(needle: &str) -> Vec<String> {
    sources()
        .into_iter()
        .filter(|(_, contents)| contents.contains(needle))
        .map(|(path, _)| path)
        .collect()
}

#[test]
fn the_unchecked_v0_link_helper_is_gone() {
    // It computed a link from unvalidated inputs, which is the thing the checked type exists to
    // make impossible. While it exists, a caller can still reach past validation by accident.
    let needle = v0_link_helper();
    let found = hits(&needle);

    assert!(
        found.is_empty(),
        "{needle} still appears in: {found:#?}\n\
         Linker v0 is deleted, not deprecated — including the doc comments that describe it.",
    );
}

#[test]
fn the_v0_scheme_tag_is_gone() {
    let needle = v0_scheme_tag();
    let found = hits(&needle);

    assert!(
        found.is_empty(),
        "the v0 scheme tag still appears in: {found:#?}\n\
         One explicit versioned domain per purpose; the retired one leaves with its code.",
    );
}

#[test]
fn the_server_side_truncated_receiver_derivation_is_gone() {
    let needle = v0_client_id_helper();
    let found = hits(&needle);

    assert!(
        found.is_empty(),
        "{needle} still appears in: {found:#?}\n\
         The recipient is the raw 32-byte key end to end.",
    );
}

#[test]
fn no_solana_source_derives_an_identity_by_hash_and_truncate() {
    // Two wallet keys colliding under a 20-byte truncation are one recipient to signcryption, and
    // the result becomes readable by the wrong key. The check is scoped to sources that mention
    // Solana: truncation is how an EVM address is legitimately derived, and this rule is about
    // Solana identities, not about the operation.
    let suffix = truncation_suffix();

    let found: Vec<_> = solana_sources()
        .into_iter()
        .filter(|(_, contents)| {
            contents
                .lines()
                .any(|line| line.contains("keccak256") && line.contains(&suffix))
        })
        .map(|(path, _)| path)
        .collect();

    assert!(
        found.is_empty(),
        "a Solana source still derives an identity by hash-and-truncate: {found:#?}\n\
         If a hit is genuinely an EVM derivation that happens to sit in a Solana-aware file, move \
         it rather than widening this rule.",
    );
}

#[test]
fn exactly_one_binding_type_exists() {
    // "One canonical binding function" is the property; two types with the same name in different
    // modules is how it stops being true without anyone deciding to end it.
    let declaration = ["pub struct SolanaUserDecrypt", "Binding"].concat();

    let found = hits(&declaration);

    assert_eq!(
        found,
        vec!["core/grpc/src/solana_binding.rs".to_string()],
        "the binding type must be declared exactly once, beside the linker it owns",
    );
}
