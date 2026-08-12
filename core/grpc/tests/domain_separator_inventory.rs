//! Inventory of the codebase's hashing domain separators.
//!
//! Every hash in this codebase is domain-separated by an 8-byte call separator, and the separator
//! is what keeps two hashes over similar material from being the same hash. Two purposes sharing a
//! separator is therefore a cryptographic defect, not a naming collision — and it is invisible in
//! review, because the two declarations live in different crates and nobody diffs them together.
//!
//! So the separators are enumerated here, and a scan of the tree must agree with the enumeration
//! exactly. Adding a separator anywhere fails this test until it is written down next to the
//! others, which is the moment a collision becomes obvious.
//!
//! This file is green from its first run: it constrains what may exist, not what the linker
//! computes.

use std::collections::BTreeMap;

use hashing::DSEP_LEN;
use kms_grpc::solana_binding::DSEP_SOLANA_LINKER;

mod common;

use common::rust_sources;

/// Whether a separator is part of the shipped system or belongs to a test fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Production,
    TestFixture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Separator {
    value: &'static str,
    path: &'static str,
    kind: Kind,
}

impl Separator {
    const fn new(value: &'static str, path: &'static str, kind: Kind) -> Self {
        Self { value, path, kind }
    }
}

/// Every `DomainSep` declared in the workspace, sorted by value.
///
/// The linker's separator, `SOLLNK01`, is frozen: it was published together with the normative
/// vectors in `core/grpc/test-vectors/solana_linker_v1.json`, so it can no longer change at all —
/// a new construction takes a new separator and a new scheme-tag version. Every other entry may
/// still move, but never into a value already listed here, which is what this file is for.
const INVENTORY: &[Separator] = &[
    Separator::new(
        "AGREERND",
        "core/threshold-execution/src/small_execution/agree_random.rs",
        Kind::Production,
    ),
    Separator::new(
        "BKUPCOMM",
        "core/service/src/backup/operator.rs",
        Kind::Production,
    ),
    Separator::new(
        "BKUPCUST",
        "core/service/src/backup/custodian.rs",
        Kind::Production,
    ),
    Separator::new(
        "BKUPRECO",
        "core/service/src/backup/operator.rs",
        Kind::Production,
    ),
    Separator::new(
        "BRACHABC",
        "core/threshold-execution/src/network_value.rs",
        Kind::Production,
    ),
    Separator::new(
        "COMMTMNT",
        "core/threshold-algebra/src/commitment.rs",
        Kind::Production,
    ),
    Separator::new(
        "CRS_UPDA",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ENTROPY_",
        "core/service/src/bin/kms-custodian.rs",
        Kind::Production,
    ),
    Separator::new("EQUALITY", "core-client/src/backup.rs", Kind::Production),
    Separator::new(
        "HASH_LST",
        "core/threshold-hashing/src/lib.rs",
        Kind::Production,
    ),
    Separator::new(
        "LDSHARNG",
        "core/threshold-algebra/src/structure_traits.rs",
        Kind::Production,
    ),
    Separator::new(
        "MNEM_ENC",
        "core/service/src/backup/seed_phrase.rs",
        Kind::Production,
    ),
    Separator::new(
        "MNEM_SIG",
        "core/service/src/backup/seed_phrase.rs",
        Kind::Production,
    ),
    Separator::new(
        "PDAT_CRS",
        "core/service/src/engine/base.rs",
        Kind::Production,
    ),
    Separator::new(
        "PDAT_KEY",
        "core/service/src/engine/base.rs",
        Kind::Production,
    ),
    Separator::new(
        "PUBL_DEC",
        "core/service/src/engine/validation_non_wasm.rs",
        Kind::Production,
    ),
    Separator::new(
        "REQST_ID",
        "core/service/src/engine/base.rs",
        Kind::Production,
    ),
    Separator::new(
        "SESSN_ID",
        "core/threshold-types/src/session_id.rs",
        Kind::Production,
    ),
    Separator::new(
        "SIGCTEST",
        "core/service/src/cryptography/signcryption.rs",
        Kind::TestFixture,
    ),
    Separator::new(
        "SIGNCRYP",
        "core/service/src/cryptography/signcryption.rs",
        Kind::Production,
    ),
    Separator::new(
        "SOLLNK01",
        "core/grpc/src/solana_binding.rs",
        Kind::Production,
    ),
    Separator::new(
        "TESTTEST",
        "core/grpc/tests/solana_linker_layout.rs",
        Kind::TestFixture,
    ),
    Separator::new(
        "TFHE_GEN",
        "core/threshold-execution/src/endpoints/keygen.rs",
        Kind::Production,
    ),
    Separator::new(
        "USER_DEC",
        "core/service/src/engine/validation_wasm.rs",
        Kind::Production,
    ),
    Separator::new(
        "VCProve2",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHASH_R",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHASH_T",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHASH_W",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHASH_Z",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHASH__",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHASH_p",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHAS_XI",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHA_CHI",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKHA_PHI",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZKLINMAP",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "ZK_AGGRE",
        "core/threshold-execution/src/zk/constants.rs",
        Kind::Production,
    ),
    Separator::new(
        "_HANDLE_",
        "core/service/src/engine/base.rs",
        Kind::Production,
    ),
    Separator::new(
        "test_1__",
        "core/threshold-hashing/src/lib.rs",
        Kind::TestFixture,
    ),
    Separator::new(
        "test_2__",
        "core/threshold-hashing/src/lib.rs",
        Kind::TestFixture,
    ),
];

/// The declaration form the scan looks for.
///
/// Assembled from pieces so that the needle does not appear literally in this file: a scanner that
/// matches its own source reports a separator that does not exist, and the first person to see the
/// failure would go looking for it in the wrong place.
fn needle() -> String {
    ["DomainSep", " = *b", "\""].concat()
}

/// Every separator declared in the tree, as `(value, workspace-relative path)`.
fn scan() -> Vec<(String, String)> {
    let needle = needle();
    let mut found = Vec::new();

    for (path, contents) in rust_sources() {
        for (offset, _) in contents.match_indices(&needle) {
            let rest = &contents[offset + needle.len()..];
            let end = rest
                .find('"')
                .unwrap_or_else(|| panic!("unterminated separator literal in {path}"));
            found.push((rest[..end].to_string(), path.clone()));
        }
    }

    found.sort();
    found
}

fn inventory_entries() -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = INVENTORY
        .iter()
        .map(|separator| (separator.value.to_string(), separator.path.to_string()))
        .collect();
    entries.sort();
    entries
}

#[test]
fn every_declaration_in_the_tree_is_inventoried() {
    let found = scan();
    let inventoried = inventory_entries();

    let missing: Vec<_> = found
        .iter()
        .filter(|entry| !inventoried.contains(entry))
        .collect();
    let stale: Vec<_> = inventoried
        .iter()
        .filter(|entry| !found.contains(entry))
        .collect();

    assert!(
        missing.is_empty(),
        "domain separators declared but not inventoried: {missing:#?}\n\
         Add them to INVENTORY in this file, and check the new value against the list while doing \
         so — that check is the reason this test exists.",
    );
    assert!(
        stale.is_empty(),
        "inventoried separators no longer declared: {stale:#?}\n\
         Remove them from INVENTORY. A stale entry silently reserves a value nothing uses.",
    );
}

#[test]
fn no_two_purposes_share_a_separator() {
    let mut by_value: BTreeMap<&str, Vec<&Separator>> = BTreeMap::new();
    for separator in INVENTORY {
        by_value.entry(separator.value).or_default().push(separator);
    }

    // No exceptions: a test that needs a production separator imports it — the fixtures
    // re-export `hashing::DSEP_LIST` instead of restating it — and a test that needs its own
    // domain declares a fresh value.
    for (value, declarations) in by_value {
        assert_eq!(
            declarations.len(),
            1,
            "separator {value:?} is declared for more than one purpose: {declarations:#?}\n\
             Two purposes sharing a separator hash into each other's domain; pick a fresh value.",
        );
    }
}

#[test]
fn the_linker_separator_is_unique_and_declared_once() {
    let linker = std::str::from_utf8(&DSEP_SOLANA_LINKER).expect("ASCII");

    let declarations: Vec<_> = INVENTORY
        .iter()
        .filter(|separator| separator.value == linker)
        .collect();

    assert_eq!(
        declarations.len(),
        1,
        "the linker separator must be declared exactly once: {declarations:#?}",
    );
    assert_eq!(
        declarations[0].path, "core/grpc/src/solana_binding.rs",
        "the linker separator belongs beside the construction it separates",
    );
    assert_eq!(declarations[0].kind, Kind::Production);
}

#[test]
fn the_linker_separator_constant_matches_its_inventory_entry() {
    // Ties the code to the list: renaming the constant's value without touching the inventory
    // would otherwise leave the collision check guarding a value nothing uses.
    assert_eq!(&DSEP_SOLANA_LINKER, b"SOLLNK01");
    assert!(
        INVENTORY
            .iter()
            .any(|separator| separator.value == "SOLLNK01"),
    );
}

#[test]
fn every_separator_is_exactly_eight_bytes() {
    // The width is what makes the separator a fixed-length prefix. A shorter or longer one would
    // shift everything that follows it into the hash, and two purposes could then collide by
    // prefix rather than by value.
    for separator in INVENTORY {
        assert_eq!(
            separator.value.len(),
            DSEP_LEN,
            "separator {:?} in {} is not {DSEP_LEN} bytes",
            separator.value,
            separator.path,
        );
    }
}
