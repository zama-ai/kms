//! Framing canary for the transport-key container published in the Solana linker vectors.
//!
//! The vector set (`core/grpc/test-vectors/solana_linker_v1.json`) carries its canonical transport
//! key under the name `reference-mlkem-512`: 869 bytes, a genuine tfhe-safe-serialized
//! `UnifiedPublicEncKey::MlKem512` rather than filler of that width. It has to be genuine, because
//! the width is a normative claim — a KMS user-decryption request carries a serialized container of
//! exactly this size, and a fixture that merely asserts "869 bytes" proves nothing about that.
//!
//! It cannot be checked where it is generated. `kms-grpc`, which owns the vector set, does not
//! depend on the encryption or safe-serialization machinery, so the bytes are embedded there as a
//! hex literal produced once, offline, from a fixed seed. This test closes that gap from the side
//! of the tree that *can* deserialize: it reads the committed JSON — the same file five
//! implementations consume, not a locally rebuilt copy — and requires the bytes to still parse.
//!
//! **What a failure here means.** Not "update the constant". If tfhe's safe-serialization framing
//! moves — a header field, a version prefix, a length encoding — this test fails against frozen
//! vector bytes that other repositories are already comparing digests against. That is a
//! cross-repository fixture break and a deliberate regeneration of the set, not an edit.

#![cfg(feature = "non-wasm")]

use std::path::PathBuf;

use kms_lib::consts::SAFE_SER_SIZE_LIMIT;
use kms_lib::cryptography::encryption::UnifiedPublicEncKey;

/// Name of the transport key under test, in the set's `transport_keys` table: the canonical
/// reference key every reference record binds.
const CONTAINER_KEY: &str = "reference-mlkem-512";

/// The width a serialized `UnifiedPublicEncKey::MlKem512` has, and the width a request carries.
const CONTAINER_LEN: usize = 869;

/// The committed set, read as raw text from the sibling crate rather than through any generator.
fn committed_transport_key(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../grpc/test-vectors/solana_linker_v1.json");
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the published vector set must exist at {path:?}: {error}"));

    let set: serde_json::Value = serde_json::from_str(&json).expect("the vector set is valid JSON");
    let hex_key = set["transport_keys"][name]
        .as_str()
        .unwrap_or_else(|| panic!("the set must carry a transport key named {name}"));

    hex::decode(hex_key).expect("a hex transport key")
}

#[test]
fn the_reference_vector_key_is_a_real_serialized_ml_kem_512_container() {
    let bytes = committed_transport_key(CONTAINER_KEY);

    assert_eq!(
        bytes.len(),
        CONTAINER_LEN,
        "the published container is no longer the width a request carries",
    );

    let key: UnifiedPublicEncKey = tfhe::safe_serialization::safe_deserialize(
        std::io::Cursor::new(bytes.as_slice()),
        SAFE_SER_SIZE_LIMIT,
    )
    .expect("the published container must still safe-deserialize; see this file's header");

    assert!(
        matches!(key, UnifiedPublicEncKey::MlKem512(_)),
        "the published container must be the MlKem512 variant",
    );
}

#[test]
fn the_container_re_serializes_to_the_published_bytes() {
    // Round trip, not just parse: a framing change that happened to remain readable would still be
    // a change to bytes another repository compares a digest against, and this catches that too.
    let bytes = committed_transport_key(CONTAINER_KEY);

    let key: UnifiedPublicEncKey = tfhe::safe_serialization::safe_deserialize(
        std::io::Cursor::new(bytes.as_slice()),
        SAFE_SER_SIZE_LIMIT,
    )
    .expect("the published container must safe-deserialize");

    let mut round_tripped = Vec::new();
    tfhe::safe_serialization::safe_serialize(&key, &mut round_tripped, SAFE_SER_SIZE_LIMIT)
        .expect("a container that deserialized must serialize");

    assert_eq!(
        round_tripped, bytes,
        "re-serializing the published container no longer reproduces it",
    );
}
