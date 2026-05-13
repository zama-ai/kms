//! Determinism regression test for types that are serialized into
//! backward-compatibility fixtures.
//!
//! Each test constructs the same struct N times from scratch (with a fixed
//! RNG seed and a fixed timestamp where applicable), serializes each instance
//! with the same encoding the generators use (`bincode::config::legacy()` +
//! `with_fixed_int_encoding()` on top of `Versionize::versionize()`), and
//! asserts every output is byte-identical.
//!
//! The N-repeats pattern is what catches HashMap regressions: each freshly
//! constructed `std::collections::HashMap` allocates a new `RandomState` from
//! the thread-local seed, so a HashMap field that survives into the serialized
//! payload will produce different byte sequences across the N builds even
//! within a single process. BTreeMap (or any sorted/canonical container) does
//! not exhibit this and the bytes stay stable.

use aes_prng::AesRng;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::PubDataType;
use kms_lib::backup::custodian::Custodian;
use kms_lib::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
use kms_lib::cryptography::signatures::gen_sig_keys;
use kms_lib::engine::base::{KeyGenMetadata, KeyGenMetadataInner};
use rand::SeedableRng;
use std::collections::BTreeMap;
use tfhe_versionable::Versionize;
use threshold_types::role::Role;

const REPEATS: usize = 10;
const FIXED_TIMESTAMP: u64 = 1_700_000_000;
const SEED: u64 = 0xdeadbeef;

fn encode_versioned<T: Versionize>(value: &T) -> Vec<u8> {
    // Mirror backward-compatibility/generate-vX.Y.Z/src/generate.rs::save_bcode.
    let versioned = value.versionize();
    let config = bincode::config::legacy().with_fixed_int_encoding();
    bincode::serde::encode_to_vec(&versioned, config).expect("encode")
}

fn assert_all_equal(label: &str, runs: Vec<Vec<u8>>) {
    let first = &runs[0];
    for (i, other) in runs.iter().enumerate().skip(1) {
        assert_eq!(
            first,
            other,
            "{label}: serialization differs between run 0 and run {i} \
             ({} bytes vs {} bytes). This usually means a HashMap or other \
             non-deterministically-ordered container is reaching the wire \
             format. Switch it to BTreeMap (or sort before serializing) and \
             bump the version of the affected struct.",
            first.len(),
            other.len(),
        );
    }
}

fn build_key_gen_metadata_inner() -> KeyGenMetadataInner {
    let mut rng = AesRng::seed_from_u64(SEED);
    let key_id = RequestId::new_random(&mut rng);
    let preprocessing_id = RequestId::new_random(&mut rng);

    let mut digest_map: BTreeMap<PubDataType, Vec<u8>> = BTreeMap::new();
    digest_map.insert(PubDataType::ServerKey, vec![0xAA; 32]);
    digest_map.insert(PubDataType::PublicKey, vec![0xBB; 32]);
    digest_map.insert(PubDataType::CompressedXofKeySet, vec![0xCC; 32]);
    digest_map.insert(PubDataType::DecompressionKey, vec![0xDD; 32]);

    match KeyGenMetadata::new(
        key_id,
        preprocessing_id,
        digest_map,
        vec![0xEE; 64],
        b"extra".to_vec(),
    ) {
        KeyGenMetadata::Current(inner) => inner,
        KeyGenMetadata::LegacyV0(_) => unreachable!("::new constructs Current"),
    }
}

#[test]
fn key_gen_metadata_inner_serialization_is_deterministic() {
    let runs: Vec<Vec<u8>> = (0..REPEATS)
        .map(|_| encode_versioned(&build_key_gen_metadata_inner()))
        .collect();
    assert_all_equal("KeyGenMetadataInner", runs);
}

#[test]
fn internal_custodian_setup_message_serialization_is_deterministic() {
    let runs: Vec<Vec<u8>> = (0..REPEATS)
        .map(|_| {
            let mut rng = AesRng::seed_from_u64(SEED);
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
            let (private_key, public_key) = encryption.keygen().expect("keygen");
            let custodian = Custodian::new(
                Role::indexed_from_one(1),
                signing_key,
                public_key,
                private_key,
            )
            .expect("Custodian::new");
            let setup_message = custodian
                .generate_setup_message_with_timestamp(
                    &mut rng,
                    "custodian-1".to_string(),
                    FIXED_TIMESTAMP,
                )
                .expect("generate_setup_message_with_timestamp");
            encode_versioned(&setup_message)
        })
        .collect();
    assert_all_equal("InternalCustodianSetupMessage", runs);
}
