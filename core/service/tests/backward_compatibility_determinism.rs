//! Regression tests for byte-stable backward-compatibility fixture serialization.
//!
//! Each test builds a representative fixture object multiple times with fixed
//! entropy and fixed timestamps, then asserts that versionized bincode bytes
//! are identical. The goal is to catch accidental nondeterminism in KMS fixture
//! construction or persisted fields, not to test stdlib container behavior.

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
             ({} bytes vs {} bytes). This usually means an unordered field or \
             ambient input reached fixture construction or serialization.",
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
