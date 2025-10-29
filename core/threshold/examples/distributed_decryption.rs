//! To use the latest version of threshold-fhe in your project,
//! you first need to add it as a dependency in your `Cargo.toml`:
//!
//! ```
//! threshold_fhe = { git = "https://github.com/zama-ai/kms-core.git" }
//! ```
//!
//! This is an example where we setup a testing runtime that runs 4 parties on the same machine.
//! You can run it with `cargo run -F testing --example distributed_decryption`.
use aes_prng::AesRng;
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use tfhe::{set_server_key, FheUint8};
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z64, structure_traits::Ring},
    execution::{
        endpoints::decryption::{threshold_decrypt64, DecryptionMode, RadixOrBoolCiphertext},
        runtime::test_runtime::{generate_fixed_roles, DistributedTestRuntime},
        tfhe_internals::{
            parameters::BC_PARAMS_SNS,
            test_feature::{gen_key_set, keygen_all_party_shares_from_keyset, KeySet},
            utils::expanded_encrypt,
        },
    },
    networking::NetworkMode,
};

#[tokio::main]
async fn main() {
    let num_parties = 4;
    let threshold = 1;
    let mut rng = AesRng::from_entropy();

    // Generate the keys normally, we'll secret share them later.
    let keyset: KeySet = gen_key_set(BC_PARAMS_SNS, tfhe::Tag::default(), &mut rng);
    set_server_key(keyset.public_keys.server_key.clone());

    let params = keyset.get_cpu_params().unwrap();
    let key_shares =
        keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, num_parties, threshold)
            .unwrap();

    // Encrypt a message and extract the raw ciphertexts.
    let message = rng.gen::<u8>();
    let ct: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, message, 8).unwrap();
    let (raw_ct, _id, _tag, _rerand_metadata) = ct.into_raw_parts();
    let raw_ct = RadixOrBoolCiphertext::Radix(raw_ct);

    // Setup the test runtime.
    // Using Sync because threshold_decrypt64 encompasses both online and offline
    let roles = generate_fixed_roles(num_parties);
    let mut runtime = DistributedTestRuntime::<
        ResiduePolyF4Z64,
        { ResiduePolyF4Z64::EXTENSION_DEGREE },
    >::new(roles.clone(), threshold as u8, NetworkMode::Sync, None);

    let server_key = Arc::new(keyset.public_keys.server_key.clone());
    runtime.setup_server_key(server_key);
    runtime.setup_sks(key_shares);

    // Perform distributed decryption.
    let result = threshold_decrypt64(&runtime, &raw_ct, DecryptionMode::NoiseFloodSmall)
        .await
        .unwrap();

    for (_, v) in result {
        assert_eq!(v.0 as u8, message);
    }
}
