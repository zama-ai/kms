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
        endpoints::decryption::{threshold_decrypt64, DecryptionMode},
        runtime::test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        tfhe_internals::{
            parameters::BC_PARAMS_SAM_SNS,
            test_feature::{gen_key_set, keygen_all_party_shares, KeySet},
            utils::expanded_encrypt,
        },
    },
    networking::NetworkMode,
};

fn main() {
    let num_parties = 4;
    let threshold = 1;
    let mut rng = AesRng::from_entropy();

    // Generate the keys normally, we'll secret share them later.
    let keyset: KeySet = gen_key_set(BC_PARAMS_SAM_SNS, &mut rng);
    set_server_key(keyset.public_keys.server_key.clone());

    let lwe_secret_key = keyset.get_raw_lwe_client_key();
    let glwe_secret_key = keyset.get_raw_glwe_client_key();
    let glwe_secret_key_sns_as_lwe = keyset.sns_secret_key.key.clone();
    let params = keyset.sns_secret_key.params;
    let key_shares = keygen_all_party_shares(
        lwe_secret_key,
        glwe_secret_key,
        glwe_secret_key_sns_as_lwe,
        params,
        &mut rng,
        num_parties,
        threshold,
    )
    .unwrap();

    // Encrypt a message and extract the raw ciphertexts.
    let message = rng.gen::<u8>();
    let ct: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, message, 8).unwrap();
    let (raw_ct, _id, _tag) = ct.into_raw_parts();

    // Setup the test runtime.
    // Using Sync because threshold_decrypt64 encompasses both online and offline
    let identities = generate_fixed_identities(num_parties);
    let mut runtime = DistributedTestRuntime::<
        ResiduePolyF4Z64,
        { ResiduePolyF4Z64::EXTENSION_DEGREE },
    >::new(identities.clone(), threshold as u8, NetworkMode::Sync, None);

    let keyset_ck = Arc::new(keyset.public_keys.sns_key.clone().unwrap());
    runtime.conversion_keys = Some(keyset_ck.clone());
    runtime.setup_sks(key_shares);

    // Perform distributed decryption.
    let result = threshold_decrypt64(&runtime, &raw_ct, DecryptionMode::NoiseFloodSmall).unwrap();

    for (_, v) in result {
        assert_eq!(v.0 as u8, message);
    }
}
