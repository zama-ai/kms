use aes_prng::AesRng;
use algebra::{
    PRSSConversions,
    galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
    structure_traits::{ErrorCorrect, Invert},
};
use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use rand::SeedableRng;
use std::{hint::black_box, sync::Arc};
use tfhe::{FheUint8, set_server_key, shortint::atomic_pattern::AtomicPatternServerKey};
use threshold_execution::{
    config::BatchParams,
    constants::REAL_KEY_PATH,
    endpoints::decryption::{DecryptionMode, RadixOrBoolCiphertext, threshold_decrypt64},
    runtime::{
        sessions::small_session::SmallSession,
        test_runtime::{DistributedTestRuntime, generate_fixed_roles},
    },
    small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
    tests::{ensure_real_keys_setup, helper::tests_and_benches::execute_protocol_small},
    tfhe_internals::{
        test_feature::{KeySet, keygen_all_party_shares_from_client_key},
        utils::expanded_encrypt,
    },
};
use threshold_types::network::NetworkMode;

fn bench_preprocessing<Z: ErrorCorrect + Invert + PRSSConversions>(c: &mut Criterion, ring: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group(format!("prss_protocols/preprocessing/{ring}"));
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.throughput(Throughput::Elements(10_000));
    for (parties, threshold) in [(4, 1), (13, 4)] {
        group.bench_function(
            BenchmarkId::new(format!("parties_{parties}_threshold_{threshold}"), 10_000),
            |b| {
                b.iter(|| {
                let mut preprocess = |mut session: SmallSession<Z>, _: Option<String>| async move {
                    black_box(SecureSmallPreprocessing::default()
                        .execute(&mut session, BatchParams { triples: 10_000, randoms: 0 })
                        .await.unwrap());
                };
                // Include local session setup and protocol communication; setup uses the test runtime.
                let completed = rt.block_on(execute_protocol_small::<_, _, Z, 4>(
                    parties, threshold, None, NetworkMode::Sync, None, &mut preprocess, None,
                ));
                assert_eq!(completed.len(), parties, "a preprocessing party failed");
            });
            },
        );
    }
    group.finish();
}

fn bench_decryption<Z: ErrorCorrect + Invert + PRSSConversions>(
    c: &mut Criterion,
    ring: &str,
    mode: DecryptionMode,
) {
    ensure_real_keys_setup();
    let keyset: KeySet = test_utils::read_element(REAL_KEY_PATH).unwrap();
    set_server_key(keyset.public_keys.server_key.clone());
    let mut rng = AesRng::seed_from_u64(42);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut group = c.benchmark_group(format!("prss_protocols/decryption/{ring}"));
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));
    for (parties, threshold) in [(4, 1), (13, 4)] {
        let key_shares = keygen_all_party_shares_from_client_key::<_, 4>(
            &keyset.client_key,
            keyset.get_cpu_params().unwrap(),
            &mut rng,
            parties,
            threshold,
        )
        .unwrap();
        let encrypted: FheUint8 =
            expanded_encrypt(&keyset.public_keys.public_key, 42_u64, 8).unwrap();
        let (ciphertext, _, _, _) = encrypted.into_raw_parts();
        let ciphertext = RadixOrBoolCiphertext::Radix(ciphertext);
        let mut runtime = DistributedTestRuntime::<Z, _, 4>::new(
            generate_fixed_roles(parties),
            threshold as u8,
            NetworkMode::Sync,
            None,
        );
        runtime.setup_server_key(Arc::new(keyset.public_keys.server_key.clone()));
        runtime.setup_sks(key_shares);
        if matches!(mode, DecryptionMode::BitDecSmall) {
            let AtomicPatternServerKey::Standard(key) = &keyset
                .public_keys
                .server_key
                .as_ref()
                .as_ref()
                .atomic_pattern
            else {
                panic!("benchmark requires standard atomic-pattern key material");
            };
            runtime.setup_ks(Arc::new(key.key_switching_key.clone()));
        }
        // Key material and encryption are outside timing; decryption includes its preprocessing.
        group.bench_function(
            BenchmarkId::new(format!("parties_{parties}_threshold_{threshold}"), "uint8"),
            |b| {
                b.iter(|| {
                    let plaintexts = rt
                        .block_on(threshold_decrypt64(&runtime, &ciphertext, mode))
                        .unwrap();
                    assert_eq!(plaintexts.len(), parties, "a decryption party failed");
                    for plaintext in plaintexts.values() {
                        assert_eq!(plaintext.0, 42);
                    }
                    black_box(plaintexts);
                });
            },
        );
    }
    group.finish();
}

fn bench_protocols(c: &mut Criterion) {
    bench_preprocessing::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_preprocessing::<ResiduePolyF4Z128>(c, "f4_z128");
    bench_decryption::<ResiduePolyF4Z64>(c, "f4_z64_bitdec", DecryptionMode::BitDecSmall);
    bench_decryption::<ResiduePolyF4Z128>(
        c,
        "f4_z128_noise_flood",
        DecryptionMode::NoiseFloodSmall,
    );
}
criterion_group!(protocols, bench_protocols);
criterion_main!(protocols);
