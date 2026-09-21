use aes_prng::AesRng;
use algebra::{
    PRSSConversions,
    galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
    structure_traits::{ErrorCorrect, Invert},
};
use criterion::{
    BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use rand::SeedableRng;
use std::{hint::black_box, sync::Arc};
use tfhe::{
    FheUint8, prelude::SquashNoise, set_server_key,
    shortint::atomic_pattern::AtomicPatternServerKey,
};
use threshold_execution::{
    constants::REAL_KEY_PATH,
    endpoints::decryption::{
        DecryptionMode, LowLevelCiphertextAndKeys, OfflineNoiseFloodSession, RadixOrBoolCiphertext,
        SecureOnlineNoiseFloodDecryption, SmallOfflineNoiseFloodSession, SnsRadixOrBoolCiphertext,
        decrypt_using_noiseflooding, partial_decrypt_using_noiseflooding, threshold_decrypt64,
    },
    runtime::{
        sessions::session_parameters::GenericParameterHandles,
        test_runtime::{DistributedTestRuntime, generate_fixed_roles},
    },
    tests::ensure_real_keys_setup,
    tfhe_internals::{
        test_feature::{KeySet, keygen_all_party_shares_from_client_key},
        utils::expanded_encrypt,
    },
};
use threshold_types::network::NetworkMode;

#[path = "support/protocol.rs"]
mod protocol;

fn bench_preprocessing<Z: ErrorCorrect + Invert + PRSSConversions>(c: &mut Criterion, ring: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group(format!("prss_protocols/preprocessing_prepared/{ring}"));
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.throughput(Throughput::Elements(10_000));
    for (parties, threshold) in [(4, 1), (13, 4)] {
        let mut setup = protocol::ProtocolSetup::<Z>::new(&rt, parties, threshold);
        group.bench_function(
            BenchmarkId::new(format!("parties_{parties}_threshold_{threshold}"), 10_000),
            |b| {
                b.iter_batched(
                    || setup.sessions(),
                    |sessions| rt.block_on(protocol::preprocess(sessions, 10_000)),
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

fn bench_bit_decryption<Z: ErrorCorrect + Invert + PRSSConversions>(
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
        // This secondary test-helper comparison includes session setup and bit preprocessing.
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

fn bench_noise_flood_decryption(c: &mut Criterion) {
    ensure_real_keys_setup();
    let keyset: KeySet = test_utils::read_element(REAL_KEY_PATH).unwrap();
    set_server_key(keyset.public_keys.server_key.clone());
    let encrypted: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, 42_u64, 8).unwrap();
    // Match BigCompressed input and its compression key, as in PR #667. All upstream work is untimed.
    let compressed = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
        .push(encrypted.squash_noise().unwrap())
        .build()
        .unwrap();
    let squashed: tfhe::SquashedNoiseFheUint = compressed.get(0).unwrap().unwrap();
    let ciphertext =
        SnsRadixOrBoolCiphertext::Radix(squashed.underlying_squashed_noise_ciphertext().clone());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut rng = AesRng::seed_from_u64(42);
    for (parties, threshold) in [(4, 1), (13, 4)] {
        let keys: Vec<_> = keygen_all_party_shares_from_client_key::<_, 4>(
            &keyset.client_key,
            keyset.get_cpu_params().unwrap(),
            &mut rng,
            parties,
            threshold,
        )
        .unwrap()
        .into_iter()
        .map(Arc::new)
        .collect();
        let mut setup =
            protocol::ProtocolSetup::<ResiduePolyF4Z128>::new(&rt, parties, threshold as u8);
        let mut group = c.benchmark_group(format!(
            "prss_protocols/noise_flood_big_compressed/parties_{parties}_threshold_{threshold}"
        ));
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size(10);
        group.throughput(Throughput::Elements(1));
        // Udec compute is local to one party; pdec opens the result across all parties.
        group.bench_function("udec_one_party/uint8", |b| {
            let mut session = SmallOfflineNoiseFloodSession::new(setup.sessions().remove(0));
            b.iter_batched(
                || ciphertext.clone(),
                |ct| {
                    let (partials, packing, _) = rt
                        .block_on(partial_decrypt_using_noiseflooding(
                            &mut session,
                            LowLevelCiphertextAndKeys::BigCompressed(ct),
                            &keys[0],
                        ))
                        .unwrap();
                    assert_eq!(partials.len(), 1);
                    assert!(packing > 0);
                    black_box(partials)
                },
                BatchSize::PerIteration,
            );
        });
        group.bench_function("pdec_all_parties/uint8", |b| {
            b.iter_batched(
                || {
                    setup
                        .sessions()
                        .into_iter()
                        .map(|session| {
                            let key = keys[session.my_role().one_based() - 1].clone();
                            (
                                SmallOfflineNoiseFloodSession::new(session),
                                ciphertext.clone(),
                                key,
                            )
                        })
                        .collect::<Vec<_>>()
                },
                |inputs| {
                    rt.block_on(async {
                        let mut tasks = tokio::task::JoinSet::new();
                        for (mut session, ct, key) in inputs {
                            tasks.spawn(async move {
                                let (plaintexts, _) = decrypt_using_noiseflooding::<
                                    4,
                                    _,
                                    SecureOnlineNoiseFloodDecryption,
                                    u64,
                                >(
                                    &mut session,
                                    LowLevelCiphertextAndKeys::BigCompressed(ct),
                                    key,
                                )
                                .await
                                .unwrap();
                                assert_eq!(plaintexts.len(), 1);
                                assert_eq!(*plaintexts.values().next().unwrap(), 42);
                                black_box(plaintexts);
                            });
                        }
                        let mut completed = 0;
                        while let Some(result) = tasks.join_next().await {
                            result.unwrap();
                            completed += 1;
                        }
                        assert_eq!(completed, parties);
                    })
                },
                BatchSize::PerIteration,
            );
        });
        group.finish();
    }
}

fn bench_protocols(c: &mut Criterion) {
    bench_preprocessing::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_preprocessing::<ResiduePolyF4Z128>(c, "f4_z128");
    // Bit decomposition is a secondary comparison, not a production optimization target.
    bench_bit_decryption::<ResiduePolyF4Z64>(c, "f4_z64_bitdec", DecryptionMode::BitDecSmall);
    bench_noise_flood_decryption(c);
}
criterion_group!(protocols, bench_protocols);
criterion_main!(protocols);
