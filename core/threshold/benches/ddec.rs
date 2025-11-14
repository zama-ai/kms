use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use tfhe::{set_server_key, FheUint8};
use threshold_fhe::{
    algebra::{
        galois_rings::degree_8::{ResiduePolyF8Z128, ResiduePolyF8Z64},
        structure_traits::Ring,
    },
    execution::{
        constants::REAL_KEY_PATH,
        endpoints::decryption::{threshold_decrypt64, DecryptionMode, RadixOrBoolCiphertext},
        runtime::test_runtime::{generate_fixed_roles, DistributedTestRuntime},
        tfhe_internals::{
            test_feature::{keygen_all_party_shares_from_keyset, KeySet},
            utils::expanded_encrypt,
        },
    },
    file_handling::tests::read_element,
    networking::NetworkMode,
};

#[derive(Debug, Clone, Copy)]
struct OneShotConfig {
    n: usize,
    t: usize,
    ctxt_size: usize,
}
impl OneShotConfig {
    fn new(n: usize, t: usize, ctxt_size: usize) -> OneShotConfig {
        OneShotConfig { n, t, ctxt_size }
    }
}
impl std::fmt::Display for OneShotConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "n={}_t={}_ctxtsize={}", self.n, self.t, self.ctxt_size)?;
        Ok(())
    }
}

fn ddec_nsmall(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddec_nsmall");

    let params = vec![
        OneShotConfig::new(5, 1, 8),
        OneShotConfig::new(5, 1, 16),
        OneShotConfig::new(5, 1, 32),
        OneShotConfig::new(10, 2, 8),
        OneShotConfig::new(10, 2, 16),
        OneShotConfig::new(10, 2, 32),
        OneShotConfig::new(13, 3, 8),
        OneShotConfig::new(13, 3, 16),
        OneShotConfig::new(13, 3, 32),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let keyset: KeySet = read_element(REAL_KEY_PATH).unwrap();

    set_server_key(keyset.public_keys.server_key.clone());

    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let params = keyset.get_cpu_params().unwrap();
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, config.n, config.t)
                .unwrap();
        let ct: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, message, 8).unwrap();
        let (raw_ct, _id, _tag, _rerand_metadata) = ct.into_raw_parts();
        let raw_ct = RadixOrBoolCiphertext::Radix(raw_ct);

        let roles = generate_fixed_roles(config.n);
        //Using Sync because threshold_decrypt64 encompasses both online and offline
        let mut runtime = DistributedTestRuntime::<
            ResiduePolyF8Z128,
            _,
            { ResiduePolyF8Z128::EXTENSION_DEGREE },
        >::new(roles, config.t as u8, NetworkMode::Sync, None);
        let ctc = Arc::new(raw_ct);

        let server_key = Arc::new(keyset.public_keys.server_key.clone());
        let key_shares = Arc::new(key_shares);
        runtime.setup_server_key(server_key);
        runtime.setup_sks(key_shares.clone().to_vec());

        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, cti, runtime)| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| {
                        threshold_decrypt64(runtime, cti.as_ref(), DecryptionMode::NoiseFloodSmall)
                    });
            },
        );
    }
}

fn ddec_bitdec_nsmall(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddec_bitdec_nsmall");

    let params = vec![
        OneShotConfig::new(5, 1, 8),
        OneShotConfig::new(5, 1, 16),
        OneShotConfig::new(5, 1, 32),
        OneShotConfig::new(10, 2, 8),
        OneShotConfig::new(10, 2, 16),
        OneShotConfig::new(10, 2, 32),
        OneShotConfig::new(13, 3, 8),
        OneShotConfig::new(13, 3, 16),
        OneShotConfig::new(13, 3, 32),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let keyset: KeySet = read_element(REAL_KEY_PATH).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let params = keyset.get_cpu_params().unwrap();
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, config.n, config.t)
                .unwrap();
        let ct: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, message, 8).unwrap();
        let (raw_ct, _id, _tag, _rerand_metadata) = ct.into_raw_parts();
        let raw_ct = RadixOrBoolCiphertext::Radix(raw_ct);

        let roles = generate_fixed_roles(config.n);
        let ctc = Arc::new(raw_ct);
        let key_shares = Arc::new(key_shares);
        //Using Sync because threshold_decrypt64 encompasses both online and offline
        let mut runtime = DistributedTestRuntime::<
            ResiduePolyF8Z64,
            _,
            { ResiduePolyF8Z64::EXTENSION_DEGREE },
        >::new(roles.clone(), config.t as u8, NetworkMode::Sync, None);
        runtime.setup_sks(key_shares.clone().to_vec());
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, ct, runtime)| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| threshold_decrypt64(runtime, ct.as_ref(), DecryptionMode::BitDecSmall))
            },
        );
    }
}

fn ddec_nlarge(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddec_nlarge");

    let params = vec![
        OneShotConfig::new(5, 1, 8),
        OneShotConfig::new(5, 1, 16),
        OneShotConfig::new(5, 1, 32),
        OneShotConfig::new(10, 2, 8),
        OneShotConfig::new(10, 2, 16),
        OneShotConfig::new(10, 2, 32),
        OneShotConfig::new(13, 3, 8),
        OneShotConfig::new(13, 3, 16),
        OneShotConfig::new(13, 3, 32),
    ];
    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let keyset: KeySet = read_element(REAL_KEY_PATH).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let params = keyset.get_cpu_params().unwrap();
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, config.n, config.t)
                .unwrap();

        let ct: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, message, 8).unwrap();
        let (raw_ct, _id, _tag, _rerand_metadata) = ct.into_raw_parts();
        let raw_ct = RadixOrBoolCiphertext::Radix(raw_ct);

        let roles = generate_fixed_roles(config.n);
        //Using Sync because threshold_decrypt64 encompasses both online and offline
        let mut runtime = DistributedTestRuntime::<
            ResiduePolyF8Z128,
            _,
            { ResiduePolyF8Z128::EXTENSION_DEGREE },
        >::new(roles, config.t as u8, NetworkMode::Sync, None);

        let ctc = Arc::new(raw_ct);

        let server_key = Arc::new(keyset.public_keys.server_key.clone());
        runtime.setup_server_key(server_key);

        let key_shares = Arc::new(key_shares);
        runtime.setup_sks(key_shares.clone().to_vec());

        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, ct, runtime)| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| {
                        threshold_decrypt64(runtime, ct.as_ref(), DecryptionMode::NoiseFloodLarge)
                    });
            },
        );
    }
}

fn ddec_bitdec_nlarge(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddec_bitdec_nlarge");

    let params = vec![
        OneShotConfig::new(5, 1, 8),
        OneShotConfig::new(5, 1, 16),
        OneShotConfig::new(5, 1, 32),
        OneShotConfig::new(10, 2, 8),
        OneShotConfig::new(10, 2, 16),
        OneShotConfig::new(10, 2, 32),
        OneShotConfig::new(13, 3, 8),
        OneShotConfig::new(13, 3, 16),
        OneShotConfig::new(13, 3, 32),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let keyset: KeySet = read_element(REAL_KEY_PATH).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let params = keyset.get_cpu_params().unwrap();
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, config.n, config.t)
                .unwrap();

        let ct: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, message, 8).unwrap();
        let (raw_ct, _id, _tag, _rerand_metadata) = ct.into_raw_parts();
        let raw_ct = RadixOrBoolCiphertext::Radix(raw_ct);

        let roles = generate_fixed_roles(config.n);
        let ctc = Arc::new(raw_ct);
        let key_shares = Arc::new(key_shares);
        let mut runtime =
        //Using Sync because threshold_decrypt64 encompasses both online and offline
            DistributedTestRuntime::<ResiduePolyF8Z64, _, {ResiduePolyF8Z64::EXTENSION_DEGREE}>::new(roles.clone(), config.t as u8, NetworkMode::Sync, None);
        runtime.setup_sks(key_shares.clone().to_vec());
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, ct, runtime)| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| threshold_decrypt64(runtime, ct.as_ref(), DecryptionMode::BitDecLarge))
            },
        );
    }
}

criterion_group! {
    name = ddec;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = ddec_nsmall, ddec_bitdec_nsmall, ddec_nlarge, ddec_bitdec_nlarge,
}

criterion_main!(ddec);
