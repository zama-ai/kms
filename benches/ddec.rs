use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    algebra::residue_poly::ResiduePoly128,
    algebra::residue_poly::ResiduePoly64,
    execution::{
        constants::REAL_KEY_PATH,
        endpoints::decryption::threshold_decrypt64,
        runtime::{
            session::DecryptionMode,
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
    },
    file_handling::read_element,
    lwe::{keygen_all_party_shares, KeySet},
};
use pprof::criterion::{Output, PProfProfiler};
use rand::Rng;
use rand_core::SeedableRng;
use std::sync::Arc;

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
    let keyset: KeySet = read_element(REAL_KEY_PATH.to_string()).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let key_shares = keygen_all_party_shares(&keyset, &mut rng, config.n, config.t).unwrap();
        let ct = keyset
            .pk
            .encrypt_w_bitlimit(&mut rng, message, config.ctxt_size);

        let identities = generate_fixed_identities(config.n);
        let mut runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, config.t as u8);
        let ctc = Arc::new(ct);

        let keyset_ck = Arc::new(keyset.ck.clone());
        let key_shares = Arc::new(key_shares);
        runtime.conversion_keys = Some(keyset_ck.clone());
        runtime.setup_sks(key_shares.clone().to_vec());

        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, cti, runtime)| {
                b.iter(|| {
                    let _ = threshold_decrypt64(runtime, cti.to_vec(), DecryptionMode::PRSSDecrypt);
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
    let keyset: KeySet = read_element(REAL_KEY_PATH.to_string()).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let key_shares = keygen_all_party_shares(&keyset, &mut rng, config.n, config.t).unwrap();
        let ct = keyset
            .pk
            .encrypt_w_bitlimit(&mut rng, message, config.ctxt_size);

        let identities = generate_fixed_identities(config.n);
        let ctc = Arc::new(ct);
        let key_shares = Arc::new(key_shares);
        let mut runtime =
            DistributedTestRuntime::<ResiduePoly64>::new(identities.clone(), config.t as u8);
        runtime.setup_sks(key_shares.clone().to_vec());
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, ct, runtime)| {
                b.iter(|| {
                    let _ = threshold_decrypt64(
                        runtime,
                        ct.to_vec(),
                        DecryptionMode::BitDecSmallDecrypt,
                    );
                })
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
    let keyset: KeySet = read_element(REAL_KEY_PATH.to_string()).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let key_shares = keygen_all_party_shares(&keyset, &mut rng, config.n, config.t).unwrap();
        let ct = keyset
            .pk
            .encrypt_w_bitlimit(&mut rng, message, config.ctxt_size);

        let identities = generate_fixed_identities(config.n);
        let mut runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, config.t as u8);

        let ctc = Arc::new(ct);
        let keyset_ck = Arc::new(keyset.ck.clone());
        let key_shares = Arc::new(key_shares);
        runtime.setup_cks(keyset_ck.clone());
        runtime.setup_sks(key_shares.clone().to_vec());

        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, ct, runtime)| {
                b.iter(|| {
                    let _ = threshold_decrypt64(runtime, ct.to_vec(), DecryptionMode::LargeDecrypt);
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
    let keyset: KeySet = read_element(REAL_KEY_PATH.to_string()).unwrap();
    let mut rng = AesRng::from_entropy();
    for config in params {
        let message = rng.gen::<u64>();
        let key_shares = keygen_all_party_shares(&keyset, &mut rng, config.n, config.t).unwrap();
        let ct = keyset
            .pk
            .encrypt_w_bitlimit(&mut rng, message, config.ctxt_size);

        let identities = generate_fixed_identities(config.n);
        let ctc = Arc::new(ct);
        let key_shares = Arc::new(key_shares);
        let mut runtime =
            DistributedTestRuntime::<ResiduePoly64>::new(identities.clone(), config.t as u8);
        runtime.setup_sks(key_shares.clone().to_vec());
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ctc, runtime),
            |b, (_config, ct, runtime)| {
                b.iter(|| {
                    let _ = threshold_decrypt64(
                        runtime,
                        ct.to_vec(),
                        DecryptionMode::BitDecLargeDecrypt,
                    );
                })
            },
        );
    }
}

criterion_group! {
    name = prep;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = ddec_nsmall, ddec_bitdec_nsmall, ddec_nlarge, ddec_bitdec_nlarge,
}

criterion_main!(prep);
