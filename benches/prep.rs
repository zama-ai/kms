use criterion::Throughput;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::execution::large_execution::offline::{
    BatchParams, LargePreprocessing,
};
use distributed_decryption::execution::large_execution::offline::{
    TrueDoubleSharing, TrueSingleSharing,
};
use distributed_decryption::execution::online::gen_bits::Solve;
use distributed_decryption::execution::session::LargeSession;
use distributed_decryption::sharing::double_sharing::DoubleSharing;
use distributed_decryption::tests::helper::tests_and_benches::execute_protocol_large;
use distributed_decryption::Z128;

use pprof::criterion::{Output, PProfProfiler};

#[derive(Debug, Clone, Copy)]
struct OneShotConfig {
    n: usize,
    t: usize,
    batch_size: usize,
}
impl OneShotConfig {
    fn new(n: usize, t: usize, batch_size: usize) -> OneShotConfig {
        OneShotConfig { n, t, batch_size }
    }
}

impl std::fmt::Display for OneShotConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "n={}_t={}_batch={}", self.n, self.t, self.batch_size)?;
        Ok(())
    }
}

fn triple(c: &mut Criterion) {
    let mut group = c.benchmark_group("triple_generation");

    let params = vec![
        OneShotConfig::new(5, 1, 100),
        OneShotConfig::new(5, 1, 200),
        OneShotConfig::new(5, 1, 500),
        OneShotConfig::new(5, 1, 1000),
        OneShotConfig::new(10, 2, 100),
        OneShotConfig::new(10, 2, 200),
        OneShotConfig::new(10, 2, 500),
        OneShotConfig::new(10, 2, 1000),
        OneShotConfig::new(13, 3, 100),
        OneShotConfig::new(13, 3, 200),
        OneShotConfig::new(13, 3, 500),
        OneShotConfig::new(13, 3, 1000),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    for config in params {
        group.throughput(Throughput::Elements(config.batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: LargeSession| async move {
                        let _ = LargePreprocessing::<TrueSingleSharing, TrueDoubleSharing>::init(
                            &mut session,
                            Some(BatchParams {
                                triple_batch_size: config.batch_size,
                                random_batch_size: 0,
                            }),
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();
                    };
                    let _result = execute_protocol_large(config.n, config.t, &mut computation);
                });
            },
        );
    }
    group.finish();
}

fn random_sharing(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_sharing");

    let params = vec![
        OneShotConfig::new(5, 1, 100),
        OneShotConfig::new(5, 1, 200),
        OneShotConfig::new(5, 1, 500),
        OneShotConfig::new(5, 1, 1000),
        OneShotConfig::new(10, 2, 100),
        OneShotConfig::new(10, 2, 200),
        OneShotConfig::new(10, 2, 500),
        OneShotConfig::new(10, 2, 1000),
        OneShotConfig::new(13, 3, 100),
        OneShotConfig::new(13, 3, 200),
        OneShotConfig::new(13, 3, 500),
        OneShotConfig::new(13, 3, 1000),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    for config in params {
        group.throughput(Throughput::Elements(config.batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: LargeSession| async move {
                        let _ = LargePreprocessing::<TrueSingleSharing, TrueDoubleSharing>::init(
                            &mut session,
                            Some(BatchParams {
                                triple_batch_size: 0,
                                random_batch_size: config.batch_size,
                            }),
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();
                    };
                    let _result = execute_protocol_large(config.n, config.t, &mut computation);
                });
            },
        );
    }
}

fn double_sharing(c: &mut Criterion) {
    let mut group = c.benchmark_group("double_sharing");

    let params = vec![
        OneShotConfig::new(5, 1, 100),
        OneShotConfig::new(5, 1, 200),
        OneShotConfig::new(5, 1, 500),
        OneShotConfig::new(5, 1, 1000),
        OneShotConfig::new(10, 2, 100),
        OneShotConfig::new(10, 2, 200),
        OneShotConfig::new(10, 2, 500),
        OneShotConfig::new(10, 2, 1000),
        OneShotConfig::new(13, 3, 100),
        OneShotConfig::new(13, 3, 200),
        OneShotConfig::new(13, 3, 500),
        OneShotConfig::new(13, 3, 1000),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    for config in params {
        group.throughput(Throughput::Elements(config.batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: LargeSession| async move {
                        let mut dsh = TrueDoubleSharing::default();
                        dsh.init(&mut session, config.batch_size).await.unwrap();
                    };
                    let _result = execute_protocol_large(config.n, config.t, &mut computation);
                });
            },
        );
    }
}

fn bitgen_nlarge(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitgen_nlarge");

    let params = vec![
        OneShotConfig::new(5, 1, 100),
        OneShotConfig::new(5, 1, 200),
        OneShotConfig::new(5, 1, 500),
        OneShotConfig::new(5, 1, 1000),
        OneShotConfig::new(10, 2, 100),
        OneShotConfig::new(10, 2, 200),
        OneShotConfig::new(10, 2, 500),
        OneShotConfig::new(10, 2, 1000),
        OneShotConfig::new(13, 3, 100),
        OneShotConfig::new(13, 3, 200),
        OneShotConfig::new(13, 3, 500),
        OneShotConfig::new(13, 3, 1000),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    for config in params {
        group.throughput(Throughput::Elements(config.batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: LargeSession| async move {
                        let mut large_preprocessing =
                            LargePreprocessing::<TrueSingleSharing, TrueDoubleSharing>::init(
                                &mut session,
                                Some(BatchParams {
                                    triple_batch_size: config.batch_size,
                                    random_batch_size: config.batch_size,
                                }),
                                TrueSingleSharing::default(),
                                TrueDoubleSharing::default(),
                            )
                            .await
                            .unwrap();
                        let _ = Solve::<Z128>::gen_bits_even(
                            config.batch_size,
                            &mut large_preprocessing,
                            &mut session,
                        )
                        .await
                        .unwrap();
                    };
                    let _result = execute_protocol_large(config.n, config.t, &mut computation);
                });
            },
        );
    }
}

fn batch_decode2t(c: &mut Criterion) {
    use distributed_decryption::shamir::ShamirGSharings;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::num::Wrapping;

    let mut group = c.benchmark_group("batch_decode2t");
    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);

    let params = vec![
        OneShotConfig::new(5, 1, 100),
        OneShotConfig::new(5, 1, 200),
        OneShotConfig::new(5, 1, 500),
        OneShotConfig::new(5, 1, 1000),
        OneShotConfig::new(10, 2, 100),
        OneShotConfig::new(10, 2, 200),
        OneShotConfig::new(10, 2, 500),
        OneShotConfig::new(10, 2, 1000),
        OneShotConfig::new(13, 3, 100),
        OneShotConfig::new(13, 3, 200),
        OneShotConfig::new(13, 3, 500),
        OneShotConfig::new(13, 3, 1000),
    ];

    for config in &params {
        let degree = config.t * 2;

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let prep: Vec<ShamirGSharings<_>> = (0..config.batch_size)
            .map(|idx| {
                ShamirGSharings::<Z128>::share(&mut rng, Wrapping(idx as u128), config.n, degree)
                    .unwrap()
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &_config| {
                b.iter(|| {
                    for secret_shares in &prep {
                        let _r = secret_shares.reconstruct(degree);
                    }
                });
            },
        );
    }
}

criterion_group! {
    name = prep;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = batch_decode2t, triple, random_sharing, double_sharing, bitgen_nlarge
}

criterion_main!(prep);
