use aes_prng::AesRng;
use criterion::Throughput;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::algebra::galois_rings::degree_8::ResiduePolyF8Z128;
use distributed_decryption::algebra::galois_rings::degree_8::ResiduePolyF8Z64;
use distributed_decryption::execution::config::BatchParams;
use distributed_decryption::execution::large_execution::double_sharing::DoubleSharing;
use distributed_decryption::execution::large_execution::offline::LargePreprocessing;
use distributed_decryption::execution::large_execution::offline::{
    TrueDoubleSharing, TrueSingleSharing,
};
use distributed_decryption::execution::online::gen_bits::{BitGenEven, RealBitGenEven};
use distributed_decryption::execution::runtime::session::{LargeSession, SmallSession128};
use distributed_decryption::execution::sharing::shamir::{InputOp, RevealOp};
use distributed_decryption::execution::small_execution::agree_random::RealAgreeRandom;
use distributed_decryption::execution::small_execution::offline::SmallPreprocessing;
use distributed_decryption::networking::NetworkMode;
use distributed_decryption::tests::helper::tests_and_benches::execute_protocol_large;
use distributed_decryption::tests::helper::tests_and_benches::execute_protocol_small;

use pprof::criterion::{Output, PProfProfiler};
use rand::SeedableRng;

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

fn triple_nsmall128(c: &mut Criterion) {
    let mut group = c.benchmark_group("triple_nsmall128");

    let params = vec![
        OneShotConfig::new(4, 1, 10000),
        OneShotConfig::new(5, 1, 10000),
        OneShotConfig::new(10, 2, 10000),
        OneShotConfig::new(13, 3, 10000),
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
                    let mut computation = |mut session: SmallSession128| async move {
                        let default_batch_size = BatchParams {
                            triples: config.batch_size,
                            randoms: 0,
                        };

                        let _prep = SmallPreprocessing::<_, RealAgreeRandom>::init(
                            &mut session,
                            default_batch_size,
                        )
                        .await
                        .unwrap();
                    };
                    //Executing offline, so require Sync network
                    let _result = execute_protocol_small::<ResiduePolyF8Z128, _, _>(
                        config.n,
                        config.t as u8,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                    );
                });
            },
        );
    }
    group.finish();
}

fn triple_z128(c: &mut Criterion) {
    let mut group = c.benchmark_group("triple_generation_z128");

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
                        let _ = LargePreprocessing::<
                            ResiduePolyF8Z128,
                            TrueSingleSharing<ResiduePolyF8Z128>,
                            TrueDoubleSharing<ResiduePolyF8Z128>,
                        >::init(
                            &mut session,
                            BatchParams {
                                triples: config.batch_size,
                                randoms: 0,
                            },
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();
                    };
                    //Executing offline, so require Sync network
                    let _result = execute_protocol_large::<ResiduePolyF8Z128, _, _>(
                        config.n,
                        config.t,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                    );
                });
            },
        );
    }
    group.finish();
}

fn triple_z64(c: &mut Criterion) {
    let mut group = c.benchmark_group("triple_generation_z64");

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
                        let _ = LargePreprocessing::<
                            ResiduePolyF8Z64,
                            TrueSingleSharing<ResiduePolyF8Z64>,
                            TrueDoubleSharing<ResiduePolyF8Z64>,
                        >::init(
                            &mut session,
                            BatchParams {
                                triples: config.batch_size,
                                randoms: 0,
                            },
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();
                    };
                    //Executing offline, so require Sync network
                    let _result = execute_protocol_large::<ResiduePolyF8Z64, _, _>(
                        config.n,
                        config.t,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                    );
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
                        let _ = LargePreprocessing::<
                            ResiduePolyF8Z128,
                            TrueSingleSharing<ResiduePolyF8Z128>,
                            TrueDoubleSharing<ResiduePolyF8Z128>,
                        >::init(
                            &mut session,
                            BatchParams {
                                triples: 0,
                                randoms: config.batch_size,
                            },
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();
                    };
                    //Executing offline, so require Sync network
                    let _result = execute_protocol_large::<ResiduePolyF8Z128, _, _>(
                        config.n,
                        config.t,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                    );
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
                        let mut dsh = TrueDoubleSharing::<ResiduePolyF8Z128>::default();
                        dsh.init(&mut session, config.batch_size).await.unwrap();
                    };
                    //Executing offline, so require Sync network
                    let _result = execute_protocol_large::<ResiduePolyF8Z128, _, _>(
                        config.n,
                        config.t,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                    );
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
                        let mut large_preprocessing = LargePreprocessing::<
                            ResiduePolyF8Z128,
                            TrueSingleSharing<ResiduePolyF8Z128>,
                            TrueDoubleSharing<ResiduePolyF8Z128>,
                        >::init(
                            &mut session,
                            BatchParams {
                                triples: config.batch_size,
                                randoms: config.batch_size,
                            },
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();
                        let _ = RealBitGenEven::gen_bits_even(
                            config.batch_size,
                            &mut large_preprocessing,
                            &mut session,
                        )
                        .await
                        .unwrap();
                    };
                    //Executing offline, so require Sync network
                    let _result = execute_protocol_large::<ResiduePolyF8Z128, _, _>(
                        config.n,
                        config.t,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                    );
                });
            },
        );
    }
}

fn batch_decode2t(c: &mut Criterion) {
    use distributed_decryption::execution::sharing::shamir::ShamirSharings;
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

        let mut rng = AesRng::seed_from_u64(0);

        let prep: Vec<ShamirSharings<_>> = (0..config.batch_size)
            .map(|idx| {
                ShamirSharings::share(
                    &mut rng,
                    ResiduePolyF8Z128::from_scalar(Wrapping(idx as u128)),
                    config.n,
                    degree,
                )
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
    targets = batch_decode2t, triple_z128, triple_z64, triple_nsmall128, random_sharing, double_sharing, bitgen_nlarge
}

criterion_main!(prep);
