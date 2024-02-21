use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::algebra::base_ring::Z64;
use distributed_decryption::algebra::residue_poly::ResiduePoly64;
use distributed_decryption::execution::config::BatchParams;
use distributed_decryption::execution::large_execution::offline::LargePreprocessing;
use distributed_decryption::execution::large_execution::offline::{
    TrueDoubleSharing, TrueSingleSharing,
};
use distributed_decryption::execution::online::bit_manipulation::bit_dec_batch;
use distributed_decryption::execution::online::preprocessing::DummyPreprocessing;
use distributed_decryption::execution::runtime::session::ParameterHandles;
use distributed_decryption::execution::runtime::session::SmallSessionHandles;
use distributed_decryption::execution::runtime::session::{LargeSession, SmallSession};
use distributed_decryption::execution::sharing::shamir::InputOp;
use distributed_decryption::execution::sharing::shamir::ShamirSharings;
use distributed_decryption::execution::sharing::share::Share;
use distributed_decryption::execution::small_execution::agree_random::RealAgreeRandom;
use distributed_decryption::execution::small_execution::offline::SmallPreprocessing;
use distributed_decryption::execution::small_execution::prss::PRSSSetup;
use distributed_decryption::tests::helper::tests_and_benches::{
    execute_protocol_large, execute_protocol_small,
};
use pprof::criterion::{Output, PProfProfiler};
use rand::SeedableRng;
use std::num::Wrapping;

#[derive(Debug, Clone, Copy)]
struct OneShotConfig {
    n: usize,
    batch_size: usize,
    t: usize,
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

/// Preprocessing amount for doing a single (full) 64-bit bit-decomposition
struct OneShotBitDec;
impl OneShotBitDec {
    fn triples() -> usize {
        1280
    }
    fn randoms() -> usize {
        64
    }
}

/// TODO(Dragos) Add pub types for different prep modes.
///
/// Helper method to get a sharing of a simple u64 value
fn get_my_share(val: u64, n: usize, threshold: usize, my_id: usize) -> Share<ResiduePoly64> {
    let mut rng = AesRng::seed_from_u64(val);
    let secret = ResiduePoly64::from_scalar(Wrapping(val));
    let shares = ShamirSharings::share(&mut rng, secret, n, threshold)
        .unwrap()
        .shares;
    shares[my_id]
}

fn bit_dec_online(c: &mut Criterion) {
    let mut group = c.benchmark_group("bit_dec_online");

    let params = vec![
        OneShotConfig::new(5, 1, 100),
        OneShotConfig::new(10, 2, 100),
    ];

    group.sample_size(10);
    for config in params {
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: LargeSession| async move {
                        let mut prep =
                            DummyPreprocessing::<ResiduePoly64, AesRng, LargeSession>::new(
                                42,
                                session.clone(),
                            );

                        let input_a = get_my_share(
                            2,
                            session.num_parties(),
                            session.threshold() as usize,
                            session.my_role().unwrap().zero_based(),
                        );
                        let _bits = bit_dec_batch::<Z64, _, _, _>(
                            &mut session,
                            &mut prep,
                            [input_a].to_vec(),
                        )
                        .await
                        .unwrap();
                    };

                    let _result = execute_protocol_large::<ResiduePoly64, _, _>(
                        config.n,
                        config.t,
                        None,
                        &mut computation,
                    );
                });
            },
        );
    }
    group.finish();
}

fn bit_dec_small_e2e_abort(c: &mut Criterion) {
    let mut group = c.benchmark_group("bit_dec_small_e2e_abort");

    let params = vec![
        OneShotConfig::new(5, 1, 8),
        OneShotConfig::new(5, 1, 16),
        OneShotConfig::new(10, 2, 5),
        OneShotConfig::new(13, 3, 5),
    ];

    group.sample_size(10);
    for config in params {
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: SmallSession<ResiduePoly64>| async move {
                        let prss_setup = PRSSSetup::init_with_abort::<
                            RealAgreeRandom,
                            AesRng,
                            SmallSession<ResiduePoly64>,
                        >(&mut session)
                        .await
                        .unwrap();

                        session.set_prss(Some(
                            prss_setup.new_prss_session_state(session.session_id()),
                        ));

                        let bitdec_batch = BatchParams {
                            triples: OneShotBitDec::triples() * config.batch_size,
                            randoms: OneShotBitDec::randoms() * config.batch_size,
                        };

                        let mut prep = SmallPreprocessing::<ResiduePoly64, RealAgreeRandom>::init(
                            &mut session,
                            bitdec_batch,
                        )
                        .await
                        .unwrap();

                        let inputs: Vec<_> = (0..config.batch_size)
                            .map(|i| {
                                get_my_share(
                                    i as u64,
                                    session.num_parties(),
                                    session.threshold() as usize,
                                    session.my_role().unwrap().zero_based(),
                                )
                            })
                            .collect();

                        let _bits = bit_dec_batch::<Z64, _, _, _>(&mut session, &mut prep, inputs)
                            .await
                            .unwrap();
                    };

                    let _result = execute_protocol_small::<ResiduePoly64, _, _>(
                        config.n,
                        config.t as u8,
                        None,
                        &mut computation,
                    );
                });
            },
        );
    }
    group.finish();
}

fn bit_dec_large_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("bit_dec_large_e2e");

    let params = vec![
        OneShotConfig::new(5, 1, 8),
        OneShotConfig::new(5, 1, 16),
        OneShotConfig::new(10, 2, 5),
        OneShotConfig::new(13, 3, 5),
    ];

    group.sample_size(10);
    for config in params {
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &config,
            |b, &config| {
                b.iter(|| {
                    let mut computation = |mut session: LargeSession| async move {
                        let mut large_preprocessing = LargePreprocessing::<
                            ResiduePoly64,
                            TrueSingleSharing<ResiduePoly64>,
                            TrueDoubleSharing<ResiduePoly64>,
                        >::init(
                            &mut session,
                            BatchParams {
                                triples: OneShotBitDec::triples() * config.batch_size,
                                randoms: OneShotBitDec::randoms() * config.batch_size,
                            },
                            TrueSingleSharing::default(),
                            TrueDoubleSharing::default(),
                        )
                        .await
                        .unwrap();

                        let inputs: Vec<_> = (0..config.batch_size)
                            .map(|i| {
                                get_my_share(
                                    i as u64,
                                    session.num_parties(),
                                    session.threshold() as usize,
                                    session.my_role().unwrap().zero_based(),
                                )
                            })
                            .collect();

                        let _bits = bit_dec_batch::<Z64, _, _, _>(
                            &mut session,
                            &mut large_preprocessing,
                            inputs,
                        )
                        .await
                        .unwrap();
                    };

                    let _result = execute_protocol_large::<ResiduePoly64, _, _>(
                        config.n,
                        config.t,
                        None,
                        &mut computation,
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = bit_dec;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bit_dec_online, bit_dec_small_e2e_abort, bit_dec_large_e2e
}

criterion_main!(bit_dec);
