use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};
use rand::SeedableRng;
use std::num::Wrapping;
use threshold_fhe::algebra::base_ring::Z64;
use threshold_fhe::algebra::galois_rings::degree_8::ResiduePolyF8Z64;
use threshold_fhe::algebra::structure_traits::Ring;
use threshold_fhe::execution::endpoints::decryption::{
    secure_init_prep_bitdec_large_session, secure_init_prep_bitdec_small_session,
};
use threshold_fhe::execution::online::bit_manipulation::bit_dec_batch;
use threshold_fhe::execution::online::preprocessing::dummy::DummyPreprocessing;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::runtime::session::ParameterHandles;
use threshold_fhe::execution::runtime::session::{LargeSession, SmallSession};
use threshold_fhe::execution::sharing::shamir::InputOp;
use threshold_fhe::execution::sharing::shamir::ShamirSharings;
use threshold_fhe::execution::sharing::share::Share;
use threshold_fhe::networking::NetworkMode;
use threshold_fhe::tests::helper::tests_and_benches::{
    execute_protocol_large, execute_protocol_small,
};

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

/// TODO(Dragos) Add pub types for different prep modes.
///
/// Helper method to get a sharing of a simple u64 value
fn get_my_share(val: u64, n: usize, threshold: usize, my_role: Role) -> Share<ResiduePolyF8Z64> {
    let mut rng = AesRng::seed_from_u64(val);
    let secret = ResiduePolyF8Z64::from_scalar(Wrapping(val));
    let shares = ShamirSharings::share(&mut rng, secret, n, threshold)
        .unwrap()
        .shares;
    shares[&my_role]
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
                        let mut prep = DummyPreprocessing::<ResiduePolyF8Z64>::new(42, &session);

                        let input_a = get_my_share(
                            2,
                            session.num_parties(),
                            session.threshold() as usize,
                            session.my_role(),
                        );
                        let _bits =
                            bit_dec_batch::<Z64, { ResiduePolyF8Z64::EXTENSION_DEGREE }, _, _>(
                                &mut session,
                                &mut prep,
                                [input_a].to_vec(),
                            )
                            .await
                            .unwrap();
                    };

                    //Async is fine because we use Dummy preprocessing
                    let _result = execute_protocol_large::<
                        _,
                        _,
                        ResiduePolyF8Z64,
                        { ResiduePolyF8Z64::EXTENSION_DEGREE },
                    >(
                        config.n,
                        config.t,
                        None,
                        NetworkMode::Async,
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
                    let mut computation = |mut session: SmallSession<ResiduePolyF8Z64>, _bot: Option<String>| async move {
                        let mut bitdec_prep =
                            secure_init_prep_bitdec_small_session(&mut session, config.batch_size)
                                .await
                                .unwrap();

                        let inputs: Vec<_> = (0..config.batch_size)
                            .map(|i| {
                                get_my_share(
                                    i as u64,
                                    session.num_parties(),
                                    session.threshold() as usize,
                                    session.my_role(),
                                )
                            })
                            .collect();

                        let _bits = bit_dec_batch::<
                            Z64,
                            { ResiduePolyF8Z64::EXTENSION_DEGREE },
                            _,
                            _

                        >(
                            &mut session, &mut bitdec_prep, inputs
                        )
                        .await
                        .unwrap();
                    };

                    //Need Sync network because we execute preprocessing
                    let _result = execute_protocol_small::<
                        _,
                        _,
                        ResiduePolyF8Z64,
                        { ResiduePolyF8Z64::EXTENSION_DEGREE },
                    >(
                        config.n,
                        config.t as u8,
                        None,
                        NetworkMode::Sync,
                        None,
                        &mut computation,
                        None,
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
                        let mut bitdec_prep =
                            secure_init_prep_bitdec_large_session(&mut session, config.batch_size)
                                .await
                                .unwrap();
                        let inputs: Vec<_> = (0..config.batch_size)
                            .map(|i| {
                                get_my_share(
                                    i as u64,
                                    session.num_parties(),
                                    session.threshold() as usize,
                                    session.my_role(),
                                )
                            })
                            .collect();

                        let _bits =
                            bit_dec_batch::<Z64, { ResiduePolyF8Z64::EXTENSION_DEGREE }, _, _>(
                                &mut session,
                                &mut bitdec_prep,
                                inputs,
                            )
                            .await
                            .unwrap();
                    };

                    //Need Sync network because we execute preprocessing
                    let _result = execute_protocol_large::<
                        _,
                        _,
                        ResiduePolyF8Z64,
                        { ResiduePolyF8Z64::EXTENSION_DEGREE },
                    >(
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

criterion_group! {
    name = bit_dec;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bit_dec_online, bit_dec_small_e2e_abort, bit_dec_large_e2e
}

criterion_main!(bit_dec);
