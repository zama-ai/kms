use std::sync::Arc;

use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    algebra::residue_poly::ResiduePoly128,
    computation::SessionId,
    execution::{
        endpoints::decryption::{run_decryption_large, run_decryption_small, to_large_ciphertext},
        runtime::{
            session::{LargeSession, ParameterHandles, SmallSession, SmallSessionHandles},
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
        small_execution::{agree_random::RealAgreeRandom, prss::PRSSSetup},
    },
    file_handling::read_element,
    lwe::{keygen_all_party_shares, KeySet},
};
use itertools::Itertools;
use pprof::criterion::{Output, PProfProfiler};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tfhe::core_crypto::entities::LweCiphertext;
use tokio::task::JoinSet;

pub const TEST_PARAM_PATH: &str = "temp/test_params.json";
pub const TEST_KEY_PATH: &str = "temp/keys1.bin";
pub const DEFAULT_KEY_PATH: &str = "temp/fullkeys.bin";
pub const DEFAULT_PARAM_PATH: &str = "temp/default_params.json";
pub const TEST_MESSAGE: u8 = 1;
pub const DEFAULT_SEED: u64 = 1;

#[derive(Debug, Clone, Copy)]
struct OneShotConfig {
    n: usize,
    t: usize,
    batch_size: usize,
    ctxt_size: usize,
}
impl OneShotConfig {
    fn new(n: usize, t: usize, batch_size: usize, ctxt_size: usize) -> OneShotConfig {
        OneShotConfig {
            n,
            t,
            batch_size,
            ctxt_size,
        }
    }
}

impl std::fmt::Display for OneShotConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "n={}_t={}_batch={}_ctxtsize={}",
            self.n, self.t, self.batch_size, self.ctxt_size
        )?;
        Ok(())
    }
}

fn ddec_nsmall(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddec_nsmall");

    let params = vec![
        OneShotConfig::new(5, 1, 100, 8),
        OneShotConfig::new(5, 1, 100, 16),
        OneShotConfig::new(10, 2, 100, 8),
        OneShotConfig::new(10, 2, 100, 16),
        OneShotConfig::new(13, 3, 100, 8),
        OneShotConfig::new(13, 3, 100, 16),
    ];

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
    let mut rng = AesRng::from_random_seed();
    for config in params {
        let messages = (0..config.batch_size)
            .map(|_| rng.gen::<u64>())
            .collect_vec();
        let key_shares = keygen_all_party_shares(&keyset, &mut rng, config.n, config.t).unwrap();
        let cts = messages
            .iter()
            .map(|message| {
                keyset
                    .pk
                    .encrypt_w_bitlimit(&mut rng, *message, config.ctxt_size)
            })
            .collect_vec();
        let identities = generate_fixed_identities(config.n);
        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, config.t as u8);
        let cts = Arc::new(cts);
        let keyset_ck = Arc::new(keyset.ck.clone());
        let key_shares = Arc::new(key_shares);
        group.throughput(criterion::Throughput::Elements(config.batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, cts, keyset_ck, key_shares),
            |b, (config, cts, keyset_ck, key_shares)| {
                b.iter(|| {
                    let computation = |mut small_session: SmallSession<ResiduePoly128>,
                                       cts: Arc<Vec<Vec<LweCiphertext<Vec<u64>>>>>,
                                       keyset_ck: Arc<
                        distributed_decryption::lwe::BootstrappingKey,
                    >,
                                       key_shares: Arc<
                        Vec<distributed_decryption::lwe::SecretKeyShare>,
                    >| async move {
                        let prss_setup =
                            PRSSSetup::init_with_abort::<RealAgreeRandom, ChaCha20Rng, _>(
                                &mut small_session,
                            )
                            .await
                            .unwrap();
                        //Doing all decryptions in the same session
                        small_session.set_prss(Some(
                            prss_setup.new_prss_session_state(small_session.session_id()),
                        ));
                        let my_role = small_session.my_role().unwrap();
                        for ct in cts.iter() {
                            let large_ct = to_large_ciphertext(&keyset_ck, ct);
                            let _out = run_decryption_small(
                                &mut small_session,
                                &key_shares[my_role.zero_based()],
                                large_ct,
                            )
                            .await
                            .unwrap();
                        }
                    };

                    let session_id = SessionId(1);
                    let mut tasks = JoinSet::new();
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let _guard = rt.enter();
                    for party_id in 0..config.n {
                        let session = runtime
                            .small_session_for_player(
                                session_id,
                                party_id,
                                Some(ChaCha20Rng::seed_from_u64(party_id as u64)),
                            )
                            .unwrap();
                        tasks.spawn(computation(
                            session,
                            cts.clone(),
                            keyset_ck.clone(),
                            key_shares.clone(),
                        ));
                    }
                    rt.block_on(async { while let Some(_v) = tasks.join_next().await {} })
                });
            },
        );
    }
}

fn ddec_nlarge(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddec_nlarge");

    let params = vec![
        OneShotConfig::new(5, 1, 100, 8),
        OneShotConfig::new(5, 1, 100, 16),
        OneShotConfig::new(10, 2, 100, 8),
        OneShotConfig::new(10, 2, 100, 16),
        OneShotConfig::new(13, 3, 100, 8),
        OneShotConfig::new(13, 3, 100, 16),
    ];
    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
    let mut rng = AesRng::from_random_seed();
    for config in params {
        let messages = (0..config.batch_size)
            .map(|_| rng.gen::<u64>())
            .collect_vec();
        let key_shares = keygen_all_party_shares(&keyset, &mut rng, config.n, config.t).unwrap();
        let cts = messages
            .iter()
            .map(|message| {
                keyset
                    .pk
                    .encrypt_w_bitlimit(&mut rng, *message, config.ctxt_size)
            })
            .collect_vec();
        let identities = generate_fixed_identities(config.n);
        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, config.t as u8);
        let cts = Arc::new(cts);
        let keyset_ck = Arc::new(keyset.ck.clone());
        let key_shares = Arc::new(key_shares);
        group.throughput(criterion::Throughput::Elements(config.batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, cts, keyset_ck, key_shares),
            |b, (config, cts, keyset_ck, key_shares)| {
                b.iter(|| {
                    let computation = |mut large_session: LargeSession,
                                       cts: Arc<Vec<Vec<LweCiphertext<Vec<u64>>>>>,
                                       keyset_ck: Arc<
                        distributed_decryption::lwe::BootstrappingKey,
                    >,
                                       key_shares: Arc<
                        Vec<distributed_decryption::lwe::SecretKeyShare>,
                    >| async move {
                        let my_role = large_session.my_role().unwrap();
                        for ct in cts.iter() {
                            let large_ct = to_large_ciphertext(&keyset_ck, ct);
                            let _out = run_decryption_large(
                                &mut large_session,
                                &key_shares[my_role.zero_based()],
                                large_ct,
                            )
                            .await
                            .unwrap();
                        }
                    };

                    let session_id = SessionId(1);
                    let mut tasks = JoinSet::new();
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let _guard = rt.enter();
                    for party_id in 0..config.n {
                        let session = runtime
                            .large_session_for_player(session_id, party_id)
                            .unwrap();
                        tasks.spawn(computation(
                            session,
                            cts.clone(),
                            keyset_ck.clone(),
                            key_shares.clone(),
                        ));
                    }
                    rt.block_on(async { while let Some(_v) = tasks.join_next().await {} })
                });
            },
        );
    }
}

criterion_group! {
    name = prep;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = ddec_nsmall, ddec_nlarge
}

criterion_main!(prep);
