use aes_prng::AesRng;
use algebra::galois_rings::degree_8::ResiduePolyF8Z128;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use std::sync::Arc;

const B_SWITCH_SQUASH: u128 = 1u128 << 70;
use threshold_execution::{
    large_execution::vss::DummyVss,
    runtime::{
        sessions::{
            base_session::BaseSession,
            session_parameters::{GenericParameterHandles, SessionParameters},
        },
        test_runtime::generate_fixed_roles,
    },
    small_execution::{
        agree_random::DummyAgreeRandomFromShare,
        prss::{DerivePRSSState, PRSSInit, PRSSPrimitives, PRSSSetup, RobustRealPrssInit},
    },
};
use threshold_networking::local::LocalNetworkingProducer;
use threshold_types::network::NetworkMode;
use threshold_types::role::Role;
use threshold_types::session_id::SessionId;

fn bench_prss(c: &mut Criterion) {
    let sizes = vec![1_usize, 10, 100, 10_000];
    let mut group = c.benchmark_group("prss");

    // params for PRSS.init
    let num_parties = 7;
    let threshold = 2;

    let bench_role = Role::indexed_from_one(1); // we can pick an arbitrary role for the bench, needed to derive the PRSS state
    let sid = SessionId::from(42); // pick an arbitrary session id for the bench, needed to derive the PRSS state

    //Going with a sync network even though PRSS init_with_abort can work in both
    let mut sess =
        get_base_session_for_parties(num_parties, threshold, bench_role, NetworkMode::Sync);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let prss: PRSSSetup<ResiduePolyF8Z128> = rt
        .block_on(async {
            RobustRealPrssInit::<DummyAgreeRandomFromShare, DummyVss>::default()
                .init(&mut sess)
                .await
        })
        .unwrap();

    let mut state = prss.new_prss_session_state(sid);

    for size in &sizes {
        group.bench_function(BenchmarkId::new("prss_mask_next", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let shares = state
                        .mask_next_vec(bench_role, B_SWITCH_SQUASH, *size)
                        .await
                        .unwrap();
                    black_box(shares);
                });
            });
        });
    }

    for size in &sizes {
        group.bench_function(BenchmarkId::new("prss_next", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let shares = state.prss_next_vec(bench_role, *size).await.unwrap();
                    black_box(shares);
                });
            });
        });
    }

    for size in &sizes {
        group.bench_function(BenchmarkId::new("przs_next", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let shares = state
                        .przs_next_vec(bench_role, threshold, *size)
                        .await
                        .unwrap();
                    black_box(shares);
                });
            });
        });
    }
}

pub fn get_base_session_for_parties(
    amount: usize,
    threshold: u8,
    role: Role,
    network_mode: NetworkMode,
) -> BaseSession {
    let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
    let net_producer = LocalNetworkingProducer::from_roles(parameters.roles());
    BaseSession::new(
        parameters,
        Arc::new(net_producer.user_net(role, network_mode, None)),
        AesRng::seed_from_u64(42),
    )
    .unwrap()
}

pub fn get_dummy_parameters_for_parties(
    amount: usize,
    threshold: u8,
    role: Role,
) -> SessionParameters {
    assert!(amount > 0);
    SessionParameters::new(
        threshold,
        SessionId::from(1),
        role,
        generate_fixed_roles(amount),
    )
    .unwrap()
}

criterion_group!(prss, bench_prss);
criterion_main!(prss);
