use std::hint::black_box;
use std::sync::Arc;

use aes_prng::AesRng;
use algebra::galois_rings::degree_8::ResiduePolyF8Z128;
use algebra::structure_traits::{Sample, Zero};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
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
    let sizes = vec![1_usize, 100, 10_000];
    let mask_sizes = vec![1_usize, 100, 10_000, 100_000];
    let mut group = c.benchmark_group("prss");

    let num_parties = 7;
    let threshold = 2;

    let sid = SessionId::from(42);

    //Going with sync although PRSS init_with_abort can work in both
    let mut sess = get_base_session_for_parties(
        num_parties,
        threshold,
        Role::indexed_from_one(1),
        NetworkMode::Sync,
    );

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

    for size in &mask_sizes {
        group.bench_function(BenchmarkId::new("prss_mask_next", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let shares = state
                        .mask_next_vec(Role::indexed_from_one(1), 1_u128 << 70, *size)
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
                    let shares = state
                        .prss_next_vec(Role::indexed_from_one(1), *size)
                        .await
                        .unwrap();
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
                        .przs_next_vec(Role::indexed_from_one(1), threshold, *size)
                        .await
                        .unwrap();
                    black_box(shares);
                });
            });
        });
    }

    // Decomposition probe: isolate the Karatsuba multiply that prss_next does per set
    // (`f_a * psi`), WITHOUT the psi AES generation or allocation. For n=7,t=2 each party is in
    // C(6,2) = 15 sets, and prss_next does one full ResiduePolyF8Z128 multiply per set per element.
    // Comparing this to prss_next/<size> shows how much of prss_next is the (AES-independent)
    // multiply vs the AES+allocation in psi.
    let num_sets = 15usize;
    let mut mul_rng = AesRng::seed_from_u64(7);
    let f_as: Vec<ResiduePolyF8Z128> = (0..num_sets)
        .map(|_| ResiduePolyF8Z128::sample(&mut mul_rng))
        .collect();
    let psis: Vec<ResiduePolyF8Z128> = (0..num_sets)
        .map(|_| ResiduePolyF8Z128::sample(&mut mul_rng))
        .collect();
    for size in &sizes {
        group.bench_function(BenchmarkId::new("prss_mul_only", size), |b| {
            b.iter(|| {
                let mut acc = ResiduePolyF8Z128::ZERO;
                for _ in 0..*size {
                    for s in 0..num_sets {
                        acc += black_box(f_as[s]) * black_box(psis[s]);
                    }
                }
                black_box(acc);
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
