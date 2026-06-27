use std::hint::black_box;
use std::sync::Arc;

use aes_prng::AesRng;
use algebra::base_ring::Z128;
use algebra::galois_rings::degree_8::ResiduePolyF8Z128;
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
        prf::{
            PrfKey,
            testing::{
                ChiAesHandle, PsiAesHandle, chi_2, chi_original, psi_2, psi_original,
            },
        },
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

    let psi_aes = PsiAesHandle::new(&PrfKey([23_u8; 16]), sid);
    let chi_aes = ChiAesHandle::new(&PrfKey([23_u8; 16]), sid);
    assert_eq!(
        psi_original::<ResiduePolyF8Z128>(&psi_aes, 0).unwrap(),
        psi_2::<Z128, 8>(&psi_aes, 0).unwrap()
    );
    assert_eq!(
        chi_original::<ResiduePolyF8Z128>(&chi_aes, 0, 1).unwrap(),
        chi_2::<Z128, 8>(&chi_aes, 0, 1).unwrap()
    );

    for size in &sizes {
        group.bench_function(BenchmarkId::new("psi_original_f8_z128", size), |b| {
            let mut ctr = 0_u128;
            b.iter(|| {
                let mut shares = Vec::with_capacity(*size);
                for _ in 0..*size {
                    shares
                        .push(psi_original::<ResiduePolyF8Z128>(&psi_aes, black_box(ctr)).unwrap());
                    ctr += 1;
                }
                black_box(shares);
            });
        });

        group.bench_function(BenchmarkId::new("psi_2_f8_z128", size), |b| {
            let mut ctr = 0_u128;
            b.iter(|| {
                let mut shares = Vec::with_capacity(*size);
                for _ in 0..*size {
                    shares.push(psi_2::<Z128, 8>(&psi_aes, black_box(ctr)).unwrap());
                    ctr += 1;
                }
                black_box(shares);
            });
        });

        group.bench_function(BenchmarkId::new("chi_original_f8_z128", size), |b| {
            let mut ctr = 0_u128;
            b.iter(|| {
                let mut shares = Vec::with_capacity(*size);
                for _ in 0..*size {
                    shares.push(
                        chi_original::<ResiduePolyF8Z128>(&chi_aes, black_box(ctr), 1).unwrap(),
                    );
                    ctr += 1;
                }
                black_box(shares);
            });
        });

        group.bench_function(BenchmarkId::new("chi_2_f8_z128", size), |b| {
            let mut ctr = 0_u128;
            b.iter(|| {
                let mut shares = Vec::with_capacity(*size);
                for _ in 0..*size {
                    shares.push(chi_2::<Z128, 8>(&chi_aes, black_box(ctr), 1).unwrap());
                    ctr += 1;
                }
                black_box(shares);
            });
        });
    }

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
