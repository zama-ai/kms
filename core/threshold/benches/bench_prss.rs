use std::{collections::HashMap, sync::Arc};

use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::SeedableRng;
use threshold_fhe::{
    algebra::galois_rings::degree_8::ResiduePolyF8Z128,
    execution::{
        large_execution::vss::DummyVss,
        runtime::{
            party::{Identity, Role},
            session::{BaseSessionStruct, SessionParameters},
        },
        small_execution::{
            agree_random::DummyAgreeRandomFromShare,
            prss::{DerivePRSSState, PRSSInit, PRSSPrimitives, PRSSSetup, RobustRealPrssInit},
        },
    },
    networking::{local::LocalNetworkingProducer, NetworkMode},
    session_id::SessionId,
};

fn bench_prss(c: &mut Criterion) {
    let sizes = vec![1_usize, 100, 10000];
    let mut group = c.benchmark_group("prss");

    let num_parties = 7;
    let threshold = 2;

    let sid = SessionId::from(42);

    //Going with sync although PRSS init_with_abort can work in both
    let mut sess = get_base_session_for_parties(
        num_parties,
        threshold,
        Role::indexed_by_one(1),
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

    for size in &sizes {
        group.bench_function(BenchmarkId::new("prss_mask_next", size), |b| {
            b.iter(|| {
                for _ in 0..*size {
                    let _e_shares = state.mask_next(Role::indexed_by_one(1), 1_u128 << 70);
                }
            });
        });
    }
}

pub fn get_base_session_for_parties(
    amount: usize,
    threshold: u8,
    role: Role,
    network_mode: NetworkMode,
) -> BaseSessionStruct<AesRng, SessionParameters> {
    let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
    let id = parameters.own_identity.clone();
    let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
    BaseSessionStruct::new(
        parameters,
        Arc::new(net_producer.user_net(id, network_mode, None)),
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
    let mut role_assignment = HashMap::new();
    for i in 0..amount {
        role_assignment.insert(
            Role::indexed_by_zero(i),
            Identity(format!("localhost:{}", 5000 + i)),
        );
    }
    SessionParameters {
        threshold,
        session_id: SessionId::from(1),
        own_identity: role_assignment.get(&role).unwrap().clone(),
        role_assignments: role_assignment,
    }
}

criterion_group!(prss, bench_prss);
criterion_main!(prss);
