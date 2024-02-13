use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    algebra::{residue_poly::ResiduePoly128, structure_traits::Ring},
    computation::SessionId,
    execution::{
        runtime::party::{Identity, Role},
        runtime::session::{SessionParameters, SmallSession, SmallSessionStruct},
        small_execution::{agree_random::DummyAgreeRandom, prss::PRSSSetup},
    },
    networking::local::LocalNetworkingProducer,
};
use rand::SeedableRng;

fn bench_prss(c: &mut Criterion) {
    let sizes = vec![1_usize, 100, 10000];
    let mut group = c.benchmark_group("prss");

    let num_parties = 7;
    let threshold = 2;

    let sid = SessionId::from(42);

    let mut sess = get_small_session_for_parties(num_parties, threshold, Role::indexed_by_one(1));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let prss = rt
        .block_on(async {
            PRSSSetup::init_with_abort::<
                DummyAgreeRandom,
                AesRng,
                SmallSessionStruct<ResiduePoly128, AesRng, SessionParameters>,
            >(&mut sess)
            .await
        })
        .unwrap();

    let mut state = prss.new_prss_session_state(sid);

    for size in &sizes {
        group.bench_function(BenchmarkId::new("prss_mask_next", size), |b| {
            b.iter(|| {
                for _ in 0..*size {
                    let _e_shares = state.mask_next(1, 1_u128 << 114);
                }
            });
        });
    }
}

pub fn get_small_session_for_parties<Z: Ring>(
    amount: usize,
    threshold: u8,
    role: Role,
) -> SmallSession<Z> {
    let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
    let id = parameters.own_identity.clone();
    let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
    SmallSession {
        parameters,
        network: Arc::new(net_producer.user_net(id)),
        rng: AesRng::seed_from_u64(42),
        corrupt_roles: HashSet::new(),
        prss_state: None,
    }
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
        session_id: SessionId(1),
        own_identity: role_assignment.get(&role).unwrap().clone(),
        role_assignments: role_assignment,
    }
}

criterion_group!(prss, bench_prss);
criterion_main!(prss);
