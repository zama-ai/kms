use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    computation::SessionId,
    execution::{
        agree_random::DummyAgreeRandom,
        party::{Identity, Role},
        session::{SessionParameters, SmallSession},
        small_execution::prss::PRSSSetup,
    },
    networking::local::LocalNetworkingProducer,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_prss(c: &mut Criterion) {
    let sizes = vec![1_usize, 100, 10000];
    let mut group = c.benchmark_group("prss");

    let num_parties = 4;
    let threshold = 1;

    let sid = SessionId::from(42);

    let sess = get_small_session_for_parties(num_parties, threshold, Role(1));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let prss = rt
        .block_on(async { PRSSSetup::party_epoch_init_sess::<DummyAgreeRandom>(&sess, 1).await })
        .unwrap();

    let mut state = prss.new_prss_session_state(sid);

    for size in &sizes {
        group.bench_function(BenchmarkId::new("prss_next", size), |b| {
            b.iter(|| {
                for _ in 0..*size {
                    let _e_shares = state.next(1);
                }
            });
        });
    }
}

pub fn get_small_session_for_parties(amount: usize, threshold: u8, role: Role) -> SmallSession {
    let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
    let id = parameters.own_identity.clone();
    let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
    SmallSession {
        parameters,
        network: Arc::new(net_producer.user_net(id)),
        rng: ChaCha20Rng::seed_from_u64(42),
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
            Role::from_zero(i),
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
