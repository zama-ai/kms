use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    computation::SessionId,
    execution::{agree_random::DummyAgreeRandom, prss::PRSSSetup},
    tests::helper::get_dummy_session_party_id,
};

fn bench_prss(c: &mut Criterion) {
    let sizes = vec![1_usize, 100, 10000];
    let mut group = c.benchmark_group("prss");

    let num_parties = 4;
    let threshold = 1;

    let sid = SessionId::from(42);

    let sess = get_dummy_session_party_id(num_parties, threshold, 1);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let prss = rt
        .block_on(async {
            PRSSSetup::party_epoch_init_sess::<DummyAgreeRandom>(sess, 123, 1).await
        })
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

criterion_group!(prss, bench_prss);
criterion_main!(prss);
