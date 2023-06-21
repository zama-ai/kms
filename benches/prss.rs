use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{computation::SessionId, execution::prss::PRSSSetup};
use rand::SeedableRng;

fn bench_prss(c: &mut Criterion) {
    let sizes = vec![1_usize, 100, 10000];
    let mut group = c.benchmark_group("prss");

    let num_parties = 4;
    let threshold = 1;

    let sid = SessionId::from(42);

    let mut rng = AesRng::from_entropy();
    let prss = PRSSSetup::epoch_init(num_parties, threshold, &mut rng).unwrap();

    let mut state = prss.new_session(sid);

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
