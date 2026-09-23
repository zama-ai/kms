//! Temporary E2 experiment: compare complete PRSS requests at different AES counter-group sizes.
use algebra::{
    PRSSConversions,
    galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
    structure_traits::{ErrorCorrect, Invert},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use threshold_execution::small_execution::prss::{DerivePRSSState, PRSSPrimitives};
use threshold_types::{role::Role, session_id::SessionId};

mod support;

fn bench_ring<Z: ErrorCorrect + Invert + PRSSConversions>(c: &mut Criterion, ring: &str) {
    const AMOUNT: usize = 30_000;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let setup = support::setup_prss::<Z>(&rt, 13, 4);
    let initial = setup.new_prss_session_state(SessionId::from(42));
    let role = Role::indexed_from_one(1);
    let mut group = c.benchmark_group(format!("prss_groups/{ring}/parties_13_threshold_4"));
    group.throughput(Throughput::Elements(AMOUNT as u64));

    // Every case starts with identical keys/counters, with setup and state cloning
    // outside timing. Const parameters give each group size its own compiled loop.
    macro_rules! measure {
        ($name:expr, $($method:tt)+) => {{
            let mut state = initial.clone();
            group.bench_function(BenchmarkId::new($name, AMOUNT), |b| {
                b.iter(|| rt.block_on(async {
                    black_box(state.$($method)+(role, AMOUNT).await.unwrap());
                }));
            });
        }};
    }
    measure!("original", prss_next_vec_orig);
    measure!("scalar_iter", prss_next_vec_iter);
    measure!("pair_control", prss_next_vec);

    // One and two counters also check the cost of the generalized grouping code
    // against the dedicated scalar and pair controls above.
    measure!("counters_1", prss_next_vec_grouped::<1>);
    measure!("counters_2", prss_next_vec_grouped::<2>);
    measure!("counters_4", prss_next_vec_grouped::<4>);
    measure!("counters_5", prss_next_vec_grouped::<5>);
    measure!("counters_6", prss_next_vec_grouped::<6>);
    measure!("counters_8", prss_next_vec_grouped::<8>);
    measure!("counters_10", prss_next_vec_grouped::<10>);
    measure!("counters_11", prss_next_vec_grouped::<11>);
    measure!("counters_16", prss_next_vec_grouped::<16>);
    measure!("counters_21", prss_next_vec_grouped::<21>);
    group.finish();
}

fn bench_prss_groups(c: &mut Criterion) {
    bench_ring::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_ring::<ResiduePolyF4Z128>(c, "f4_z128");
}

criterion_group!(benches, bench_prss_groups);
criterion_main!(benches);
