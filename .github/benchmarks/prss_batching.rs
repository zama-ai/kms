// TEMP: REMOVE BEFORE MERGE. Exact request harness for the PRSS/PRZS batching investigation.
use algebra::{
    PRSSConversions,
    galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
    structure_traits::{ErrorCorrect, Invert},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use threshold_execution::small_execution::prss::{DerivePRSSState, PRSSPrimitives, PRSSSetup};
use threshold_types::{role::Role, session_id::SessionId};

macro_rules! session_state {
    ($setup:expr, $sid:expr, $role:expr) => {
        $setup.new_prss_session_state($sid, $role).unwrap()
    };
}

fn bench_ring<Z: ErrorCorrect + Invert + PRSSConversions>(c: &mut Criterion, ring: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let role = Role::indexed_from_one(1);
    let sid = SessionId::from(42);
    for (parties, threshold) in [(4, 1), (13, 4)] {
        let setup = rt
            .block_on(PRSSSetup::<Z>::testing_party_epoch_init(
                parties, threshold, role,
            ))
            .unwrap();
        let mut group = c.benchmark_group(format!(
            "prss/{ring}/parties_{parties}_threshold_{threshold}"
        ));
        group.bench_function("new_prss_session_state", |b| {
            b.iter(|| black_box(session_state!(setup, black_box(sid), role)));
        });
        for (name, amount) in [
            ("prss_next", 30_000),
            ("przs_next", 10_000),
            ("triple_inputs", 10_000),
            ("prss_mask_next", 1),
            ("prss_mask_next", 16),
            ("prss_mask_next", 30_000),
        ] {
            if name == "prss_mask_next" && Z::CHAR_LOG2 != 128 {
                continue;
            }
            let mut state = session_state!(setup, sid, role);
            let output_count = if name == "triple_inputs" {
                amount * 4
            } else {
                amount
            };
            group.throughput(Throughput::Elements(output_count as u64));
            group.bench_function(BenchmarkId::new(name, amount), |b| {
                b.iter(|| {
                    rt.block_on(async {
                        match name {
                            "prss_next" => {
                                black_box(state.prss_next_vec(role, amount).await.unwrap());
                            }
                            "przs_next" => {
                                black_box(
                                    state
                                        .przs_next_vec(role, threshold as u8, amount)
                                        .await
                                        .unwrap(),
                                );
                            }
                            "prss_mask_next" => {
                                black_box(
                                    state.mask_next_vec(role, 1 << 70, amount).await.unwrap(),
                                );
                            }
                            "triple_inputs" => {
                                let prss = state.prss_next_vec(role, 3 * amount).await.unwrap();
                                let przs = state
                                    .przs_next_vec(role, threshold as u8, amount)
                                    .await
                                    .unwrap();
                                black_box((prss, przs));
                            }
                            _ => unreachable!(),
                        }
                    });
                });
            });
        }
        group.finish();
    }
}

fn bench_prss(c: &mut Criterion) {
    bench_ring::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_ring::<ResiduePolyF4Z128>(c, "f4_z128");
}

criterion_group!(benches, bench_prss);
criterion_main!(benches);
