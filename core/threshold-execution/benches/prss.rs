use algebra::{
    PRSSConversions,
    galois_rings::{
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
    },
    structure_traits::{ErrorCorrect, Invert},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

mod support;
use support::PrssWorkload;
use threshold_execution::small_execution::prss::DerivePRSSState;
use threshold_types::role::Role;
use threshold_types::session_id::SessionId;

fn bench_prss(c: &mut Criterion) {
    bench_ring::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_ring::<ResiduePolyF4Z128>(c, "f4_z128");
    bench_ring::<ResiduePolyF8Z64>(c, "f8_z64");
    bench_ring::<ResiduePolyF8Z128>(c, "f8_z128");
}

fn bench_ring<Z: ErrorCorrect + Invert + PRSSConversions>(c: &mut Criterion, ring: &str) {
    // Include small requests and the preprocessing request size.
    let sizes = [
        1_usize, 10, 100, 1024, 1025, 2047, 2048, 2049, 4096, 4097, 10_000, 30_000,
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    for (num_parties, threshold) in [(4, 1), (7, 2), (13, 4)] {
        let mut group = c.benchmark_group(format!(
            "prss/{ring}/parties_{num_parties}_threshold_{threshold}"
        ));

        let sid = SessionId::from(42); // pick an arbitrary session id for the bench, needed to derive the PRSS state

        let prss_setup = support::setup_prss::<Z>(&rt, num_parties, threshold);

        let role = Role::indexed_from_one(1);

        group.throughput(Throughput::Elements(1));
        group.bench_function("new_prss_session_state", |b| {
            b.iter(|| {
                black_box(
                    prss_setup
                        .new_prss_session_state(black_box(sid), role)
                        .unwrap(),
                )
            });
        });
        group.bench_function("new_prss_reference_state", |b| {
            b.iter(|| black_box(prss_setup.new_prss_reference_state(black_box(sid))));
        });
        for workload in PrssWorkload::for_ring::<Z>() {
            // Means triples for TripleInputs, shares for all others.
            let request_sizes: &[usize] = if matches!(workload, PrssWorkload::TripleInputs) {
                &[10_000]
            } else {
                &sizes
            };
            for &request_size in request_sizes {
                let mut prss_state = prss_setup.new_prss_session_state(sid, role).unwrap();
                group.throughput(Throughput::Elements(
                    workload.output_value_count(request_size) as u64,
                ));
                if matches!(workload, PrssWorkload::Prss) {
                    // Compare scalar implementations in one binary with identical
                    // session keys and starting counters. Setup/cloning is untimed;
                    // output disposal is timed in both cases.
                    let mut original_state = prss_setup.new_prss_reference_state(sid);
                    group.bench_function(BenchmarkId::new("prss_next_orig", request_size), |b| {
                        b.iter(|| {
                            rt.block_on(async {
                                black_box(
                                    original_state
                                        .prss_next_vec_orig(Role::indexed_from_one(1), request_size)
                                        .await
                                        .unwrap(),
                                );
                            })
                        });
                    });
                    // Keep the scalar iterator case adjacent to the original and
                    // prepared cases, with the same keys and initial counter.
                    let mut iterator_state = prss_setup.new_prss_reference_state(sid);
                    group.bench_function(BenchmarkId::new("prss_next_iter", request_size), |b| {
                        b.iter(|| {
                            rt.block_on(async {
                                black_box(
                                    iterator_state
                                        .prss_next_vec_iter(Role::indexed_from_one(1), request_size)
                                        .await
                                        .unwrap(),
                                );
                            })
                        });
                    });
                }
                if !matches!(workload, PrssWorkload::Prss) {
                    let mut reference = prss_setup.new_prss_reference_state(sid);
                    group.bench_function(
                        BenchmarkId::new(format!("{}_orig", workload.name()), request_size),
                        |b| {
                            b.iter(|| {
                                rt.block_on(workload.run(&mut reference, threshold, request_size))
                            })
                        },
                    );
                }
                group.bench_function(BenchmarkId::new(workload.name(), request_size), |b| {
                    b.iter(|| rt.block_on(workload.run(&mut prss_state, threshold, request_size)));
                });
            }
        }
        group.finish();
    }
}

criterion_group!(prss, bench_prss);
criterion_main!(prss);
