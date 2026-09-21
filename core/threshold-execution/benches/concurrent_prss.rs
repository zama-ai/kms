use algebra::{
    PRSSConversions,
    galois_rings::{
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_8::ResiduePolyF8Z128,
    },
    structure_traits::{ErrorCorrect, Invert},
};
use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use futures::future::join_all;
use support::PrssWorkload;
use threshold_execution::small_execution::prss::DerivePRSSState;
use threshold_types::session_id::SessionId;
mod support;

const SHARES_PER_REQUEST: usize = 30_000;

fn workload_request_size(workload: PrssWorkload) -> usize {
    if matches!(workload, PrssWorkload::TripleInputs) {
        10_000
    } else {
        SHARES_PER_REQUEST
    }
}

fn bench_ring<Z: ErrorCorrect + Invert + PRSSConversions>(c: &mut Criterion, ring: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    for (parties, threshold) in [(4, 1), (13, 4)] {
        let prss_setup = support::setup_prss::<Z>(&rt, parties, threshold);
        let mut group = c.benchmark_group(format!(
            "concurrent_prss/{ring}/parties_{parties}_threshold_{threshold}"
        ));
        // A concurrent batch is expensive; flat sampling avoids increasing the number of batch executions in each
        // successive sample (default is linear sampling, where Criterion increases the iter count for each sample).
        group.sampling_mode(SamplingMode::Flat);
        // These sessions share one pool; production parties run on separate hosts.
        for sessions in [1_usize, 4, 13] {
            let mut prss_states: Vec<_> = (0..sessions)
                .map(|i| prss_setup.new_prss_session_state(SessionId::from(42 + i as u128)))
                .collect();
            for workload in PrssWorkload::for_ring::<Z>() {
                // Means triples for TripleInputs, shares for all others.
                let request_size = workload_request_size(workload);
                let generated_values = workload.output_value_count(request_size);
                group.throughput(Throughput::Elements((sessions * generated_values) as u64));
                group.bench_function(BenchmarkId::new(workload.name(), sessions), |b| {
                    b.iter(|| {
                        rt.block_on(join_all(prss_states.iter_mut().map(|prss_state| {
                            workload.run(prss_state, threshold, request_size)
                        })));
                    })
                });
            }
        }
        group.finish();
    }
}

fn bench_concurrent(c: &mut Criterion) {
    bench_ring::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_ring::<ResiduePolyF4Z128>(c, "f4_z128");
    bench_ring::<ResiduePolyF8Z128>(c, "f8_z128");
}

criterion_group!(concurrent_prss, bench_concurrent);
criterion_main!(concurrent_prss);
