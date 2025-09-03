#[path = "../utilities.rs"]
mod utilities;

use criterion::measurement::Measurement;
#[cfg(not(feature = "measure_memory"))]
use criterion::{measurement::WallTime, Throughput};
use criterion::{BenchmarkGroup, Criterion};
use tfhe::Config;
use tfhe::{ClientKey, ConfigBuilder, ServerKey};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "measure_memory")]
use utilities::MemoryProfiler;
use utilities::ALL_PARAMS;

fn keygen(config: Config) -> (ClientKey, ServerKey) {
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);
    (cks, sks)
}

fn bench_keygen<M: Measurement>(c: &mut BenchmarkGroup<'_, M>, params: DKGParams) {
    let config = ConfigBuilder::with_custom_parameters(
        params
            .get_params_basics_handle()
            .to_classic_pbs_parameters(),
    )
    .build();

    c.bench_function("keygen", |b| {
        b.iter(|| std::hint::black_box(keygen(config)));
    });
}

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

#[allow(unused_mut)]
fn main() {
    #[cfg(feature = "measure_memory")]
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    for (name, params) in ALL_PARAMS {
        let mut c = Criterion::default().sample_size(10).configure_from_args();
        #[cfg(feature = "measure_memory")]
        let mut c = c.with_profiler(MemoryProfiler);

        let bench_name = format!("non-threshold_keygen_{name}");
        #[cfg(feature = "measure_memory")]
        let bench_name = format!("{bench_name}_memory");
        // FheUint64 latency
        {
            let mut group = c.benchmark_group(&bench_name);

            bench_keygen(&mut group, params);

            group.finish();
        }

        c.final_summary();
    }
}
