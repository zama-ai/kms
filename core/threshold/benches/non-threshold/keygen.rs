#[path = "../utilities.rs"]
mod utilities;

#[cfg(not(feature = "measure_memory"))]
use criterion::measurement::WallTime;
#[cfg(not(feature = "measure_memory"))]
use criterion::{BenchmarkGroup, Criterion};
use tfhe::{ClientKey, Config, ServerKey};
#[cfg(not(feature = "measure_memory"))]
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "measure_memory")]
use utilities::bench_memory;
use utilities::ALL_PARAMS;

fn keygen(config: Config) -> (ClientKey, ServerKey) {
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    (cks, sks)
}

#[cfg(not(feature = "measure_memory"))]
fn bench_keygen(c: &mut BenchmarkGroup<'_, WallTime>, params: DKGParams) {
    let config = params.to_tfhe_config();

    c.bench_function("keygen", |b| {
        b.iter(|| std::hint::black_box(keygen(config)));
    });
}

#[cfg(not(feature = "measure_memory"))]
fn main() {
    for (name, params) in ALL_PARAMS {
        let mut c = Criterion::default().sample_size(10).configure_from_args();

        let bench_name = format!("non-threshold_keygen_{name}");
        // FheUint64 latency
        {
            let mut group = c.benchmark_group(&bench_name);

            bench_keygen(&mut group, params);

            group.finish();
        }

        c.final_summary();
    }
}

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

#[cfg(feature = "measure_memory")]
fn main() {
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    for (name, params) in ALL_PARAMS {
        let bench_name = format!("non-threshold_keygen_{name}_memory");
        let config = params.to_tfhe_config();
        bench_memory(keygen, config, bench_name);
    }
}
