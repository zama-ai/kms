#[path = "../../utilities.rs"]
mod utilities;

use crate::utilities::generate_tfhe_keys;
use crate::utilities::set_plan;
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use utilities::ALL_PARAMS;

fn bench_keygen(c: &mut BenchmarkGroup<'_, WallTime>, params: DKGParams) {
    c.bench_function("keygen", |b| {
        b.iter(|| std::hint::black_box(generate_tfhe_keys(&params)));
    });
}

fn main() {
    set_plan();
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
