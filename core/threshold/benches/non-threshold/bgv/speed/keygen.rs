#[path = "../../../utilities.rs"]
mod utilities;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use tfhe::core_crypto::seeders::new_seeder;
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::bgv::utils::XofWrapper;
use threshold_fhe::experimental::constants::*;

fn bench_keygen(c: &mut BenchmarkGroup<'_, WallTime>) {
    let mut seeder = new_seeder();
    let seed = seeder.seed().0;
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let mut xof = XofWrapper::new_bgv_kg(seed);
            std::hint::black_box(keygen::<_, LevelEll, LevelKsw, N65536>(
                &mut xof,
                PLAINTEXT_MODULUS.get().0,
            ))
        });
    });
}

fn main() {
    let mut c = Criterion::default().sample_size(10).configure_from_args();

    {
        let bench_name = "non-threshold_keygen_bgv".to_string();
        let mut group = c.benchmark_group(&bench_name);

        bench_keygen(&mut group);

        group.finish();
    }

    c.final_summary();
}
