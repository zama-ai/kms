#[path = "../../../utilities.rs"]
mod utilities;

use aes_prng::AesRng;
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::constants::*;

fn bench_keygen(c: &mut BenchmarkGroup<'_, WallTime>) {
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let mut rng = AesRng::from_random_seed();
            std::hint::black_box(keygen::<AesRng, LevelEll, LevelKsw, N65536>(
                &mut rng,
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
