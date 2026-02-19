#[path = "../../../utilities.rs"]
mod utilities;

use aes_prng::AesRng;
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::constants::*;
use utilities::bench_memory;

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

fn main() {
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    let mut rng = AesRng::from_random_seed();
    let bench_name = "non-threshold_keygen_bgv_memory".to_string();
    bench_memory(
        |rng: &mut AesRng| {
            keygen::<AesRng, LevelEll, LevelKsw, N65536>(rng, PLAINTEXT_MODULUS.get().0)
        },
        &mut rng,
        bench_name,
    );
}
