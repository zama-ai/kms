#[path = "../../../utilities.rs"]
mod utilities;

use tfhe::core_crypto::seeders::new_seeder;
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::bgv::utils::XofWrapper;
use threshold_fhe::experimental::constants::*;
use utilities::bench_memory;

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

fn main() {
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    let mut seeder = new_seeder();
    let mut seed = seeder.seed().0;
    bench_memory(
        |seed: &mut u128| {
            let mut xof = XofWrapper::new_bgv_kg(*seed);
            keygen::<_, LevelEll, LevelKsw, N65536>(&mut xof, PLAINTEXT_MODULUS.get().0)
        },
        &mut seed,
        "non-threshold_keygen_bgv_memory".to_string(),
    );
}
