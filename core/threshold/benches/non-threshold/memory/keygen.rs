#[path = "../../utilities.rs"]
mod utilities;

use crate::utilities::generate_tfhe_keys;
use crate::utilities::set_plan;
use utilities::bench_memory;
use utilities::ALL_PARAMS;

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

fn main() {
    set_plan();
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    for (name, params) in ALL_PARAMS {
        let bench_name = format!("non-threshold_keygen_{name}_memory");
        bench_memory(generate_tfhe_keys, params, bench_name);
    }
}
