#[cfg(feature = "measure_memory")]
use criterion::profiler::Profiler;
#[cfg(feature = "measure_memory")]
use threshold_fhe::allocator::MEM_ALLOCATOR;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::tfhe_internals::parameters::{
    BC_PARAMS_SNS, NIST_PARAMS_P32_SNS_FGLWE, NIST_PARAMS_P32_SNS_LWE, NIST_PARAMS_P8_SNS_FGLWE,
    NIST_PARAMS_P8_SNS_LWE,
};

/// Best workaround to using criterion to measure memory seems to be using the Profiler.
/// We can then get memory reporting using
/// cargo bench -- --profile-time <num_seconds>
/// inspired by this discussion:
/// https://github.com/bheisler/criterion.rs/issues/97
///
/// Couple of issues though:
/// - we are most likely also measuring criterion's overhead
/// - we are only measuring memory allocated on the heap
#[cfg(feature = "measure_memory")]
pub struct MemoryProfiler;

#[cfg(feature = "measure_memory")]
impl Profiler for MemoryProfiler {
    fn start_profiling(&mut self, _: &str, _: &std::path::Path) {
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();
        println!(
            "\nABOUT TO START MEMORY PROFILER, RESET PEAK USAGE TO CURRENT {}",
            MEM_ALLOCATOR.get().unwrap().peak_usage()
        );
    }

    fn stop_profiling(&mut self, _: &str, _: &std::path::Path) {
        let size = MEM_ALLOCATOR.get().unwrap().peak_usage();
        println!("Profiling finished. Allocated {} B", size);
    }
}

pub const ALL_PARAMS: [(&str, DKGParams); 5] = [
    ("NIST_PARAMS_P32_SNS_FGLWE", NIST_PARAMS_P32_SNS_FGLWE),
    ("NIST_PARAMS_P32_SNS_LWE", NIST_PARAMS_P32_SNS_LWE),
    ("NIST_PARAMS_P8_SNS_FGLWE", NIST_PARAMS_P8_SNS_FGLWE),
    ("NIST_PARAMS_P8_SNS_LWE", NIST_PARAMS_P8_SNS_LWE),
    ("BC_PARAMS_SNS", BC_PARAMS_SNS),
];
