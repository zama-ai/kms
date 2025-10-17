#[cfg(feature = "measure_memory")]
use threshold_fhe::allocator::MEM_ALLOCATOR;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::tfhe_internals::parameters::{
    BC_PARAMS_SNS, NIST_PARAMS_P32_SNS_FGLWE, NIST_PARAMS_P32_SNS_LWE, NIST_PARAMS_P8_SNS_FGLWE,
    NIST_PARAMS_P8_SNS_LWE,
};

#[cfg(feature = "measure_memory")]
fn print_memory_usage(bench_name: String, results: Vec<usize>) {
    let num_runs = results.len();
    // Compute mean and std deviation of the results
    let mean = results.iter().sum::<usize>() as f64 / num_runs as f64;
    let std_dv = (results
        .iter()
        .map(|x| (*x as f64 - mean).powi(2))
        .sum::<f64>()
        / num_runs as f64)
        .sqrt();
    let sorted = {
        let mut sorted = results.clone();
        sorted.sort();
        sorted
    };
    let min = sorted.first().unwrap();
    let max = sorted.last().unwrap();
    let median = sorted[sorted.len() / 2];
    println!(
        "Memory usage for {bench_name} (avg over {num_runs} runs) : {mean} B.
        \t [min:{min}, median:{median}, max:{max}]
        \t STD_DV: {std_dv}\n"
    );
}

#[cfg(feature = "measure_memory")]
pub fn bench_memory<
    I: Clone + Send + Sync + 'static,
    O: Send + 'static,
    F: Fn(I) -> O + Clone + Send + Sync + 'static,
>(
    bench_fn: F,
    input: I,
    bench_name: String,
) {
    let mut results = Vec::new();

    for _ in 0..10 {
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();
        let input = input.clone();
        let bench_fn = bench_fn.clone();
        std::hint::black_box(bench_fn(input));
        results.push(MEM_ALLOCATOR.get().unwrap().peak_usage());
    }
    print_memory_usage(bench_name, results);
}

pub const ALL_PARAMS: [(&str, DKGParams); 5] = [
    ("NIST_PARAMS_P32_SNS_FGLWE", NIST_PARAMS_P32_SNS_FGLWE),
    ("NIST_PARAMS_P32_SNS_LWE", NIST_PARAMS_P32_SNS_LWE),
    ("NIST_PARAMS_P8_SNS_FGLWE", NIST_PARAMS_P8_SNS_FGLWE),
    ("NIST_PARAMS_P8_SNS_LWE", NIST_PARAMS_P8_SNS_LWE),
    ("BC_PARAMS_SNS", BC_PARAMS_SNS),
];
