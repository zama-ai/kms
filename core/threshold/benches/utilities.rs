use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::{
    core_crypto::{prelude::NormalizedHammingWeightBound, seeders::new_seeder},
    xof_key_set::CompressedXofKeySet,
    ClientKey, Tag,
};
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
    eprintln!("Measuring memory usage for {bench_name}...");
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
    ("NIST_PARAMS_P32_SNS_LWE", NIST_PARAMS_P32_SNS_LWE),
    ("NIST_PARAMS_P32_SNS_FGLWE", NIST_PARAMS_P32_SNS_FGLWE),
    ("NIST_PARAMS_P8_SNS_FGLWE", NIST_PARAMS_P8_SNS_FGLWE),
    ("NIST_PARAMS_P8_SNS_LWE", NIST_PARAMS_P8_SNS_LWE),
    ("BC_PARAMS_SNS", BC_PARAMS_SNS),
];

pub fn set_plan() {
    for n in [512, 1024, 2048] {
        let my_plan = Plan::new(
            // n / 2 is due to how TFHE-rs handles ffts
            n / 2,
            Method::UserProvided {
                // User responsibility to choose an algorithm compatible with their n
                // Both for the algorithm and the base_n
                base_algo: FftAlgo::Dif4,
                base_n: n / 2,
            },
        );
        setup_custom_fft_plan(my_plan);
    }
}

pub fn generate_tfhe_keys(params: DKGParams) -> (ClientKey, CompressedXofKeySet) {
    let config = params.to_tfhe_config();

    // If the params do not have sk deviation, we set a default value of 1.0
    let max_norm_hwt = params
        .get_params_basics_handle()
        .get_sk_deviations()
        .map(|d| d.pmax)
        .unwrap_or(1.0);

    let mut seeder = new_seeder();
    let private_seed_bytes = seeder.seed().0.to_le_bytes().to_vec();

    CompressedXofKeySet::generate(
        config,
        private_seed_bytes,
        128,
        NormalizedHammingWeightBound::new(max_norm_hwt).expect("Invalid hwt bound for KAT"),
        Tag::from("BENCH"),
    )
    .expect("XofKeySet generation for KAT failed")
}
