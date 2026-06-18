//! Focused reconstruction microbench for the A/B (branch vs `main`) comparison of the
//! opening/reconstruction allocation work. Isolates `error_correct_with_hints` (the DKG opening
//! hot path) with no errors (the honest/production case) — no FHE, no network, no rayon.
//!
//! Run: `cargo test -p threshold-algebra --test recon_bench -- --ignored --nocapture`
//! Override iterations with `RECON_ITERS=NNN`.

use aes_prng::AesRng;
use rand::SeedableRng;
use std::time::Instant;
use threshold_algebra::{
    error_correction::ReconstructionHints,
    galois_rings::degree_4::ResiduePolyF4Z128,
    sharing::shamir::{InputOp, ShamirSharings},
    structure_traits::{ErrorCorrect, Sample},
};

fn bench_config(n: usize, threshold: usize, iters: usize) {
    let degree = threshold;
    let max_errors = threshold;

    let mut rng = AesRng::seed_from_u64(42);
    let secret = ResiduePolyF4Z128::sample(&mut rng);
    let sharing = ShamirSharings::share(&mut rng, secret, n, threshold).unwrap();
    let hints = ReconstructionHints::new(&sharing, degree).unwrap();

    // Warm the memoized exceptional-power store + caches before timing.
    for _ in 0..2_000 {
        let r = ResiduePolyF4Z128::error_correct_with_hints(&sharing, degree, max_errors, &hints)
            .unwrap();
        std::hint::black_box(&r);
    }

    let t0 = Instant::now();
    for _ in 0..iters {
        let r = ResiduePolyF4Z128::error_correct_with_hints(&sharing, degree, max_errors, &hints)
            .unwrap();
        std::hint::black_box(&r);
    }
    let el = t0.elapsed();
    println!(
        "RECON_BENCH n={n} t={threshold} iters={iters} total={:.3}s per_op={:.3}us",
        el.as_secs_f64(),
        el.as_secs_f64() * 1e6 / iters as f64
    );
}

#[test]
#[ignore = "microbench, run explicitly with --ignored --nocapture"]
fn recon_bench() {
    let iters: usize = std::env::var("RECON_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    bench_config(4, 1, iters);
    bench_config(13, 4, iters);
}
