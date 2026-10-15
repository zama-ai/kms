//! Before/after benchmark of the reconstruction step of openings: the optimistic path (interpolate from
//! `degree + 1` shares on the prepared Lagrange constants, accept only if every share agrees; AVX-512 IFMA for
//! `ResiduePolyF4Z128`) in front of the error-correcting decoder, against the decoder alone.
//!
//! The switch is the `MPC_RECONSTRUCT` environment variable (`decoder` disables the optimistic path), so the
//! comparison is two runs of the same binary:
//!
//! ```text
//! cargo bench -p threshold-execution -F testing --bench open_lincomb                         # optimistic (default)
//! MPC_RECONSTRUCT=decoder cargo bench -p threshold-execution -F testing --bench open_lincomb # before
//! ```
//!
//! Two shapes, as in the code: `robust_open` reconstructs degree-`t` sharings the way `robust_open_list_to_all`
//! does in a synchronous session (`reconstruct_w_errors_sync`, no known bots), `d_values` reconstructs the
//! degree-`2t` sharings of triple generation (`error_reconstruct_with_hints` at the decoder's capacity). Each
//! measured call builds the `ReconstructionHints` for the owner set, as every reconstruction attempt does, and
//! reconstructs the whole batch (batches of more than 256 go to Rayon in tasks of 256). The `honest`
//! scenario has every share correct; `one_error` has one wrong share per sharing, so every sharing fails the
//! optimistic check and goes to the decoder: that is the worst case, the cost of the check on top of the
//! decoder.

use algebra::error_correction::ReconstructionHints;
use algebra::galois_rings::degree_4::ResiduePolyF4Z128;
use algebra::sharing::shamir::{InputOp, RevealOp, ShamirSharings, reconstruct_w_errors_sync};
use algebra::sharing::share::Share;
use algebra::structure_traits::{ErrorCorrect, Sample};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_execution::constants::RECONSTRUCT_OPTIMISTIC;
use threshold_execution::sharing::open::reconstruct_batch;
use threshold_types::rng::AesRng;

const BATCHES: [usize; 4] = [1, 16, 256, 4096];
const PARTIES: [(usize, usize); 2] = [(7, 2), (13, 4)];
/// Sharings per Rayon task, the default of `MPC_ROBUST_OPEN_PAR_MIN_CHUNK`.
const PAR_CHUNK: usize = 256;

/// The decoder a shape falls back to for the sharings the optimistic path does not settle.
type Fallback = dyn Fn(
        &ShamirSharings<ResiduePolyF4Z128>,
        &ReconstructionHints<ResiduePolyF4Z128>,
    ) -> Option<ResiduePolyF4Z128>
    + Sync;

fn sharings<Z: ErrorCorrect + Sample>(
    rng: &mut AesRng,
    count: usize,
    num_parties: usize,
    degree: usize,
    corrupt_one: bool,
) -> Vec<ShamirSharings<Z>> {
    (0..count)
        .map(|k| {
            let secret = Z::sample(rng);
            let mut sharing = ShamirSharings::share(rng, secret, num_parties, degree).unwrap();
            if corrupt_one {
                // A different wrong share per sharing, inside and outside the interpolation set.
                let position = k % num_parties;
                let share = sharing.shares[position];
                sharing.shares[position] = Share::new(share.owner(), share.value() + Z::ONE);
            }
            sharing
        })
        .collect()
}

fn bench_shape(
    c: &mut Criterion,
    series: &str,
    shape: &str,
    num_parties: usize,
    threshold: usize,
    degree: usize,
    fallback: &Fallback,
) {
    let mut rng = AesRng::seed_from_u64(42);
    for (scenario, corrupt_one) in [("honest", false), ("one_error", true)] {
        let mut group = c.benchmark_group(format!(
            "reconstruct/{series}/F4Z128/{shape}_n{num_parties}_t{threshold}_d{degree}/{scenario}"
        ));
        for batch in BATCHES {
            let batch_sharings =
                sharings::<ResiduePolyF4Z128>(&mut rng, batch, num_parties, degree, corrupt_one);
            group.throughput(Throughput::Elements(batch as u64));
            group.bench_with_input(BenchmarkId::from_parameter(batch), &batch, |b, _| {
                b.iter(|| {
                    let hints = ReconstructionHints::new(&batch_sharings[0], degree).unwrap();
                    let out = reconstruct_batch(
                        &batch_sharings,
                        &hints,
                        degree + 1,
                        PAR_CHUNK,
                        |sharing| fallback(sharing, &hints),
                    );
                    black_box(out);
                });
            });
        }
        group.finish();
    }
}

fn bench_open_lincomb(c: &mut Criterion) {
    let series = if *RECONSTRUCT_OPTIMISTIC {
        "Optimistic"
    } else {
        "Decoder"
    };
    println!(
        "reconstruction: {series} (set MPC_RECONSTRUCT=decoder to disable the optimistic path); lincomb backend {:?}",
        algebra::lincomb::LinearCombinator::<ResiduePolyF4Z128>::detected_backend()
    );
    for (num_parties, threshold) in PARTIES {
        // Robust open of degree-t sharings, synchronous network, no known bots.
        let degree = threshold;
        bench_shape(
            c,
            series,
            "robust_open",
            num_parties,
            threshold,
            degree,
            &move |sharing, hints| {
                reconstruct_w_errors_sync(num_parties, degree, threshold, 0, sharing, hints)
                    .unwrap_or_default()
            },
        );
        // d-values of triple generation: degree 2t at the decoder's capacity.
        let degree = 2 * threshold;
        let max_errors = (num_parties - (degree + 1)) / 2;
        bench_shape(
            c,
            series,
            "d_values",
            num_parties,
            threshold,
            degree,
            &move |sharing, hints| {
                sharing
                    .error_reconstruct_with_hints(degree, max_errors, hints)
                    .ok()
            },
        );
    }
    // The hints alone, built once per reconstruction attempt (with the optimistic constants, prepared on
    // first use, in the optimistic series).
    let mut group = c.benchmark_group(format!("reconstruct/{series}/F4Z128/hints"));
    let mut rng = AesRng::seed_from_u64(7);
    for (num_parties, threshold) in PARTIES {
        for degree in [threshold, 2 * threshold] {
            let sharing = sharings::<ResiduePolyF4Z128>(&mut rng, 1, num_parties, degree, false);
            group.bench_function(format!("n{num_parties}_t{threshold}_d{degree}"), |b| {
                b.iter(|| {
                    let hints = ReconstructionHints::new(&sharing[0], degree).unwrap();
                    if *RECONSTRUCT_OPTIMISTIC {
                        black_box(hints.optimistic().is_some());
                    }
                    black_box(hints)
                });
            });
        }
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_open_lincomb
}
criterion_main!(benches);
