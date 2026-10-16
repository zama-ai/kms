//! Benchmark of the reconstruction step of openings: error correction against error detection.
//!
//! `ErrorCorrect` decodes every sharing with the error-correcting decoder (Figure 59), as the openings did
//! before; `ErrorDetect` is [`reconstruct_batch`]: interpolate from `degree + 1` shares on the prepared
//! Lagrange constants, accept if every share agrees, and decode only the sharings that fail the check. The two
//! are the two functions of every benchmark group, measured in the same run on the same inputs with the same
//! Rayon chunking, so criterion prints them next to each other and, without `--noplot`, plots them against
//! each other in `target/criterion/report/index.html`:
//!
//! ```text
//! cargo bench -p threshold-execution -F testing --bench open_reconstruct
//! cargo bench -p threshold-execution -F testing --bench open_reconstruct -- --noplot 'n13_t4'
//! ```
//!
//! Two shapes, with the inputs as the code receives them. `robust_open` reconstructs degree-`t` sharings the
//! way `robust_open_list_to_all` does in a synchronous session (`reconstruct_w_errors_sync`, no known bots),
//! from the sharings the receive jobs filled in. `d_values` reconstructs the degree-`2t` sharings of triple
//! generation (`error_reconstruct_with_hints` at the decoder's capacity) from the vector of d-values every
//! party broadcast: each sharing is built from the vectors inside the measured call, by the Rayon task that
//! reconstructs it ([`reconstruct_batch_with`]), as `reconstruct_d_values` does. Each measured call builds the
//! `ReconstructionHints` for the owner set, as every reconstruction attempt does, and reconstructs the whole
//! batch on Rayon in tasks of at least 256 sharings. The `honest` scenario has every share correct;
//! `one_error` has one wrong share per sharing, so every sharing fails the check and is decoded: that is the
//! worst case for error detection, the cost of the check on top of the decoder. The `hints` group measures
//! the hints alone, built once per reconstruction attempt, and the share of the check's Lagrange constants in
//! them.

use algebra::error_correction::ReconstructionHints;
use algebra::galois_rings::degree_4::ResiduePolyF4Z128;
use algebra::sharing::optimistic::OptimisticHints;
use algebra::sharing::shamir::{InputOp, RevealOp, ShamirSharings, reconstruct_w_errors_sync};
use algebra::sharing::share::Share;
use algebra::structure_traits::{ErrorCorrect, Sample};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use std::hint::black_box;
use threshold_execution::sharing::open::{reconstruct_batch, reconstruct_batch_with};
use threshold_types::rng::AesRng;
use threshold_types::role::Role;

type Z = ResiduePolyF4Z128;

const BATCHES: [usize; 4] = [1, 16, 256, 4096];
const PARTIES: [(usize, usize); 2] = [(7, 2), (13, 4)];
/// Minimum sharings per Rayon task, the default of `MPC_ROBUST_OPEN_PAR_MIN_CHUNK` and
/// `MPC_D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK`.
const PAR_CHUNK: usize = 256;

/// The two functions of every group.
#[derive(Clone, Copy)]
enum Series {
    ErrorCorrect,
    ErrorDetect,
}

impl Series {
    const ALL: [Series; 2] = [Series::ErrorCorrect, Series::ErrorDetect];

    fn name(self) -> &'static str {
        match self {
            Series::ErrorCorrect => "ErrorCorrect",
            Series::ErrorDetect => "ErrorDetect",
        }
    }
}

/// The decoder a shape uses: for every sharing in `ErrorCorrect`, for the ones failing the check in
/// `ErrorDetect`.
type Decoder = dyn Fn(&ShamirSharings<Z>, &ReconstructionHints<Z>) -> Option<Z> + Sync;

/// The inputs of a batch as the code holds them when it reconstructs.
enum Inputs {
    /// The openings: the sharings, filled in by the receive jobs.
    Sharings(Vec<ShamirSharings<Z>>),
    /// The d-values: the vector every party broadcast, sharing `i` is share `i` of every vector.
    PartyVectors(Vec<(Role, Vec<Z>)>),
}

impl Inputs {
    fn from_sharings(shape: &str, sharings: Vec<ShamirSharings<Z>>) -> Self {
        match shape {
            "robust_open" => Self::Sharings(sharings),
            "d_values" => {
                let num_parties = sharings[0].shares.len();
                Self::PartyVectors(
                    (0..num_parties)
                        .map(|p| {
                            let role = sharings[0].shares[p].owner();
                            let values = sharings.iter().map(|s| s.shares[p].value()).collect();
                            (role, values)
                        })
                        .collect(),
                )
            }
            other => panic!("unknown shape {other}"),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Sharings(sharings) => sharings.len(),
            Self::PartyVectors(vectors) => vectors[0].1.len(),
        }
    }

    /// The hints of a reconstruction attempt, as `try_reconstruct_from_shares` and `reconstruct_d_values`
    /// build them.
    fn hints(&self, degree: usize) -> ReconstructionHints<Z> {
        match self {
            Self::Sharings(sharings) => ReconstructionHints::new(&sharings[0], degree).unwrap(),
            Self::PartyVectors(vectors) => {
                let roles = vectors.iter().map(|(role, _)| *role).collect();
                ReconstructionHints::from_parties(roles, degree).unwrap()
            }
        }
    }

    /// Sharing `i` of the party vectors, as `reconstruct_d_values` builds it.
    fn build(vectors: &[(Role, Vec<Z>)], i: usize) -> ShamirSharings<Z> {
        let shares = vectors
            .iter()
            .map(|(role, values)| Share::new(*role, values[i]))
            .collect();
        ShamirSharings::create(shares)
    }

    /// One measured call: the hints, then the reconstruction of the batch by `series`.
    fn reconstruct(&self, series: Series, degree: usize, decoder: &Decoder) -> Vec<Option<Z>> {
        let hints = self.hints(degree);
        let fallback = |sharing: &ShamirSharings<Z>| decoder(sharing, &hints);
        match (self, series) {
            (Self::Sharings(sharings), Series::ErrorCorrect) => correct_batch(sharings, &fallback),
            (Self::Sharings(sharings), Series::ErrorDetect) => {
                reconstruct_batch(sharings, &hints, degree + 1, PAR_CHUNK, fallback)
            }
            (Self::PartyVectors(vectors), Series::ErrorCorrect) => {
                correct_batch_with(self.len(), |i| Self::build(vectors, i), &fallback)
            }
            (Self::PartyVectors(vectors), Series::ErrorDetect) => reconstruct_batch_with(
                self.len(),
                |i| Self::build(vectors, i),
                &hints,
                degree + 1,
                PAR_CHUNK,
                fallback,
            ),
        }
    }
}

/// Error correction of every sharing: the reconstruction loop of `try_reconstruct_from_shares` before the
/// optimistic path, the Rayon tasks of [`reconstruct_batch`].
fn correct_batch<F>(sharings: &[ShamirSharings<Z>], decoder: &F) -> Vec<Option<Z>>
where
    F: Fn(&ShamirSharings<Z>) -> Option<Z> + Sync,
{
    sharings
        .par_iter()
        .with_min_len(PAR_CHUNK)
        .map(decoder)
        .collect()
}

/// Error correction of every sharing built on demand, each decoded as soon as it is built: the loop of
/// `reconstruct_d_values` before the optimistic path, the Rayon tasks of [`reconstruct_batch_with`].
fn correct_batch_with<B, F>(len: usize, build: B, decoder: &F) -> Vec<Option<Z>>
where
    B: Fn(usize) -> ShamirSharings<Z> + Sync,
    F: Fn(&ShamirSharings<Z>) -> Option<Z> + Sync,
{
    (0..len)
        .into_par_iter()
        .with_min_len(PAR_CHUNK)
        .map(|i| decoder(&build(i)))
        .collect()
}

fn sharings<R: ErrorCorrect + Sample>(
    rng: &mut AesRng,
    count: usize,
    num_parties: usize,
    degree: usize,
    corrupt_one: bool,
) -> Vec<ShamirSharings<R>> {
    (0..count)
        .map(|k| {
            let secret = R::sample(rng);
            let mut sharing = ShamirSharings::share(rng, secret, num_parties, degree).unwrap();
            if corrupt_one {
                // A different wrong share per sharing, inside and outside the interpolation set.
                let position = k % num_parties;
                let share = sharing.shares[position];
                sharing.shares[position] = Share::new(share.owner(), share.value() + R::ONE);
            }
            sharing
        })
        .collect()
}

fn bench_shape(
    c: &mut Criterion,
    shape: &str,
    num_parties: usize,
    threshold: usize,
    degree: usize,
    decoder: &Decoder,
) {
    let mut rng = AesRng::seed_from_u64(42);
    for (scenario, corrupt_one) in [("honest", false), ("one_error", true)] {
        let mut group = c.benchmark_group(format!(
            "reconstruct/F4Z128/{shape}_n{num_parties}_t{threshold}_d{degree}/{scenario}"
        ));
        for batch in BATCHES {
            let inputs = Inputs::from_sharings(
                shape,
                sharings::<Z>(&mut rng, batch, num_parties, degree, corrupt_one),
            );
            group.throughput(Throughput::Elements(batch as u64));
            for series in Series::ALL {
                group.bench_with_input(BenchmarkId::new(series.name(), batch), &batch, |b, _| {
                    b.iter(|| black_box(inputs.reconstruct(series, degree, decoder)));
                });
            }
        }
        group.finish();
    }
}

fn bench_open_reconstruct(c: &mut Criterion) {
    for (num_parties, threshold) in PARTIES {
        // Robust open of degree-t sharings, synchronous network, no known bots.
        let degree = threshold;
        bench_shape(
            c,
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
    // The hints alone, built once per reconstruction attempt (`ReconstructionHints`, the decoder's hints and
    // the Lagrange constants of the check together), and the share of the constants in them (`OptimisticHints`).
    let mut rng = AesRng::seed_from_u64(7);
    let mut group = c.benchmark_group("reconstruct/F4Z128/hints");
    for (num_parties, threshold) in PARTIES {
        for degree in [threshold, 2 * threshold] {
            let sharing = sharings::<Z>(&mut rng, 1, num_parties, degree, false);
            let parameter = format!("n{num_parties}_t{threshold}_d{degree}");
            group.bench_function(BenchmarkId::new("ReconstructionHints", &parameter), |b| {
                b.iter(|| black_box(ReconstructionHints::new(&sharing[0], degree).unwrap()));
            });
            let points = ReconstructionHints::new(&sharing[0], degree)
                .unwrap()
                .embedded_points;
            group.bench_function(BenchmarkId::new("OptimisticHints", &parameter), |b| {
                b.iter(|| black_box(OptimisticHints::new(&points, degree).unwrap()));
            });
        }
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_open_reconstruct
}
criterion_main!(benches);
