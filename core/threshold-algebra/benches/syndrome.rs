//! Micro-benchmarks for Reed–Solomon syndrome computation and decoding
//! (`core/threshold-algebra/src/syndrome.rs`) and the production ring-level
//! `Syndrome` trait impl on `ResiduePolyF4Z128` (`galois_rings/common.rs`).
//!
//! Run with:
//!   cargo bench -p threshold-algebra --bench syndrome
//!   cargo bench -p threshold-algebra --bench syndrome -- syndrome_ring   # the hot path
//!
//! ## What is measured, and why these shapes
//!
//! Production uses `n = 13` parties, threshold `t = 4` (the `n = 3t + 1`
//! honest-majority shape). The RS "redundancy" is `r = n - (t + 1) = 2t`, so
//! the code can correct up to `floor(r/2) = t` errors.
//!
//! Three groups:
//!
//! * `syndrome_field/*` — the field-level functions literally in `syndrome.rs`
//!   (`lagrange_numerators`, `compute_syndrome`, `decode_syndrome`) over `GF16`
//!   (the quotient field of `ResiduePolyF4Z128`, i.e. the field that actually
//!   runs in production) and `GF256` (contrast: 8-bit vs 4-bit field). Swept over
//!   `(n, t) = (4,1), (7,2), (10,3), (13,4)` and error counts `e ∈ {0,1,2,t}`.
//!   NOTE: `decode_syndrome` early-returns on a zero syndrome, so `e = 0`
//!   measures only the zero-check; `e ≥ 1` measures the extended-Euclidean solve.
//!
//! * `syndrome_ring/*` — the real hot path: `<ResiduePolyF4Z128 as Syndrome>`'s
//!   `syndrome_compute` and `syndrome_decode` at `n=13, t=4`. `syndrome_decode`
//!   runs a 128-iteration bit loop (one per bit of Z128), each iteration calling
//!   field-level decode AND recomputing `syndrome_compute` for the correction —
//!   this is where redundant per-committee precompute dominates.
//!
//! * `syndrome_primitives/*` — the `Poly` primitives the two paths lean on
//!   (`compute_powers_list`, `eval`, multiply-by-monic-linear, `Zʳ / syndrome`
//!   long division), to attribute where the time goes.

use aes_prng::AesRng;
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    galois_fields::{gf16::GF16, gf256::GF256},
    galois_rings::degree_4::ResiduePolyF4Z128,
    matrix::compute_powers_list,
    poly::Poly,
    sharing::shamir::{InputOp, ShamirSharings},
    structure_traits::{
        Field, FromU128, Invert, One, RingWithExceptionalSequence, Sample, Syndrome,
    },
    syndrome::{compute_syndrome, decode_syndrome, lagrange_numerators},
};
use threshold_types::role::Role;

/// `(n, t)` pairs following the production `n = 3t + 1` shape (`r = 2t`).
const PARAMS: [(usize, usize); 4] = [(4, 1), (7, 2), (10, 3), (13, 4)];

/// Build `(xs, ys, v, r)` for a degree-`t` message polynomial over `F` with `e`
/// injected errors at distinct low indices. `v = t + 1` (RS dimension), `r = n - v`.
fn field_inputs<F: Field + std::fmt::Debug>(
    n: usize,
    t: usize,
    e: usize,
) -> (Vec<F>, Vec<F>, usize, usize) {
    // coefficients [1, 2, ..., t+1] — leading coef non-zero, so degree is exactly t.
    let coefs: Vec<F> = (0..=t).map(|i| F::from_u128(i as u128 + 1)).collect();
    let f = Poly::from_coefs(coefs);

    let v = t + 1;
    let r = n - v;

    let xs: Vec<F> = (1..=n as u128).map(F::from_u128).collect();
    let mut ys: Vec<F> = xs.iter().map(|x| f.eval(x)).collect();

    // inject e errors (non-zero offsets) at indices 0..e
    for (k, y) in ys.iter_mut().enumerate().take(e) {
        *y += F::from_u128(11 * (k as u128 + 1) + 1);
    }

    (xs, ys, v, r)
}

/// Error counts to sweep for a given threshold: {0, 1, 2, t}, deduped, capped at t.
fn error_counts(t: usize) -> Vec<usize> {
    let mut e = vec![0usize, 1, 2, t];
    e.retain(|&x| x <= t);
    e.sort_unstable();
    e.dedup();
    e
}

// ---------------------------------------------------------------------------
// Field-level (syndrome.rs) benchmarks
// ---------------------------------------------------------------------------

fn bench_field_for<F: Field + std::fmt::Debug>(c: &mut Criterion, field: &str) {
    // lagrange_numerators: depends only on the point set (the party identities).
    // Recomputed on every compute_syndrome AND every decode_syndrome call today.
    {
        let mut g = c.benchmark_group("syndrome_field/lagrange_numerators");
        for (n, _t) in PARAMS {
            let xs: Vec<F> = (1..=n as u128).map(F::from_u128).collect();
            g.bench_function(BenchmarkId::from_parameter(format!("{field}/n{n}")), |b| {
                b.iter(|| black_box(lagrange_numerators(black_box(&xs))));
            });
        }
        g.finish();
    }

    // compute_syndrome: r coefficients, each a sum over n points.
    {
        let mut g = c.benchmark_group("syndrome_field/compute_syndrome");
        for (n, t) in PARAMS {
            let (xs, ys, v, _r) = field_inputs::<F>(n, t, 1);
            g.bench_function(
                BenchmarkId::from_parameter(format!("{field}/n{n}_t{t}")),
                |b| b.iter(|| black_box(compute_syndrome(black_box(&xs), black_box(&ys), v))),
            );
        }
        g.finish();
    }

    // decode_syndrome: extended-Euclidean solve + Chien-style root search.
    {
        let mut g = c.benchmark_group("syndrome_field/decode_syndrome");
        for (n, t) in PARAMS {
            for e in error_counts(t) {
                let (xs, ys, v, r) = field_inputs::<F>(n, t, e);
                let syndrome = compute_syndrome(&xs, &ys, v);
                g.bench_function(
                    BenchmarkId::from_parameter(format!("{field}/n{n}_t{t}_e{e}")),
                    |b| {
                        b.iter(|| {
                            black_box(decode_syndrome(black_box(&syndrome), black_box(&xs), r))
                        })
                    },
                );
            }
        }
        g.finish();
    }
}

fn bench_field(c: &mut Criterion) {
    bench_field_for::<GF16>(c, "gf16");
    bench_field_for::<GF256>(c, "gf256");
}

// ---------------------------------------------------------------------------
// Ring-level (production) benchmarks: <ResiduePolyF4Z128 as Syndrome>
// ---------------------------------------------------------------------------

/// Share a random secret at `(n, t)` and corrupt `e` shares. Returns the sharing
/// and the (ordered) party roles that own the shares.
fn ring_sharing(n: usize, t: usize, e: usize) -> (ShamirSharings<ResiduePolyF4Z128>, Vec<Role>) {
    let mut rng = AesRng::seed_from_u64(0x5117 ^ e as u64);
    let secret = ResiduePolyF4Z128::sample(&mut rng);
    let mut sharing = ShamirSharings::share(&mut rng, secret, n, t).unwrap();
    for k in 0..e {
        // A full-width random ring offset -> a genuine error at index k that
        // touches (up to) all 128 bit-planes, so the per-bit field decode is
        // exercised realistically (a small offset would only perturb the low bits).
        sharing.shares[k] += ResiduePolyF4Z128::sample(&mut rng);
    }
    let parties: Vec<Role> = sharing.shares.iter().map(|s| s.owner()).collect();
    (sharing, parties)
}

fn bench_ring(c: &mut Criterion) {
    const N: usize = 13;
    const T: usize = 4;

    let mut g = c.benchmark_group("syndrome_ring");

    // syndrome_compute: work is independent of the number of errors.
    {
        let (sharing, _parties) = ring_sharing(N, T, 1);
        g.bench_function(
            BenchmarkId::new("syndrome_compute", format!("n{N}_t{T}")),
            |b| {
                b.iter(|| {
                    black_box(ResiduePolyF4Z128::syndrome_compute(black_box(&sharing), T).unwrap())
                });
            },
        );
    }

    for e in [0usize, 1, 2, 4] {
        let (sharing, parties) = ring_sharing(N, T, e);
        let syndrome = ResiduePolyF4Z128::syndrome_compute(&sharing, T).unwrap();

        // syndrome_decode alone (the 128-bit Hensel-lift loop). The syndrome is
        // consumed, so clone it in untimed setup via iter_batched.
        g.bench_function(
            BenchmarkId::new("syndrome_decode", format!("n{N}_t{T}_e{e}")),
            |b| {
                b.iter_batched(
                    || syndrome.clone(),
                    |s| black_box(ResiduePolyF4Z128::syndrome_decode(s, &parties, T).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );

        // end-to-end: compute the syndrome then decode it.
        g.bench_function(
            BenchmarkId::new("compute_then_decode", format!("n{N}_t{T}_e{e}")),
            |b| {
                b.iter(|| {
                    let s = ResiduePolyF4Z128::syndrome_compute(black_box(&sharing), T).unwrap();
                    black_box(ResiduePolyF4Z128::syndrome_decode(s, &parties, T).unwrap())
                });
            },
        );
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Primitive Poly ops (attribution)
// ---------------------------------------------------------------------------

fn bench_primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("syndrome_primitives");

    let n = 13usize;
    let r = 8usize;
    let xs: Vec<GF16> = (1..=n as u128).map(GF16::from_u128).collect();

    // compute_powers_list: the alpha-power table built by compute_syndrome.
    g.bench_function("compute_powers_list/gf16_n13_r8", |b| {
        b.iter(|| black_box(compute_powers_list(black_box(&xs), r)));
    });

    // A degree-(n-1) Lagrange numerator, used as a representative dense poly.
    let lag = lagrange_numerators(&xs);
    let poly0 = lag[0].clone();

    // Poly::eval at degree n-1 (the denominator evaluations in compute_syndrome).
    g.bench_function("poly_eval/gf16_deg12", |b| {
        b.iter(|| black_box(black_box(&poly0).eval(black_box(&xs[0]))));
    });

    // Poly * (monic linear): the multiply pattern inside lagrange_numerators.
    let lin = Poly::from_coefs(vec![-xs[1], GF16::ONE]);
    g.bench_function("poly_mul_by_linear/gf16_deg12", |b| {
        b.iter(|| black_box(black_box(&poly0) * black_box(&lin)));
    });

    // Zʳ / syndrome long division: the per-iteration step of decode_syndrome's EEA.
    let (xs2, ys2, v2, _r2) = field_inputs::<GF16>(13, 4, 2);
    let syndrome = compute_syndrome(&xs2, &ys2, v2);
    let mut zr = Poly::<GF16>::zero();
    zr.set_coef(r, GF16::ONE);
    g.bench_function("poly_divmod/gf16_Zr_by_syndrome", |b| {
        b.iter(|| black_box(black_box(&zr) / black_box(&syndrome)));
    });

    // --- ring-level attribution: the two committee-invariant levers inside
    //     the ~32 µs ring `syndrome_compute` (called 128× per syndrome_decode) ---
    let ring_pts: Vec<ResiduePolyF4Z128> = (1..=13)
        .map(|i| ResiduePolyF4Z128::get_from_exceptional_sequence(i).unwrap())
        .collect();

    // Ring `lagrange_numerators`: depends only on the party set, yet recomputed on
    // every `syndrome_compute` call (i.e. 128× inside one `syndrome_decode`).
    g.bench_function("lagrange_numerators/ring_n13", |b| {
        b.iter(|| black_box(lagrange_numerators(black_box(&ring_pts))));
    });

    // A single ring inversion (Newton-Raphson, ~7 ring mults). `syndrome_compute`
    // does n·r = 104 of these per call, of which only n = 13 are distinct.
    let denom = lagrange_numerators(&ring_pts)[0].eval(&ring_pts[0]);
    g.bench_function("ring_invert/residue_poly_f4z128", |b| {
        b.iter(|| black_box(black_box(denom).invert().unwrap()));
    });

    g.finish();
}

criterion_group!(syndrome, bench_field, bench_ring, bench_primitives);
criterion_main!(syndrome);
