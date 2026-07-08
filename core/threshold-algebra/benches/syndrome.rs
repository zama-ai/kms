//! Benchmarks for the syndrome-based error correction that resharing runs (`SyndromeContext` in
//! `galois_rings/common.rs`).
//!
//! Run: cargo bench -p threshold-algebra --bench syndrome
//!
//! These answer *how fast resharing's local CPU work is* at the production shape: `n = 13` parties, threshold `t = 4`
//! (correcting up to `t` errors). They cover the syndrome compute and decode only (no robust-open).
//!
//! Everything runs over the production ring `ResiduePolyF4Z128`. The benchmarks vary the error count `e`: `0` is the
//! all-honest common case (the syndrome is zero and `decode` early-outs), `e = 4` is the worst correctable case (slow,
//! hopefully rare).
//!
//! Groups: * `syndrome_full_reshare` — syndrome CPU measurements for resharing one full `BC_PARAMS_SNS` key, honest
//! (`e=0`) and worst-case (`e=4`). * `syndrome_reshare_batch` — the same, per key component to show how cost scales
//! with element count. * `syndrome_ring` — the per-element unit: committee setup plus compute + decode for one ring
//! element, by error count.

use aes_prng::AesRng;
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    base_ring::Z128,
    galois_rings::{common::SyndromeContext, degree_4::ResiduePolyF4Z128},
    sharing::shamir::{InputOp, ShamirSharings},
    structure_traits::Sample,
};
use threshold_types::role::Role;

/// Share a random secret at `(n, t)` and corrupt `e` shares. Returns the sharing and the (ordered) party roles that own
/// the shares.
fn ring_sharing(n: usize, t: usize, e: usize) -> (ShamirSharings<ResiduePolyF4Z128>, Vec<Role>) {
    let mut rng = AesRng::seed_from_u64(0x5117 ^ e as u64);
    let secret = ResiduePolyF4Z128::sample(&mut rng);
    let mut sharing = ShamirSharings::share(&mut rng, secret, n, t).unwrap();
    for k in 0..e {
        // A full-width random ring offset -> a genuine error at index k that touches (up to) all 128 bit-planes, so the
        // per-bit field decode is exercised realistically.
        sharing.shares[k] += ResiduePolyF4Z128::sample(&mut rng);
    }
    let parties: Vec<Role> = sharing.shares.iter().map(|s| s.owner()).collect();
    (sharing, parties)
}

/// Per-element syndrome cost.
fn bench_ring(c: &mut Criterion) {
    const N: usize = 13;
    const T: usize = 4;

    let mut g = c.benchmark_group("syndrome_ring");

    // Setup (`SyndromeContext::new`). Paid once per key component and amortized over all its elements (918–6144), so it
    // is negligible per element — measured here only to document that.
    {
        let (_, parties) = ring_sharing(N, T, 0);
        g.bench_function(BenchmarkId::new("pre-compute", format!("n{N}_t{T}")), |b| {
            b.iter(|| black_box(SyndromeContext::<Z128, 4>::new(&parties, T).unwrap()));
        });
    }

    // Per-element cost by error count. `syndrome_decode` isolates the 128-bit Hensel-lift loop (the syndrome is
    // consumed, so it is cloned in untimed setup); `compute_then_decode` is the full per-element unit: build the
    // syndrome, then decode it.
    for e in [0usize, 1, 2, 4] {
        let (sharing, parties) = ring_sharing(N, T, e);
        let syn_ctx = SyndromeContext::new(&parties, T).unwrap();
        let syndrome = syn_ctx.compute(&sharing).unwrap();

        g.bench_function(
            BenchmarkId::new("syndrome_decode", format!("n{N}_t{T}_e{e}")),
            |b| {
                b.iter_batched(
                    || syndrome.clone(),
                    |s| black_box(syn_ctx.decode(s).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );

        g.bench_function(
            BenchmarkId::new("compute_then_decode", format!("n{N}_t{T}_e{e}")),
            |b| {
                b.iter(|| {
                    let s = syn_ctx.compute(black_box(&sharing)).unwrap();
                    black_box(syn_ctx.decode(s).unwrap())
                });
            },
        );
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Syndrome CPU cost of resharing one key component of `k` ring elements.
//
// Mirrors one `open_syndromes_and_correct_errors` call: build the `SyndromeContext` once for the committee, then
// compute + decode a syndrome per element. The real protocol interleaves ONE network robust-open between compute and
// decode;
//
// `k` values are the production per-component element counts for `BC_PARAMS_SNS` (one
// `open_syndromes_and_correct_errors` call each): LWE 918, compression 1024, GLWE/PKE 2048,
// SNS-GLWE 4096, SNS-compression 6144. `e` = errors per element (0 = all-honest common case, 4 =
// worst correctable — slow and rare).
// ---------------------------------------------------------------------------
fn bench_reshare_batch(c: &mut Criterion) {
    const N: usize = 13;
    const T: usize = 4;
    const COMPONENT_SIZES: [usize; 5] = [918, 1024, 2048, 4096, 6144];

    let mut g = c.benchmark_group("syndrome_reshare_batch");
    g.sample_size(10); // large loops; keep the worst-case (e=4, large k) runs bounded
    for k in COMPONENT_SIZES {
        for e in [0usize, 4] {
            let (sharing, parties) = ring_sharing(N, T, e);
            g.bench_function(BenchmarkId::from_parameter(format!("k{k}_e{e}")), |b| {
                b.iter(|| {
                    // One SyndromeContext per reshared component (amortized over all k elements).
                    let ctx = SyndromeContext::<Z128, 4>::new(&parties, T).unwrap();
                    for _ in 0..k {
                        let syn = ctx.compute(&sharing).unwrap();
                        black_box(ctx.decode(syn).unwrap());
                    }
                });
            });
        }
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Syndrome CPU cost of one full BC_PARAMS_SNS key reshare. `reshare_sk` reshares each secret-key component separately,
// so this runs all of them. Sizes (no dedicated OPRF key): SNS-compression 6144, SNS-GLWE 4096, GLWE 2048, PKE 2048,
// compression 1024, LWE 918 — total 16,278 ring elements.
// ---------------------------------------------------------------------------
fn bench_full_reshare(c: &mut Criterion) {
    const N: usize = 13;
    const T: usize = 4;
    const COMPONENTS: [usize; 6] = [6144, 4096, 2048, 2048, 1024, 918];

    let mut g = c.benchmark_group("syndrome_full_reshare");
    g.sample_size(10);
    for e in [0usize, 4] {
        let (sharing, parties) = ring_sharing(N, T, e);
        g.bench_function(BenchmarkId::from_parameter(format!("e{e}")), |b| {
            b.iter(|| {
                for &k in &COMPONENTS {
                    // reshare_sk builds a fresh context per component (same committee each time).
                    let ctx = SyndromeContext::<Z128, 4>::new(&parties, T).unwrap();
                    for _ in 0..k {
                        let syn = ctx.compute(&sharing).unwrap();
                        black_box(ctx.decode(syn).unwrap());
                    }
                }
            });
        });
    }
    g.finish();
}

criterion_group!(
    syndrome,
    bench_ring,
    bench_reshare_batch,
    bench_full_reshare
);
criterion_main!(syndrome);
