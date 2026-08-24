//! Micro-benchmarks for the Lagrange / vanishing-polynomial.
//!
//! Run: `cargo bench -p threshold-algebra --bench lagrange`
//!
//! Party counts `n = 4` (fast tests) and `n = 13` (production), over `GF16` (the quotient field syndrome decoding runs
//! in), and `GF256`, and `ResiduePolyF4Z128`.
//!
//! Groups: * `lagrange_numerators` — the numerator polynomials L_i (syndrome.rs) * `lagrange_polynomials` — the full
//! Lagrange basis (poly.rs) * `build_lagrange_map` — the biggest bulk consumer of `lagrange_polynomials`: warms the
//! startup cache by building the basis for every subset of size ≥ t+1 (~8k calls at n=13, t=4).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::num::NonZero;
use threshold_algebra::{
    galois_fields::{gf16::GF16, gf256::GF256, lagrange::build_lagrange_map},
    galois_rings::degree_4::ResiduePolyF4Z128,
    poly::lagrange_polynomials,
    structure_traits::{FromU128, Ring},
    syndrome::lagrange_numerators,
};

const PARTY_COUNTS: [usize; 2] = [4, 13];

/// `lagrange_numerators`: the L_i numerators, over both fields and the F4 ring.
fn bench_lagrange_numerators_for<F: Ring>(c: &mut Criterion, ty: &str) {
    let mut g = c.benchmark_group("lagrange_numerators");
    for n in PARTY_COUNTS {
        let points: Vec<F> = (1..=n as u128).map(F::from_u128).collect();
        g.bench_function(BenchmarkId::from_parameter(format!("{ty}/n{n}")), |b| {
            b.iter(|| black_box(lagrange_numerators(black_box(&points))));
        });
    }
    g.finish();
}

fn bench_lagrange_numerators(c: &mut Criterion) {
    bench_lagrange_numerators_for::<GF16>(c, "gf16");
    bench_lagrange_numerators_for::<GF256>(c, "gf256");
    bench_lagrange_numerators_for::<ResiduePolyF4Z128>(c, "ring_f4z128");
}

/// `lagrange_polynomials` (poly.rs): full basis (numerator + denominator). `Field`-only, so GF16/GF256.
fn bench_lagrange_polynomials(c: &mut Criterion) {
    let mut g = c.benchmark_group("lagrange_polynomials");
    for n in PARTY_COUNTS {
        let gf16: Vec<GF16> = (1..=n as u128).map(GF16::from_u128).collect();
        g.bench_function(BenchmarkId::from_parameter(format!("gf16/n{n}")), |b| {
            b.iter(|| black_box(lagrange_polynomials(black_box(&gf16))));
        });
        let gf256: Vec<GF256> = (1..=n as u128).map(GF256::from_u128).collect();
        g.bench_function(BenchmarkId::from_parameter(format!("gf256/n{n}")), |b| {
            b.iter(|| black_box(lagrange_polynomials(black_box(&gf256))));
        });
    }
    g.finish();
}

/// `build_lagrange_map` (galois_fields/lagrange.rs): builds the basis for every subset of size ≥ t+1 for caching (~8k
/// `lagrange_polynomials` calls at n=13, t=4).
fn bench_build_lagrange_map(c: &mut Criterion) {
    let mut g = c.benchmark_group("build_lagrange_map");
    g.sample_size(10); // thousands of subsets per iteration
    let n = NonZero::new(13).unwrap();
    g.bench_function(BenchmarkId::from_parameter("gf16/n13_t4"), |b| {
        b.iter(|| black_box(build_lagrange_map::<GF16>(black_box(n), black_box(4)).unwrap()));
    });
    g.finish();
}

criterion_group!(
    lagrange,
    bench_lagrange_numerators,
    bench_lagrange_polynomials,
    bench_build_lagrange_map
);
criterion_main!(lagrange);
