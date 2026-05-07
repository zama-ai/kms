use aes_prng::AesRng;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    bivariate::{BivariateEval, BivariatePoly, compute_powers},
    galois_rings::degree_4::ResiduePolyF4Z128,
    structure_traits::{Ring, Sample},
};

const DEGREES: [usize; 3] = [1, 4, 13];
// Use this shorter sweep for fast local iteration.
// const DEGREES: [usize; 2] = [4, 13];

fn bivariate_setup(degree: usize) -> (BivariatePoly<ResiduePolyF4Z128>, ResiduePolyF4Z128) {
    let mut rng = AesRng::seed_from_u64(degree as u64);
    let secret = ResiduePolyF4Z128::sample(&mut rng);
    let point = ResiduePolyF4Z128::sample(&mut rng);
    let poly = BivariatePoly::from_secret(&mut rng, secret, degree);
    (poly, point)
}

fn full_evaluation_direct<Z: Ring>(
    poly: &BivariatePoly<Z>,
    degree: usize,
    alpha_x: Z,
    alpha_y: Z,
) -> Z {
    let powers_x = compute_powers(alpha_x, degree);
    let powers_y = compute_powers(alpha_y, degree);
    let mut acc = Z::ZERO;
    let d = degree + 1;

    for (row_idx, row) in poly.coefs.chunks_exact(d).enumerate() {
        for (col_idx, coef) in row.iter().enumerate() {
            acc += powers_x[row_idx] * *coef * powers_y[col_idx];
        }
    }

    acc
}

fn bench_bivariate_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("bivariate/from_secret");

    for degree in DEGREES {
        group.bench_function(BenchmarkId::from_parameter(degree), |b| {
            let mut rng = AesRng::seed_from_u64(degree as u64);
            let secret = ResiduePolyF4Z128::sample(&mut rng);
            b.iter(|| {
                black_box(BivariatePoly::from_secret(
                    &mut rng,
                    black_box(secret),
                    black_box(degree),
                ))
            });
        });
    }

    group.finish();
}

fn bench_bivariate_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("bivariate/evaluation");

    for degree in DEGREES {
        let (poly, point) = bivariate_setup(degree);
        let current = poly.full_evaluation(point, point);
        let direct = full_evaluation_direct(&poly, degree, point, point);
        assert_eq!(current, direct);

        group.bench_function(BenchmarkId::new("partial_x", degree), |b| {
            b.iter(|| black_box(poly.partial_x_evaluation(black_box(point))));
        });
        group.bench_function(BenchmarkId::new("partial_y", degree), |b| {
            b.iter(|| black_box(poly.partial_y_evaluation(black_box(point))));
        });
        group.bench_function(BenchmarkId::new("full", degree), |b| {
            b.iter(|| black_box(poly.full_evaluation(black_box(point), black_box(point))));
        });
    }

    group.finish();
}

criterion_group!(
    bivariate,
    bench_bivariate_sampling,
    bench_bivariate_evaluation,
);
criterion_main!(bivariate);
