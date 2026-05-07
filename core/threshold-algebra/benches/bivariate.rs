use aes_prng::AesRng;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    bivariate::{BivariateEval, BivariatePoly, compute_powers},
    galois_rings::degree_4::ResiduePolyF4Z128,
    structure_traits::{Ring, Sample},
};

const DEGREES: [usize; 5] = [1, 3, 4, 13, 20];
// Use this shorter sweep for fast local iteration.
// const DEGREES: [usize; 2] = [4, 20];

fn bivariate_setup(degree: usize) -> (BivariatePoly<ResiduePolyF4Z128>, ResiduePolyF4Z128) {
    let mut rng = AesRng::seed_from_u64(degree as u64);
    let secret = ResiduePolyF4Z128::sample(&mut rng);
    let point = ResiduePolyF4Z128::sample(&mut rng);
    let poly = BivariatePoly::from_secret(&mut rng, secret, degree).unwrap();
    (poly, point)
}

fn matrix_setup(degree: usize) -> (Vec<ResiduePolyF4Z128>, Vec<ResiduePolyF4Z128>) {
    let mut rng = AesRng::seed_from_u64(100 + degree as u64);
    let d = degree + 1;
    let vector = (0..d)
        .map(|_| ResiduePolyF4Z128::sample(&mut rng))
        .collect();
    let matrix = (0..d * d)
        .map(|_| ResiduePolyF4Z128::sample(&mut rng))
        .collect();

    (vector, matrix)
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

fn vector_matrix_product<Z: Ring>(vector: &[Z], matrix: &[Z]) -> Vec<Z> {
    let d = vector.len();
    let mut res = vec![Z::ZERO; d];
    for (row_idx, vector_value) in vector.iter().enumerate() {
        let row_start = row_idx * d;
        for col_idx in 0..d {
            res[col_idx] += *vector_value * matrix[row_start + col_idx];
        }
    }
    res
}

fn matrix_vector_product<Z: Ring>(matrix: &[Z], vector: &[Z]) -> Vec<Z> {
    let d = vector.len();
    let mut res = Vec::with_capacity(d);
    for row_idx in 0..d {
        let row_start = row_idx * d;
        let mut acc = Z::ZERO;
        for col_idx in 0..d {
            acc += matrix[row_start + col_idx] * vector[col_idx];
        }
        res.push(acc);
    }
    res
}

fn bench_bivariate_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("bivariate/from_secret");

    for degree in DEGREES {
        group.bench_function(BenchmarkId::from_parameter(degree), |b| {
            let mut rng = AesRng::seed_from_u64(degree as u64);
            let secret = ResiduePolyF4Z128::sample(&mut rng);
            b.iter(|| {
                black_box(
                    BivariatePoly::from_secret(&mut rng, black_box(secret), black_box(degree))
                        .unwrap(),
                )
            });
        });
    }

    group.finish();
}

fn bench_bivariate_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("bivariate/evaluation");

    for degree in DEGREES {
        let (poly, point) = bivariate_setup(degree);
        let current = poly.full_evaluation(point, point).unwrap();
        let direct = full_evaluation_direct(&poly, degree, point, point);
        assert_eq!(current, direct);

        group.bench_function(BenchmarkId::new("partial_x", degree), |b| {
            b.iter(|| black_box(poly.partial_x_evaluation(black_box(point)).unwrap()));
        });
        group.bench_function(BenchmarkId::new("partial_y", degree), |b| {
            b.iter(|| black_box(poly.partial_y_evaluation(black_box(point)).unwrap()));
        });
        group.bench_function(BenchmarkId::new("full", degree), |b| {
            b.iter(|| {
                black_box(
                    poly.full_evaluation(black_box(point), black_box(point))
                        .unwrap(),
                )
            });
        });
        group.bench_function(BenchmarkId::new("full_direct", degree), |b| {
            b.iter(|| black_box(full_evaluation_direct(&poly, degree, point, point)));
        });
    }

    group.finish();
}

fn bench_matrix_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("bivariate/matrix_mul");

    for degree in DEGREES {
        let (vector, matrix) = matrix_setup(degree);

        group.bench_function(BenchmarkId::new("vector_matrix", degree), |b| {
            b.iter(|| {
                black_box(vector_matrix_product(
                    black_box(&vector),
                    black_box(&matrix),
                ))
            });
        });
        group.bench_function(BenchmarkId::new("matrix_vector", degree), |b| {
            b.iter(|| {
                black_box(matrix_vector_product(
                    black_box(&matrix),
                    black_box(&vector),
                ))
            });
        });
    }

    group.finish();
}

criterion_group!(
    bivariate,
    bench_bivariate_sampling,
    bench_bivariate_evaluation,
    bench_matrix_mul
);
criterion_main!(bivariate);
