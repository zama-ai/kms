use aes_prng::AesRng;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    bivariate::BivariatePoly, galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Sample,
};

const DEGREES: [usize; 3] = [1, 4, 13];

fn bivariate_setup(degree: usize) -> (BivariatePoly<ResiduePolyF4Z128>, ResiduePolyF4Z128) {
    let mut rng = AesRng::seed_from_u64(degree as u64);
    let secret = ResiduePolyF4Z128::sample(&mut rng);
    let point = ResiduePolyF4Z128::sample(&mut rng);
    let poly = BivariatePoly::from_secret(&mut rng, secret, degree);
    (poly, point)
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

        group.bench_function(BenchmarkId::new("partial_x", degree), |b| {
            b.iter(|| black_box(poly.partial_x_eval(black_box(point))));
        });
        group.bench_function(BenchmarkId::new("partial_y", degree), |b| {
            b.iter(|| black_box(poly.partial_y_eval(black_box(point))));
        });
        // Baseline: two separate partial evals, mirroring the code before PR 576.
        group.bench_function(BenchmarkId::new("partial_x_then_y", degree), |b| {
            b.iter(|| {
                let p = black_box(point);
                (
                    black_box(poly.partial_x_eval(p)),
                    black_box(poly.partial_y_eval(p)),
                )
            });
        });
        // Fused: the path `DoublePoly::from_bivariate` actually uses.
        group.bench_function(BenchmarkId::new("partial_evaluations", degree), |b| {
            b.iter(|| black_box(poly.partial_evals(black_box(point))));
        });
        group.bench_function(BenchmarkId::new("full", degree), |b| {
            b.iter(|| black_box(poly.full_eval(black_box(point), black_box(point))));
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
