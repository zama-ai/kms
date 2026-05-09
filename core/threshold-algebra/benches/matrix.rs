use aes_prng::AesRng;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    galois_rings::degree_4::ResiduePolyF4Z128, matrix::VdmMatrix, structure_traits::Sample,
};

const PRODUCTION_PARTIES: usize = 13;
const PRODUCTION_THRESHOLD: usize = 4;
const EXTRACTED_WIDTH: usize = PRODUCTION_PARTIES - PRODUCTION_THRESHOLD;

fn sample_vec(rng: &mut AesRng, len: usize) -> Vec<ResiduePolyF4Z128> {
    (0..len).map(|_| ResiduePolyF4Z128::sample(rng)).collect()
}

fn bench_single_sharing_vdm(c: &mut Criterion) {
    let mut rng = AesRng::seed_from_u64(0);
    let shares = sample_vec(&mut rng, PRODUCTION_PARTIES);
    let vdm = VdmMatrix::<ResiduePolyF4Z128>::from_exceptional_sequence(
        PRODUCTION_PARTIES,
        EXTRACTED_WIDTH,
    )
    .unwrap();

    c.bench_function("matrix/production/single_sharing_vdm/n13_t4", |b| {
        b.iter(|| black_box(black_box(&vdm).mul_vector(black_box(&shares)).unwrap()))
    });
}

fn bench_double_sharing_vdm(c: &mut Criterion) {
    let mut rng = AesRng::seed_from_u64(1);
    let shares_t = sample_vec(&mut rng, PRODUCTION_PARTIES);
    let shares_2t = sample_vec(&mut rng, PRODUCTION_PARTIES);
    let vdm = VdmMatrix::<ResiduePolyF4Z128>::from_exceptional_sequence(
        PRODUCTION_PARTIES,
        EXTRACTED_WIDTH,
    )
    .unwrap();

    c.bench_function("matrix/production/double_sharing_vdm/n13_t4", |b| {
        b.iter(|| {
            black_box((
                black_box(&vdm).mul_vector(black_box(&shares_t)).unwrap(),
                black_box(&vdm).mul_vector(black_box(&shares_2t)).unwrap(),
            ))
        })
    });
}

fn bench_robust_prss_vdm(c: &mut Criterion) {
    let mut rng = AesRng::seed_from_u64(2);
    let shares = sample_vec(&mut rng, PRODUCTION_PARTIES);
    let vdm = VdmMatrix::<ResiduePolyF4Z128>::from_exceptional_sequence(
        PRODUCTION_PARTIES,
        EXTRACTED_WIDTH,
    )
    .unwrap();

    // Keep the Criterion ID stable so this branch can compare against the
    // original transposed ndarray baseline.
    c.bench_function("matrix/production/robust_prss_transposed_vdm/n13_t4", |b| {
        b.iter(|| black_box(black_box(&vdm).mul_vector(black_box(&shares)).unwrap()))
    });
}

criterion_group!(
    matrix,
    bench_single_sharing_vdm,
    bench_double_sharing_vdm,
    bench_robust_prss_vdm,
);
criterion_main!(matrix);
