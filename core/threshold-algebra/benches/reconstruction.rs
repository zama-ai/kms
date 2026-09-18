//! Benchmarks Galois-ring reconstruction across every supported extension degree.
//!
//! Run with `cargo bench -p threshold-algebra --bench reconstruction`.

use aes_prng::AesRng;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_algebra::{
    error_correction::ReconstructionHints,
    galois_rings::{
        degree_3::{ResiduePolyF3Z64, ResiduePolyF3Z128},
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_5::{ResiduePolyF5Z64, ResiduePolyF5Z128},
        degree_6::{ResiduePolyF6Z64, ResiduePolyF6Z128},
        degree_7::{ResiduePolyF7Z64, ResiduePolyF7Z128},
        degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
    },
    sharing::shamir::{InputOp, RevealOp, ShamirSharings},
    structure_traits::Sample,
};

macro_rules! benchmark_honest_reconstruction {
    ($group:expr, $ring:ty, $ring_name:literal, $parameters:expr) => {
        for &(num_parties, threshold) in $parameters {
            let mut rng = AesRng::seed_from_u64(42);
            let secret = <$ring>::sample(&mut rng);
            let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
            let hints = ReconstructionHints::new(&sharing, threshold).unwrap();

            assert_eq!(
                sharing
                    .error_reconstruct_with_hints(threshold, threshold, &hints)
                    .unwrap(),
                secret
            );

            $group.bench_function(
                BenchmarkId::new($ring_name, format!("n{num_parties}_t{threshold}")),
                |b| {
                    b.iter(|| {
                        black_box(
                            sharing
                                .error_reconstruct_with_hints(
                                    threshold,
                                    threshold,
                                    black_box(&hints),
                                )
                                .unwrap(),
                        )
                    });
                },
            );
        }
    };
}

fn bench_honest_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconstruction_with_hints");

    // Four parties fit every exceptional sequence, including GF(2^3). This gives each specialized
    // BitWiseEval implementation a directly comparable benchmark for both base-ring sizes.
    let small = &[(4, 1)];
    benchmark_honest_reconstruction!(group, ResiduePolyF3Z64, "f3z64", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF3Z128, "f3z128", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF4Z64, "f4z64", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF4Z128, "f4z128", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF5Z64, "f5z64", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF5Z128, "f5z128", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF6Z64, "f6z64", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF6Z128, "f6z128", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF7Z64, "f7z64", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF7Z128, "f7z128", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF8Z64, "f8z64", small);
    benchmark_honest_reconstruction!(group, ResiduePolyF8Z128, "f8z128", small);

    // Keep the original production-sized F4Z128 case from PR #650 and cover both word sizes for
    // F8, which previously lived only in the experiments crate.
    let production_sized = &[(13, 4)];
    benchmark_honest_reconstruction!(group, ResiduePolyF4Z128, "f4z128", production_sized);
    benchmark_honest_reconstruction!(group, ResiduePolyF8Z64, "f8z64", production_sized);
    benchmark_honest_reconstruction!(group, ResiduePolyF8Z128, "f8z128", production_sized);

    group.finish();
}

fn bench_reconstruction_with_errors(c: &mut Criterion) {
    const NUM_PARTIES: usize = 13;
    const THRESHOLD: usize = 4;

    let mut group = c.benchmark_group("reconstruction_with_errors/f4z128/n13_t4");

    for error_count in [1, THRESHOLD] {
        let mut rng = AesRng::seed_from_u64(42);
        let secret = ResiduePolyF4Z128::sample(&mut rng);
        let mut sharing = ShamirSharings::share(&mut rng, secret, NUM_PARTIES, THRESHOLD).unwrap();
        for share in sharing.shares.iter_mut().take(error_count) {
            *share += ResiduePolyF4Z128::sample(&mut rng);
        }
        let hints = ReconstructionHints::new(&sharing, THRESHOLD).unwrap();

        assert_eq!(
            sharing.error_reconstruct(THRESHOLD, THRESHOLD).unwrap(),
            secret
        );
        assert_eq!(
            sharing
                .error_reconstruct_with_hints(THRESHOLD, THRESHOLD, &hints)
                .unwrap(),
            secret
        );

        group.bench_function(
            BenchmarkId::new("without_hints", format!("e{error_count}")),
            |b| {
                b.iter(|| {
                    black_box(
                        black_box(&sharing)
                            .error_reconstruct(THRESHOLD, THRESHOLD)
                            .unwrap(),
                    )
                });
            },
        );
        group.bench_function(
            BenchmarkId::new("with_hints", format!("e{error_count}")),
            |b| {
                b.iter(|| {
                    black_box(
                        black_box(&sharing)
                            .error_reconstruct_with_hints(THRESHOLD, THRESHOLD, black_box(&hints))
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    reconstruction,
    bench_honest_reconstruction,
    bench_reconstruction_with_errors
);
criterion_main!(reconstruction);
