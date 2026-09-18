//! Benchmarks Gao decoding's honest fast path and its partial extended-GCD error path.
//!
//! Run with `cargo bench -p threshold-algebra --bench gao_decoding`.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use threshold_algebra::{
    galois_fields::gf256::GF256,
    poly::{Poly, gao_decoding, gao_decoding_with_field_hints, lagrange_polynomials},
    structure_traits::RingWithExceptionalSequence,
};
use threshold_types::role::Role;

fn bench_gao_decoding(c: &mut Criterion) {
    const NUM_POINTS: usize = 13;
    const K: usize = 5;
    const MAX_ERRORS: usize = 4;

    let message = Poly::from_coefs(
        (1..=K)
            .map(|coefficient| GF256::from(coefficient as u8))
            .collect(),
    );
    let points: Vec<_> = (1..=NUM_POINTS)
        .map(|party| {
            GF256::embed_role_to_exceptional_sequence(&Role::indexed_from_one(party)).unwrap()
        })
        .collect();
    let lagrange_polys = lagrange_polynomials(&points);
    let vanishing_poly = points
        .iter()
        .fold(Poly::from_coefs(vec![GF256::from(1)]), |product, point| {
            product * Poly::from_coefs(vec![GF256::from(0) - *point, GF256::from(1)])
        });

    let mut group = c.benchmark_group("gao_decoding/n13_k5");
    for error_count in [0, 1, MAX_ERRORS] {
        let mut values: Vec<_> = points.iter().map(|point| message.eval(point)).collect();
        for (index, value) in values.iter_mut().take(error_count).enumerate() {
            *value += GF256::from((index + 1) as u8);
        }

        assert_eq!(
            gao_decoding(&points, values.iter().copied(), K, MAX_ERRORS).unwrap(),
            message
        );
        assert_eq!(
            gao_decoding_with_field_hints(
                &points,
                values.iter().copied(),
                K,
                MAX_ERRORS,
                &lagrange_polys,
                &vanishing_poly,
            )
            .unwrap(),
            message
        );

        group.bench_function(
            BenchmarkId::new("without_hints", format!("e{error_count}")),
            |b| {
                b.iter(|| {
                    black_box(
                        gao_decoding(
                            black_box(&points),
                            black_box(&values).iter().copied(),
                            K,
                            MAX_ERRORS,
                        )
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
                        gao_decoding_with_field_hints(
                            black_box(&points),
                            black_box(&values).iter().copied(),
                            K,
                            MAX_ERRORS,
                            black_box(&lagrange_polys),
                            black_box(&vanishing_poly),
                        )
                        .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(gao_decoding_benches, bench_gao_decoding);
criterion_main!(gao_decoding_benches);
