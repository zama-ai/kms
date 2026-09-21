use algebra::{
    PRSSConversions,
    galois_rings::{
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
    },
    structure_traits::Ring,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use threshold_types::session_id::SessionId;

use threshold_execution::small_execution::prf::benchmarking as prf;

fn bench_ring<Z: Ring + PRSSConversions>(c: &mut Criterion, ring: &str) {
    let key = prf::PrfKey([23; 16]);
    let psi = prf::PsiAes::new(&key, SessionId::from(42));
    let chi = prf::ChiAes::new(&key, SessionId::from(42));
    let mut group = c.benchmark_group(format!("prf/{ring}"));
    group.throughput(Throughput::Elements(1));
    let mut counter = 0;
    group.bench_function("psi", |b| {
        b.iter(|| {
            counter += 1;
            black_box(prf::psi::<Z>(black_box(&psi), black_box(counter)).unwrap());
        })
    });
    group.bench_function("chi", |b| {
        b.iter(|| {
            counter += 1;
            black_box(prf::chi::<Z>(black_box(&chi), black_box(counter), black_box(1)).unwrap());
        })
    });
    let blocks = Z::EXTENSION_DEGREE * Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    group.bench_function("conversion_with_allocation", |b| {
        b.iter(|| {
            black_box(Z::from_u128_chunks(vec![black_box(42); blocks]));
        })
    });
    let a = Z::from_u128_chunks(vec![13; blocks]);
    let v = Z::from_u128_chunks(vec![29; blocks]);
    group.bench_function("multiply_accumulate", |b| {
        b.iter(|| {
            let mut sum = black_box(Z::ZERO);
            sum += black_box(a) * black_box(v);
            black_box(sum);
        })
    });
    group.finish();
}

fn bench_prf(c: &mut Criterion) {
    bench_ring::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_ring::<ResiduePolyF4Z128>(c, "f4_z128");
    bench_ring::<ResiduePolyF8Z64>(c, "f8_z64");
    bench_ring::<ResiduePolyF8Z128>(c, "f8_z128");
    let phi = prf::PhiAes::new(&prf::PrfKey([23; 16]), SessionId::from(42));
    let mut group = c.benchmark_group("prf/phi_range");
    let mut counter = 0;
    for size in [1_usize, 1024, 30_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                let values =
                    prf::phi_range(black_box(&phi), black_box(counter), size, 1 << 110).unwrap();
                counter += size as u128;
                black_box(values);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prf);
criterion_main!(benches);
