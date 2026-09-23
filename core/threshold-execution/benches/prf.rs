use aes_prng::AesRng;
use algebra::{
    PRSSConversions,
    base_ring::{Z64, Z128},
    galois_rings::{
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
    },
    structure_traits::{BaseRing, Ring},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
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
    bench_counter_group::<Z, 1>(c, ring, &psi, &chi);
    bench_counter_group::<Z, 2>(c, ring, &psi, &chi);
    bench_counter_group::<Z, 4>(c, ring, &psi, &chi);
    bench_counter_group::<Z, 8>(c, ring, &psi, &chi);
    bench_accumulation::<Z>(c, ring);
}

fn bench_counter_group<Z: Ring + PRSSConversions, const N: usize>(
    c: &mut Criterion,
    ring: &str,
    psi: &prf::PsiAes,
    chi: &prf::ChiAes,
) {
    let mut group = c.benchmark_group(format!("prf_group/{ring}"));
    group.throughput(Throughput::Elements(N as u64));
    let mut counter = 0;
    group.bench_function(BenchmarkId::new("psi_scalar", N), |b| {
        b.iter(|| {
            let start = black_box(counter);
            let key = black_box(psi);
            let outputs: [Z; N] =
                std::array::from_fn(|i| prf::psi(key, start + i as u128).unwrap());
            counter += N as u128;
            black_box(outputs);
        });
    });
    group.bench_function(BenchmarkId::new("psi_grouped", N), |b| {
        b.iter(|| {
            black_box(prf::psi_group::<Z, N>(black_box(psi), black_box(counter)));
            counter += N as u128;
        });
    });
    group.bench_function(BenchmarkId::new("chi_scalar", N), |b| {
        b.iter(|| {
            let start = black_box(counter);
            let key = black_box(chi);
            let j = black_box(1);
            let outputs: [Z; N] =
                std::array::from_fn(|i| prf::chi(key, start + i as u128, j).unwrap());
            counter += N as u128;
            black_box(outputs);
        });
    });
    group.bench_function(BenchmarkId::new("chi_grouped", N), |b| {
        b.iter(|| {
            black_box(prf::chi_group::<Z, N>(
                black_box(chi),
                black_box(counter),
                black_box(1),
            ));
            counter += N as u128;
        });
    });
    group.finish();
}

fn bench_accumulation<Z: Ring>(c: &mut Criterion, ring: &str) {
    let mut rng = AesRng::seed_from_u64(42);
    let mut group = c.benchmark_group(format!("prss_arithmetic/{ring}"));
    // One output visits 495 PRSS terms or 1,980 PRZS terms at 13 parties/t4.
    for terms in [495, 1980] {
        let left: Vec<_> = (0..terms).map(|_| Z::sample(&mut rng)).collect();
        let right: Vec<_> = (0..terms).map(|_| Z::sample(&mut rng)).collect();
        group.throughput(Throughput::Elements(terms as u64));
        group.bench_function(BenchmarkId::new("accumulate", terms), |b| {
            b.iter(|| {
                let mut sum = Z::ZERO;
                for (&left, &right) in black_box(left.as_slice())
                    .iter()
                    .zip(black_box(right.as_slice()))
                {
                    sum += left * right;
                }
                black_box(sum);
            });
        });
    }
    group.finish();
}

fn bench_operand_preparation<Z: BaseRing>(c: &mut Criterion, ring: &str) {
    let mut rng = AesRng::seed_from_u64(42);
    let mut group = c.benchmark_group(format!("prss_arithmetic/{ring}"));
    for terms in [495, 1980] {
        let operands: Vec<[Z; 4]> = (0..terms)
            .map(|_| std::array::from_fn(|_| Z::sample(&mut rng)))
            .collect();
        group.throughput(Throughput::Elements(terms as u64));
        group.bench_function(BenchmarkId::new("prepare_left", terms), |b| {
            b.iter(|| {
                // Prototype table: retain raw coefficients and the five fixed-left Karatsuba sums.
                // Includes table allocation; inputs are prepared outside timing.
                let prepared: Vec<_> = black_box(operands.as_slice())
                    .iter()
                    .map(|&a| {
                        let low = a[0] + a[1];
                        let high = a[2] + a[3];
                        let even = a[0] + a[2];
                        let odd = a[1] + a[3];
                        (a, [low, high, even, odd, even + odd])
                    })
                    .collect();
                black_box(prepared);
            });
        });
    }
    group.finish();
}

fn bench_prf(c: &mut Criterion) {
    bench_ring::<ResiduePolyF4Z64>(c, "f4_z64");
    bench_ring::<ResiduePolyF4Z128>(c, "f4_z128");
    bench_ring::<ResiduePolyF8Z64>(c, "f8_z64");
    bench_ring::<ResiduePolyF8Z128>(c, "f8_z128");
    bench_operand_preparation::<Z64>(c, "f4_z64");
    bench_operand_preparation::<Z128>(c, "f4_z128");
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
