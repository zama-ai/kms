use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::algebra::structure_traits::{FromU128, Sample};
use distributed_decryption::execution::sharing::shamir::ShamirSharing;
use distributed_decryption::execution::sharing::shamir::{InputOp, RevealOp, ShamirFieldPoly};
use distributed_decryption::experimental::algebra::levels::LevelOne;
use distributed_decryption::{
    algebra::{
        gf256::{error_correction, GF256},
        residue_poly::{ResiduePoly128, ResiduePoly64},
    },
    execution::sharing::shamir::ShamirSharings,
};
use itertools::Itertools;
use pprof::criterion::Output;
use pprof::criterion::PProfProfiler;
use rand::SeedableRng;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::num::Wrapping;

fn bench_decode_z2(c: &mut Criterion) {
    let degrees = vec![2_usize, 4, 8, 16, 32, 64];
    let mut group = c.benchmark_group("decode_z2");

    for degree in &degrees {
        group.bench_function(BenchmarkId::new("decode", degree), |b| {
            let threshold = *degree;

            let mut coefs: Vec<GF256> = Vec::new();
            for i in 0..=threshold {
                coefs.push(GF256::from(i as u8));
            }

            // f = a0 + ... + a_{t} * X^t
            let f = ShamirFieldPoly { coefs };

            // compute f(1),...,f(t+1)
            let party_ids: Vec<u8> = (1..2 * threshold + 2).map(|x| x as u8).collect();

            let shares: Vec<_> = party_ids
                .iter()
                .map(|x| ShamirSharing::<GF256> {
                    share: f.eval(&GF256::from(*x)),
                    party_id: *x,
                })
                .collect();

            b.iter(|| {
                let secret_poly = error_correction(&shares, threshold, 0).unwrap();
                assert_eq!(secret_poly, f);
            });
        });
    }
}

fn bench_decode_z128(c: &mut Criterion) {
    // params are (num_parties, threshold, max_errors)
    let params = vec![(4, 1, 0), (10, 3, 0), (10, 3, 2), (40, 13, 0)];
    let mut group = c.benchmark_group("decode_z128");

    for p in &params {
        let (num_parties, threshold, max_err) = *p;
        let p_str = format!("n:{num_parties}/t:{threshold}/e:{max_err}");
        assert!(num_parties >= (threshold + 1) + 2 * max_err);

        group.bench_function(BenchmarkId::new("decode", p_str), |b| {
            let mut rng = AesRng::seed_from_u64(0);
            let secret = ResiduePoly128::from_scalar(Wrapping(23425));
            let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();

            b.iter(|| {
                let f_zero = sharing.err_reconstruct(threshold, max_err).unwrap();
                assert_eq!(f_zero, secret);
            });
        });
    }
}

fn bench_decode_z64(c: &mut Criterion) {
    // params are (num_parties, threshold, max_errors)
    let params = vec![(4, 1, 0), (10, 3, 0), (10, 3, 2), (40, 13, 0)];
    let mut group = c.benchmark_group("decode_z64");

    for p in &params {
        let (num_parties, threshold, max_err) = *p;
        let p_str = format!("n:{num_parties} t:{threshold} e:{max_err}");
        assert!(num_parties >= (threshold + 1) + 2 * max_err);

        group.bench_function(BenchmarkId::new("decode", p_str), |b| {
            let mut rng = AesRng::seed_from_u64(0);
            let secret = ResiduePoly64::from_scalar(Wrapping(23425));
            let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();

            b.iter(|| {
                let f_zero = sharing.err_reconstruct(threshold, max_err).unwrap();
                assert_eq!(f_zero, secret);
            });
        });
    }
}

fn bench_decode_par_z64(c: &mut Criterion) {
    // params are (num_parties, threshold, max_errors)
    let params = vec![(4, 1, 1), (10, 3, 3), (40, 13, 13)];
    let chunk_sizes = [
        None,
        Some(1),
        Some(100),
        Some(1000),
        Some(5000),
        Some(10000),
    ];
    let mut group = c.benchmark_group("decode_par_z64");

    for p in &params {
        for chunk_size in chunk_sizes {
            let (num_parties, threshold, max_err) = *p;
            let p_str = format!(
                "n:{num_parties} t:{threshold} e:{max_err} chunk_size:{:?}",
                chunk_size
            );
            assert!(num_parties >= (threshold + 1) + 2 * max_err);

            group.bench_function(BenchmarkId::new("decode", p_str), |b| {
                //Doing 10000 reconstructions
                let num_rec = 10000;
                let mut rng = AesRng::seed_from_u64(0);
                let secrets = (0..num_rec)
                    .map(|_| ResiduePoly64::sample(&mut rng))
                    .collect_vec();
                let sharings = secrets
                    .into_iter()
                    .map(|secret| {
                        ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap()
                    })
                    .collect_vec();

                b.iter(|| {
                    let mut f_zero = Vec::new();
                    match chunk_size {
                        None => {
                            sharings
                                .iter()
                                .map(|sharing| sharing.err_reconstruct(threshold, max_err).unwrap())
                                .collect_vec();
                        }
                        Some(chunk_size) => {
                            sharings
                                .par_iter()
                                .with_min_len(chunk_size)
                                .map(|sharing| sharing.err_reconstruct(threshold, max_err).unwrap())
                                .collect_into_vec(&mut f_zero);
                        }
                    }
                });
            });
        }
    }
}

fn bench_decode_large_field(c: &mut Criterion) {
    // params are (num_parties, threshold, max_errors)
    let params = vec![(4, 1, 0), (10, 3, 0), (10, 3, 2), (40, 13, 0)];
    let mut group = c.benchmark_group("decode_large_field");

    for p in &params {
        let (num_parties, threshold, max_err) = *p;
        let p_str = format!("n:{num_parties}/t:{threshold}/e:{max_err}");
        assert!(num_parties >= (threshold + 1) + 2 * max_err);

        group.bench_function(BenchmarkId::new("decode", p_str), |b| {
            let mut rng = AesRng::seed_from_u64(0);
            let secret = LevelOne::from_u128(2345);
            let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
            b.iter(|| {
                let f_zero = sharing.err_reconstruct(threshold, max_err).unwrap();
                assert_eq!(f_zero, secret);
            });
        });
    }
}

criterion_group! {
    name = decode;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_decode_z2, bench_decode_z128, bench_decode_z64,
    bench_decode_large_field, bench_decode_par_z64
}
criterion_main!(decode);
