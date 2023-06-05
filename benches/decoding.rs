use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    gf256::{error_correction, ShamirZ2Poly, ShamirZ2Sharing, GF256},
    residue_poly::ResiduePoly,
    shamir::ShamirGSharings,
    Zero, Z128, Z64,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
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
            let f = ShamirZ2Poly { coefs };

            // compute f(1),...,f(t+1)
            let party_ids: Vec<u8> = (1..2 * threshold + 2).map(|x| x as u8).collect();

            let shares: Vec<_> = party_ids
                .iter()
                .map(|x| ShamirZ2Sharing {
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
        let p_str = format!("n:{num_parties} t:{threshold} e:{max_err}");
        assert!(num_parties >= (threshold + 1) + 2 * max_err);

        group.bench_function(BenchmarkId::new("decode", p_str), |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(0);
            let secret: Z128 = Wrapping(23425);
            let sharings =
                ShamirGSharings::<Z128>::share(&mut rng, secret, num_parties, threshold).unwrap();

            b.iter(|| {
                let recon = sharings.decode(threshold, max_err).unwrap();
                let f_zero = recon.eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);
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
            let mut rng = ChaCha12Rng::seed_from_u64(0);
            let secret: Z64 = Wrapping(23425);
            let sharings =
                ShamirGSharings::<Z64>::share(&mut rng, secret, num_parties, threshold).unwrap();

            b.iter(|| {
                let recon = sharings.decode(threshold, max_err).unwrap();
                let f_zero = recon.eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);
            });
        });
    }
}

criterion_group!(decode, bench_decode_z2, bench_decode_z128, bench_decode_z64);
criterion_main!(decode);
