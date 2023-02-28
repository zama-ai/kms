use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};

use distributed_decryption::gf256::{error_correction, ShamirZ2Poly, ShamirZ2Sharing, GF256};

fn bench_decode(c: &mut Criterion) {
    let degrees = vec![2_usize, 4, 8, 16, 32, 64];
    let mut group = c.benchmark_group("decode");

    for degree in &degrees {
        group.bench_function(BenchmarkId::new("degree", degree), |b| {
            let threshold = *degree;

            let mut coefs: Vec<GF256> = Vec::new();
            for i in 0..threshold + 1 {
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
                let secret_poly = error_correction(shares.clone(), threshold, 0).unwrap();
                assert_eq!(secret_poly, f);
            });
        });
    }
}

criterion_group!(decode, bench_decode);
criterion_main!(decode);
