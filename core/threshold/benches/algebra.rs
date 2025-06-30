use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use itertools::Itertools;
use pprof::criterion::Output;
use pprof::criterion::PProfProfiler;
use rand::SeedableRng;
use threshold_fhe::algebra::poly::lagrange_interpolation;
use threshold_fhe::algebra::poly::lagrange_polynomials;
use threshold_fhe::algebra::poly::Poly;
use threshold_fhe::algebra::structure_traits::FromU128;
use threshold_fhe::execution::sharing::shamir::InputOp;
use threshold_fhe::execution::sharing::shamir::ShamirSharings;

fn bench_lagrange_poly(c: &mut Criterion) {
    // params are (num_parties, threshold, max_errors)

    use threshold_fhe::experimental::algebra::levels::LevelOne;
    let params = vec![(4, 1, 0), (10, 3, 0), (10, 3, 2), (40, 13, 0)];
    let mut group = c.benchmark_group("lagrange_interpolation");

    for p in &params {
        let (num_parties, threshold, max_err) = *p;
        let p_str = format!("n:{num_parties}/t:{threshold}/e:{max_err}");
        assert!(num_parties >= (threshold + 1) + 2 * max_err);

        group.bench_function(BenchmarkId::new("lagrange_mem", p_str.clone()), |b| {
            let mut rng = AesRng::seed_from_u64(0);
            let secret = LevelOne::from_u128(2345);
            let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
            let xs: Vec<_> = sharing
                .shares
                .iter()
                .map(|s| LevelOne::from_u128(s.owner().one_based() as u128))
                .collect();
            let ys: Vec<_> = sharing.shares.iter().map(|s| s.value()).collect();
            b.iter(|| {
                let interpolated = lagrange_interpolation(&xs, &ys);
                assert_eq!(interpolated.unwrap().eval(&LevelOne::from_u128(0)), secret);
            });
        });

        group.bench_function(BenchmarkId::new("lagrange_no_mem", p_str), |b| {
            let mut rng = AesRng::seed_from_u64(0);
            let secret = LevelOne::from_u128(2345);
            let sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();
            let xs: Vec<_> = sharing
                .shares
                .iter()
                .map(|s| LevelOne::from_u128(s.owner().one_based() as u128))
                .collect();
            let ys: Vec<_> = sharing.shares.iter().map(|s| s.value()).collect();
            b.iter(|| {
                let ls = lagrange_polynomials(&xs);
                let mut res = Poly::zero();
                for (li, vi) in ls.into_iter().zip_eq(ys.iter()) {
                    let term = li * vi;
                    res = res + term;
                }
                assert_eq!(res.eval(&LevelOne::from_u128(0)), secret);
            });
        });
    }
}

criterion_group! {
    name = algebra;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_lagrange_poly
}

criterion_main!(algebra);
