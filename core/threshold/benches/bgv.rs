use aes_prng::AesRng;
use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_bigint::modular::ConstMontyParams;
use distributed_decryption::execution::runtime::test_runtime::generate_fixed_identities;
use distributed_decryption::experimental::algebra::levels::*;
use distributed_decryption::experimental::algebra::ntt::N65536;
use distributed_decryption::experimental::algebra::ntt::{Const, NTTConstants};
use distributed_decryption::experimental::bgv::basics::bgv_dec;
use distributed_decryption::experimental::bgv::basics::bgv_enc;
use distributed_decryption::experimental::bgv::basics::keygen;
use distributed_decryption::experimental::bgv::basics::modulus_switch;
use distributed_decryption::experimental::bgv::ddec::keygen_shares;
use distributed_decryption::experimental::bgv::endpoints::threshold_decrypt;
use distributed_decryption::experimental::bgv::runtime::BGVTestRuntime;
use distributed_decryption::experimental::constants::PLAINTEXT_MODULUS;
use pprof::criterion::Output;
use pprof::criterion::PProfProfiler;
use rand::RngCore;
use rand::SeedableRng;

fn bench_modswitch(c: &mut Criterion) {
    let mut rng = AesRng::seed_from_u64(0);
    let (pk, sk) =
        keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, PLAINTEXT_MODULUS.get().0);

    let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
        .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
        .collect();
    let ct = bgv_enc(
        &mut rng,
        &plaintext_vec,
        &pk.a,
        &pk.b,
        PLAINTEXT_MODULUS.get().0,
    );

    let mut group = c.benchmark_group("modswitch");
    group.sample_size(10);
    group.bench_function("modswitch_large", |b| {
        let q = LevelOne {
            value: GenericModulus(*Q1::MODULUS.as_ref()),
        };
        let big_q = LevelEll {
            value: GenericModulus(*Q::MODULUS.as_ref()),
        };
        b.iter(|| {
            let ct_prime =
                modulus_switch::<LevelOne, LevelEll, N65536>(&ct, q, big_q, *PLAINTEXT_MODULUS);
            let plaintext = bgv_dec(&ct_prime, sk.clone(), &PLAINTEXT_MODULUS);
            assert_eq!(plaintext, plaintext_vec);
        });
    });
}

#[derive(Debug, Clone, Copy)]
struct ThresholdConfig {
    n: usize,
    t: u8,
}

impl ThresholdConfig {
    pub fn new(n: usize, t: u8) -> Self {
        ThresholdConfig { n, t }
    }
}

impl std::fmt::Display for ThresholdConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "n={}_t={}", self.n, self.t)?;
        Ok(())
    }
}

fn bench_bgv_ddec(c: &mut Criterion) {
    let mut rng = AesRng::seed_from_u64(0);

    let (pk, sk) =
        keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, PLAINTEXT_MODULUS.get().0);

    let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
        .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
        .collect();
    let params = vec![ThresholdConfig::new(5, 1)];
    let mut group = c.benchmark_group("bgv_ddec");

    group.sample_size(10);
    group.sampling_mode(criterion::SamplingMode::Flat);
    let mut rng = AesRng::from_entropy();
    for config in params {
        let ct = bgv_enc(
            &mut rng,
            &plaintext_vec,
            &pk.a,
            &pk.b,
            PLAINTEXT_MODULUS.get().0,
        );
        let keyshares = keygen_shares(&mut rng, &sk, config.n, config.t);
        let ntt_keyshares: Vec<_> = keyshares
            .iter()
            .map(|k| k.as_ntt_repr(N65536::VALUE, N65536::THETA))
            .collect();
        let identities = generate_fixed_identities(config.n);

        let runtime = BGVTestRuntime::new(identities, config.t);
        group.bench_with_input(
            BenchmarkId::from_parameter(config),
            &(config, ct.clone(), ntt_keyshares, runtime),
            |b, (_config, ct, ks, runtime)| {
                b.iter(|| {
                    let _ = threshold_decrypt(runtime, ks, ct);
                });
            },
        );
    }
}

fn bench_bfv_to_bgv(c: &mut Criterion) {
    let mut rng = AesRng::seed_from_u64(0);
    let (pk, _) = distributed_decryption::experimental::bfv::basics::keygen::<AesRng>(&mut rng);

    let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
        .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
        .collect();
    let ct = distributed_decryption::experimental::bfv::basics::bfv_enc(
        &mut rng,
        &plaintext_vec,
        &pk.a,
        &pk.b,
    );

    let mut group = c.benchmark_group("bfv-to-bgv");
    group.sample_size(10);
    group.bench_function("conversion", |b| {
        b.iter(|| {
            let _ = distributed_decryption::experimental::bfv::basics::bfv_to_bgv(ct.clone());
        });
    });
}

criterion_group! {
    name = bgv;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_modswitch, bench_bgv_ddec, bench_bfv_to_bgv,
}
criterion_main!(bgv);
