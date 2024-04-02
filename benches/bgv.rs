use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::Limb;
use crypto_bigint::NonZero;
use distributed_decryption::experimental::bgv::bgv_dec;
use distributed_decryption::experimental::bgv::bgv_enc;
use distributed_decryption::experimental::bgv::keygen;
use distributed_decryption::experimental::bgv::modulus_switch;
use distributed_decryption::experimental::bgv_algebra::GenericModulus;
use distributed_decryption::experimental::bgv_algebra::LevelEll;
use distributed_decryption::experimental::bgv_algebra::LevelKsw;
use distributed_decryption::experimental::bgv_algebra::LevelOne;
use distributed_decryption::experimental::bgv_algebra::Q;
use distributed_decryption::experimental::bgv_algebra::Q1;
use distributed_decryption::experimental::cyclotomic::RingElement;
use distributed_decryption::experimental::ntt::Const;
use distributed_decryption::experimental::ntt::N65536;
use pprof::criterion::Output;
use pprof::criterion::PProfProfiler;
use rand::RngCore;
use rand::SeedableRng;

fn bench_modswitch(c: &mut Criterion) {
    let plaintext_mod = 65537;
    let pmod = NonZero::new(Limb(plaintext_mod)).unwrap();
    let mut rng = AesRng::seed_from_u64(0);
    let new_hope_bound = 1;
    let (pk, sk) =
        keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, new_hope_bound, plaintext_mod);

    let m: Vec<u16> = (0..N65536::VALUE)
        .map(|_| (rng.next_u64() % plaintext_mod) as u16)
        .collect();
    let mr = RingElement::<u16>::from(m);
    let ct = bgv_enc(&mut rng, &mr, pk.a, pk.b, 1, plaintext_mod);

    let mut group = c.benchmark_group("modswitch");
    group.sample_size(10);
    group.bench_function("modswitch_large", |b| {
        let q = GenericModulus(*Q1::MODULUS.as_ref());
        let big_q = GenericModulus(*Q::MODULUS.as_ref());
        b.iter(|| {
            let ct_prime = modulus_switch::<LevelOne, LevelEll, N65536>(ct.clone(), q, big_q, pmod);
            let plaintext = bgv_dec(&ct_prime, sk.clone(), pmod);
            assert_eq!(plaintext, mr);
        });
    });
}

criterion_group! {
    name = bgv;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_modswitch,
}
criterion_main!(bgv);
