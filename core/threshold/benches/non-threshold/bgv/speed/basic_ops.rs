//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../../../utilities.rs"]
mod utilities;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use rand::RngCore;
use std::fmt::Write;
use std::hint::black_box;
use tfhe::core_crypto::seeders::new_seeder;
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::bgv::utils::XofWrapper;
use threshold_fhe::experimental::constants::*;

pub fn bench_bgv(
    bench_group: &mut BenchmarkGroup<'_, WallTime>,
    sk: SecretKey,
    pk: PublicBgvKeySet,
) {
    let mut seeder = new_seeder();
    let seed = seeder.seed().0;
    let mut rng = XofWrapper::new_bgv_enc(seed);
    let mut name = String::with_capacity(255);

    let plaintext_vec_a: Vec<u32> = (0..N65536::VALUE)
        .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
        .collect();
    let plaintext_vec_b: Vec<u32> = (0..N65536::VALUE)
        .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
        .collect();

    let ct_a = bgv_enc(
        &mut rng,
        &plaintext_vec_a,
        &pk.a,
        &pk.b,
        PLAINTEXT_MODULUS.get().0,
    );
    let ct_b = bgv_enc(
        &mut rng,
        &plaintext_vec_b,
        &pk.a,
        &pk.b,
        PLAINTEXT_MODULUS.get().0,
    );

    {
        write!(name, "mul(bgv)").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| black_box(multiply_ctxt(&ct_a, &ct_b, &pk)));
        });
        name.clear();
    }

    {
        write!(name, "encrypt(bgv)").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| {
                let mut rng = XofWrapper::new_bgv_enc(seed);
                black_box(bgv_enc(
                    &mut rng,
                    &plaintext_vec_a,
                    &pk.a,
                    &pk.b,
                    PLAINTEXT_MODULUS.get().0,
                ))
            });
        });
        name.clear();
    }

    {
        write!(name, "decrypt(bgv)").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| black_box(bgv_dec(&ct_a, sk.clone(), &PLAINTEXT_MODULUS)))
        });
        name.clear();
    }
}

fn main() {
    let mut seeder = new_seeder();
    let seed = seeder.seed().0;
    let mut xof = XofWrapper::new_bgv_kg(seed);
    let (pk, sk) = keygen::<_, LevelEll, LevelKsw, N65536>(&mut xof, PLAINTEXT_MODULUS.get().0);

    let mut c = Criterion::default().sample_size(10).configure_from_args();
    {
        let mut group = c.benchmark_group("non-threshold_basic-ops_bgv");
        bench_bgv(&mut group, sk, pk);
        group.finish();
    }

    c.final_summary();
}
