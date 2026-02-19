//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../../../utilities.rs"]
mod utilities;

use aes_prng::AesRng;
use rand::RngCore;
use std::fmt::Write;
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::constants::*;

use crate::utilities::bench_memory;

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

pub fn bench_bgv(sk: SecretKey, pk: PublicBgvKeySet) {
    let mut rng = AesRng::from_random_seed();
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
        write!(name, "bgv_mul_memory").unwrap();
        let bench_fn =
            |(ct_a, ct_b, pk): &mut (LevelEllCiphertext, LevelEllCiphertext, PublicBgvKeySet)| {
                multiply_ctxt(ct_a, ct_b, pk)
            };
        bench_memory(
            bench_fn,
            &mut (ct_a.clone(), ct_b, pk.clone()),
            name.clone(),
        );
        name.clear();
    }

    {
        write!(name, "bgv_encrypt_memory").unwrap();
        let bench_fn = |(plaintext_vec, pk, rng): &mut (Vec<u32>, PublicBgvKeySet, AesRng)| {
            bgv_enc(rng, plaintext_vec, &pk.a, &pk.b, PLAINTEXT_MODULUS.get().0)
        };
        bench_memory(
            bench_fn,
            &mut (plaintext_vec_a.clone(), pk.clone(), rng.clone()),
            name.clone(),
        );
        name.clear();
    }

    {
        write!(name, "bgv_decrypt_memory").unwrap();
        let bench_fn = |(ct, sk): &mut (LevelEllCiphertext, SecretKey)| {
            bgv_dec(ct, sk.clone(), &PLAINTEXT_MODULUS)
        };
        bench_memory(bench_fn, &mut (ct_a.clone(), sk.clone()), name.clone());
        name.clear();
    }
}

fn main() {
    let mut rng = AesRng::from_random_seed();
    let (pk, sk) =
        keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, PLAINTEXT_MODULUS.get().0);
    bench_bgv(sk, pk);
}
