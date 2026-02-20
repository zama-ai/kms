//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../../../utilities.rs"]
mod utilities;

use rand::RngCore;
use tfhe::core_crypto::seeders::new_seeder;
use threshold_fhe::experimental::algebra::levels::{LevelEll, LevelKsw};
use threshold_fhe::experimental::algebra::ntt::*;
use threshold_fhe::experimental::bgv::basics::*;
use threshold_fhe::experimental::bgv::utils::XofWrapper;
use threshold_fhe::experimental::constants::*;

use crate::utilities::bench_memory;

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

pub fn bench_bgv(sk: SecretKey, pk: PublicBgvKeySet) {
    let mut seeder = new_seeder();
    let seed = seeder.seed().0;
    let mut rng = XofWrapper::new_bgv_enc(seed);

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
        let bench_fn =
            |(ct_a, ct_b, pk): &mut (LevelEllCiphertext, LevelEllCiphertext, PublicBgvKeySet)| {
                multiply_ctxt(ct_a, ct_b, pk)
            };
        bench_memory(
            bench_fn,
            &mut (ct_a.clone(), ct_b, pk.clone()),
            "non-threshold_basic-ops_bgv_mul_memory".to_string(),
        );
    }

    {
        let bench_fn = |(plaintext_vec, pk, seed): &mut (Vec<u32>, PublicBgvKeySet, u128)| {
            let mut rng = XofWrapper::new_bgv_enc(*seed);
            bgv_enc(
                &mut rng,
                plaintext_vec,
                &pk.a,
                &pk.b,
                PLAINTEXT_MODULUS.get().0,
            )
        };
        bench_memory(
            bench_fn,
            &mut (plaintext_vec_a.clone(), pk.clone(), seed),
            "non-threshold_basic-ops_bgv_encrypt_memory".to_string(),
        );
    }

    {
        let bench_fn = |(ct, sk): &mut (LevelEllCiphertext, SecretKey)| {
            bgv_dec(ct, sk.clone(), &PLAINTEXT_MODULUS)
        };
        bench_memory(
            bench_fn,
            &mut (ct_a.clone(), sk.clone()),
            "non-threshold_basic-ops_bgv_decrypt_memory".to_string(),
        );
    }
}

fn main() {
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);
    let mut seeder = new_seeder();
    let seed = seeder.seed().0;
    let mut xof = XofWrapper::new_bgv_kg(seed);
    let (pk, sk) = keygen::<_, LevelEll, LevelKsw, N65536>(&mut xof, PLAINTEXT_MODULUS.get().0);
    bench_bgv(sk, pk);
}
