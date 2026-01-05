//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::set_plan;
use aes_prng::AesRng;
#[cfg(not(feature = "measure_memory"))]
use criterion::Criterion;
use rand::prelude::*;
use tfhe::{prelude::*, CompactPublicKey, ReRandomizationContext};
use tfhe::{set_server_key, ClientKey, FheUint64, ServerKey};
use utilities::ALL_PARAMS;

/// This one uses overflowing sub to remove the need for comparison
/// it also uses the 'boolean' multiplication
fn transfer_overflow(
    from_amount: &mut FheUint64,
    to_amount: &mut FheUint64,
    amount: &mut FheUint64,
    compact_pk: &CompactPublicKey,
) -> (FheUint64, FheUint64) {
    /* FIRST: Proceed with rerandomization of the inputs */
    // Simulate a 256 bits hash added as metadata
    let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    let rand_c: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

    from_amount
        .re_randomization_metadata_mut()
        .set_data(&rand_a);
    to_amount.re_randomization_metadata_mut().set_data(&rand_b);
    amount.re_randomization_metadata_mut().set_data(&rand_c);

    // Simulate a 256 bits nonce
    let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

    let mut re_rand_context = ReRandomizationContext::new(
        *b"TFHE.Rrd",
        // First is the function description, second is a nonce
        [b"ERC20Transfer".as_slice(), nonce.as_slice()],
        *b"TFHE.Enc",
    );

    re_rand_context.add_ciphertext(from_amount);
    re_rand_context.add_ciphertext(to_amount);
    re_rand_context.add_ciphertext(amount);
    let mut seed_gen = re_rand_context.finalize();
    from_amount
        .re_randomize(compact_pk, seed_gen.next_seed().unwrap())
        .unwrap();
    to_amount
        .re_randomize(compact_pk, seed_gen.next_seed().unwrap())
        .unwrap();
    amount
        .re_randomize(compact_pk, seed_gen.next_seed().unwrap())
        .unwrap();

    let from_amount = &*from_amount;
    let to_amount = &*to_amount;
    let amount = &*amount;

    /* SECOND: Compute the new balances */
    let (new_from, did_not_have_enough) = (from_amount).overflowing_sub(amount);

    let new_from_amount = did_not_have_enough.if_then_else(from_amount, &new_from);

    let had_enough_funds = !did_not_have_enough;
    let new_to_amount = to_amount + (amount * FheUint64::cast_from(had_enough_funds));

    (new_from_amount, new_to_amount)
}

#[cfg(not(feature = "measure_memory"))]
#[allow(unused_mut)]
fn main() {
    set_plan();
    for (name, params) in ALL_PARAMS {
        if params
            .get_params_basics_handle()
            .get_rerand_params()
            .is_none()
        {
            // Rerandomization is required for this bench
            continue;
        }
        let config = params.to_tfhe_config();

        let mut rng = AesRng::from_entropy();
        let cks = ClientKey::generate(config);
        let sks = ServerKey::new(&cks);
        let public_key = tfhe::CompactPublicKey::new(&cks);

        let mut from_amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);
        let mut to_amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);
        let mut amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);

        let mut c = Criterion::default().sample_size(10).configure_from_args();

        let bench_name = format!("non-threshold_erc20_{name}");
        // FheUint64 latency
        {
            let mut group = c.benchmark_group(&bench_name);

            let bench_id = format!("{bench_name}::overflow::FheUint64");
            group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let (_, _) = transfer_overflow(
                        &mut from_amount.clone(),
                        &mut to_amount.clone(),
                        &mut amount.clone(),
                        &public_key,
                    );
                })
            });

            group.finish();
        }

        c.final_summary();
    }
}

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

#[cfg(feature = "measure_memory")]
fn main() {
    set_plan();
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    let transfer = |(mut from_amount, mut to_amount, mut amount, public_key): (
        FheUint64,
        FheUint64,
        FheUint64,
        CompactPublicKey,
    )| {
        transfer_overflow(&mut from_amount, &mut to_amount, &mut amount, &public_key)
    };

    for (name, params) in ALL_PARAMS {
        if params
            .get_params_basics_handle()
            .get_rerand_params()
            .is_none()
        {
            // Rerandomization is required for this bench
            continue;
        }
        use crate::utilities::bench_memory;

        let bench_name = format!("non-threshold_erc20_{name}_memory");

        let config = params.to_tfhe_config();

        let cks = ClientKey::generate(config);
        let sks = ServerKey::new(&cks);
        let public_key = tfhe::CompactPublicKey::new(&cks);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
        let mut rng = AesRng::from_entropy();

        let from_amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);
        let to_amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);
        let amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);

        bench_memory(
            transfer,
            (from_amount, to_amount, amount, public_key),
            bench_name,
        );
    }
}
