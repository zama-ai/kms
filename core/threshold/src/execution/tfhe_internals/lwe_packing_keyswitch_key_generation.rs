use crate::algebra::{
    galois_rings::common::ResiduePoly,
    structure_traits::{BaseRing, Ring, Zero},
};
use itertools::Itertools;
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount},
    core_crypto::{commons::math::decomposition::DecompositionLevel, prelude::ByteRandomGenerator},
};

use super::{
    glwe_ciphertext::encrypt_glwe_ciphertext_list, glwe_key::GlweSecretKeyShare,
    lwe_key::LweSecretKeyShare, lwe_packing_keyswitch_key::LwePackingKeyswitchKeyShares,
    parameters::EncryptionType, randomness::MPCEncryptionRandomGenerator,
};

// Warning: This function will panic if the amount of elements in `input_lwe_sk` is different
// from the amount of elements in `lwe_packing_keyswitch_key`
//
// As with other key gen primitives,
// we expect the generator to already be filled with
// the correct noise from the caller
// as the noise is sampled via the MPC protocol
fn generate_lwe_packing_keyswitch_key<Z, Gen, const EXTENSION_DEGREE: usize>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_glwe_sk: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    lwe_packing_keyswitch_key: &mut LwePackingKeyswitchKeyShares<Z, EXTENSION_DEGREE>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
) where
    Z: BaseRing,
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
    Gen: ByteRandomGenerator,
{
    let decomp_base_log = lwe_packing_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_packing_keyswitch_key.decomposition_level_count();
    let polynomial_size = lwe_packing_keyswitch_key.output_polynomial_size();

    let input_key_it = input_lwe_sk.data_as_raw_vec().into_iter();
    let packing_key_switch_key_block_it = lwe_packing_keyswitch_key.iter_mut_levels();

    let mut decomposition_plaintexts_buffer =
        vec![ResiduePoly::<Z, EXTENSION_DEGREE>::ZERO; decomp_level_count.0 * polynomial_size.0];

    // Iterate over the input key elements and the destination lwe_packing_keyswitch_key memory
    // zip_eq and `encrypt_glwe_ciphertext_list` can panic but we just checked the length above to ensure this does not occur
    for (input_key_element, packing_keyswitch_key_block) in
        input_key_it.zip_eq(packing_key_switch_key_block_it)
    {
        // We fill the buffer with the powers of the key elements
        // zip_eq can panic, but we just defined decomposition_plaintexts_buffer with the right size
        for (level, message) in (1..=decomp_level_count.0)
            .rev()
            .map(DecompositionLevel)
            .zip_eq(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            //We only generate KSK in the smaller encryption domain, so we hardcode the 64 value here
            let shift = 64 - decomp_base_log.0 * level.0;
            message[0] = input_key_element << shift;
        }

        encrypt_glwe_ciphertext_list(
            output_glwe_sk,
            packing_keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            generator,
            EncryptionType::Bits64,
        );
    }
}

pub fn allocate_and_generate_lwe_packing_keyswitch_key<Z, Gen, const EXTENSION_DEGREE: usize>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_glwe_sk: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
) -> LwePackingKeyswitchKeyShares<Z, EXTENSION_DEGREE>
where
    Z: BaseRing,
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
    Gen: ByteRandomGenerator,
{
    // Ensure the input key and output key have the same number of elements to avoid a panic in `generate_lwe_packing_keyswitch_key`
    let mut new_ksk = LwePackingKeyswitchKeyShares::new(
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_glwe_sk.glwe_dimension(),
        output_glwe_sk.polynomial_size(),
    );

    generate_lwe_packing_keyswitch_key(input_lwe_sk, output_glwe_sk, &mut new_ksk, generator);
    new_ksk
}
