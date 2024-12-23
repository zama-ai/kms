use crate::{
    algebra::{
        galois_rings::degree_8::ResiduePolyF8,
        structure_traits::{BaseRing, Zero},
    },
    error::error_handler::anyhow_error_and_log,
};
use itertools::{EitherOrBoth, Itertools};
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount},
    core_crypto::{commons::math::decomposition::DecompositionLevel, prelude::ByteRandomGenerator},
};

use super::{
    glwe_ciphertext::encrypt_glwe_ciphertext_list, glwe_key::GlweSecretKeyShare,
    lwe_key::LweSecretKeyShare, lwe_packing_keyswitch_key::LwePackingKeyswitchKeyShares,
    parameters::EncryptionType, randomness::MPCEncryptionRandomGenerator,
};

// As with other key gen primitives,
// we expect the generator to already be filled with
// the correct noise from the caller
// as the noise is sampled via the MPC protocol
pub fn generate_lwe_packing_keyswitch_key<Z, Gen>(
    input_lwe_sk: &LweSecretKeyShare<Z>,
    output_glwe_sk: &GlweSecretKeyShare<Z>,
    lwe_packing_keyswitch_key: &mut LwePackingKeyswitchKeyShares<Z>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
{
    let decomp_base_log = lwe_packing_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_packing_keyswitch_key.decomposition_level_count();
    let polynomial_size = lwe_packing_keyswitch_key.output_polynomial_size();

    let mut decomposition_plaintexts_buffer =
        vec![ResiduePolyF8::<Z>::ZERO; decomp_level_count.0 * polynomial_size.0];

    // Iterate over the input key elements and the destination lwe_packing_keyswitch_key memory
    for (input_key_element, packing_keyswitch_key_block) in input_lwe_sk
        .data_as_raw_vec()
        .iter()
        .zip(lwe_packing_keyswitch_key.iter_mut_levels())
    {
        // We fill the buffer with the powers of the key elements
        for level_message in (1..=decomp_level_count.0)
            .rev()
            .map(DecompositionLevel)
            .zip_longest(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            if let EitherOrBoth::Both(level, message) = level_message {
                //We only generate KSK in the smaller encryption domain, so we hardcode the 64 value here
                let shift = 64 - decomp_base_log.0 * level.0;
                message[0] = (*input_key_element) << shift;
            } else {
                return Err(anyhow_error_and_log("zip error"));
            }
        }

        encrypt_glwe_ciphertext_list(
            output_glwe_sk,
            packing_keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            generator,
            EncryptionType::Bits64,
        )?;
    }
    Ok(())
}

pub fn allocate_and_generate_lwe_packing_keyswitch_key<Z, Gen>(
    input_lwe_sk: &LweSecretKeyShare<Z>,
    output_glwe_sk: &GlweSecretKeyShare<Z>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen>,
) -> anyhow::Result<LwePackingKeyswitchKeyShares<Z>>
where
    Z: BaseRing,
    Gen: ByteRandomGenerator,
{
    let mut new_ksk = LwePackingKeyswitchKeyShares::new(
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_glwe_sk.glwe_dimension(),
        output_glwe_sk.polynomial_size(),
    );

    generate_lwe_packing_keyswitch_key(input_lwe_sk, output_glwe_sk, &mut new_ksk, generator)?;

    Ok(new_ksk)
}
