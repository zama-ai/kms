use core::fmt;
use core::fmt::Debug;
use std::num::Wrapping;

use aligned_vec::ABox;
use num_traits::AsPrimitive;
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::{
        algorithms::{
            allocate_and_trivially_encrypt_new_glwe_ciphertext,
            lwe_ciphertext_cleartext_mul_assign, programmable_bootstrap_f128_lwe_ciphertext,
        },
        commons::{
            ciphertext_modulus::CiphertextModulus,
            parameters::{GlweSize, LweSize},
            traits::{CastFrom, CastInto, Container, ContainerMut, UnsignedInteger, UnsignedTorus},
        },
        entities::{
            Cleartext, Fourier128LweBootstrapKey, GlweCiphertextOwned, LweCiphertext, PlaintextList,
        },
    },
    integer::{parameters::PolynomialSize, IntegerCiphertext},
};
use tracing::instrument;

use crate::{
    algebra::{base_ring::Z128, structure_traits::Zero},
    error::error_handler::anyhow_error_and_log,
};

use super::parameters::{
    AugmentedCiphertextParameters, Ciphertext128, Ciphertext128Block, Ciphertext64,
    Ciphertext64Block,
};

/// Key used for switch-and-squash to convert a ciphertext over u64 to one over u128
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct SwitchAndSquashKey {
    pub fbsk_out: Fourier128LweBootstrapKey<ABox<[f64]>>,
}

impl Debug for SwitchAndSquashKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bootstrapping key vector{:?}", self.fbsk_out)
    }
}
impl SwitchAndSquashKey {
    pub fn new(fbsk_out: Fourier128LweBootstrapKey<ABox<[f64]>>) -> Self {
        SwitchAndSquashKey { fbsk_out }
    }

    /// Converts a ciphertext over a 64 bit domain to a ciphertext over a 128 bit domain (which is needed for secure threshold decryption).
    /// Conversion is done using a precreated conversion key [conversion_key].
    /// Observe that the decryption key will be different after conversion, since [conversion_key] is actually a key-switching key.
    #[instrument(name = "SwitchAndSquash", skip(self, raw_small_ct), fields(batch_size=?raw_small_ct.blocks().len()))]
    pub fn to_large_ciphertext(
        &self,
        raw_small_ct: &Ciphertext64,
    ) -> anyhow::Result<Ciphertext128> {
        let blocks = raw_small_ct.blocks();
        let mut res = Vec::with_capacity(blocks.len());
        for current_block in blocks {
            res.push(self.to_large_ciphertext_block(current_block)?);
        }
        Ok(res)
    }

    /// Converts a single ciphertext block over a 64 bit domain to a ciphertext block over a 128 bit domain (which is needed for secure threshold decryption).
    /// Conversion is done using a precreated conversion key, [conversion_key].
    /// Observe that the decryption key will be different after conversion, since [conversion_key] is actually a key-switching key.
    pub fn to_large_ciphertext_block(
        &self,
        small_ct_block: &Ciphertext64Block,
    ) -> anyhow::Result<Ciphertext128Block> {
        let total_bits = small_ct_block.total_block_bits();
        // Accumulator definition
        let delta = 1_u64 << (u64::BITS - 1 - total_bits);
        let msg_modulus = 1_u64 << total_bits;

        let f_out = |x: u128| x;
        let delta_u128 = (delta as u128) << 64;
        let accumulator_out: GlweCiphertextOwned<u128> = Self::generate_accumulator(
            self.fbsk_out.polynomial_size(),
            self.fbsk_out.glwe_size(),
            msg_modulus.cast_into(),
            CiphertextModulus::<u128>::new_native(),
            delta_u128,
            f_out,
        );

        //MSUP
        let mut ms_output_lwe = LweCiphertext::new(
            0_u128,
            self.fbsk_out.input_lwe_dimension().to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        Self::lwe_ciphertext_modulus_switch_up(&mut ms_output_lwe, &small_ct_block.ct)?;

        let pbs_cipher_size = LweSize(
            1 + self.fbsk_out.glwe_size().to_glwe_dimension().0 * self.fbsk_out.polynomial_size().0,
        );
        let mut out_pbs_ct = LweCiphertext::new(
            0_u128,
            pbs_cipher_size,
            CiphertextModulus::<u128>::new_native(),
        );
        programmable_bootstrap_f128_lwe_ciphertext(
            &ms_output_lwe,
            &mut out_pbs_ct,
            &accumulator_out,
            &self.fbsk_out,
        );
        Ok(out_pbs_ct)
    }

    // Here we will define a helper function to generate an accumulator for a PBS
    fn generate_accumulator<F, Scalar: UnsignedTorus + CastFrom<usize>>(
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        message_modulus: usize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        delta: Scalar,
        f: F,
    ) -> GlweCiphertextOwned<Scalar>
    where
        F: Fn(Scalar) -> Scalar,
    {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the
        // notion of box, which manages redundancy to yield a denoised value
        // for several noisy values around a true input value.
        let box_size = polynomial_size.0 / message_modulus;

        // Create the accumulator
        let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

        // Fill each box with the encoded denoised value
        for i in 0..message_modulus {
            let index = i * box_size;
            accumulator_scalar[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_scalar.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

        allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &accumulator_plaintext,
            ciphertext_modulus,
        )
    }

    /// The method below is copied from the `noise-gap-exp` branch in tfhe-rs-internal (and added error handling)
    /// since this branch will likely not be merged in main.
    ///
    /// Takes a ciphertext, `input`, of a certain domain, [InputScalar] and overwrites the content of `output`
    /// with the ciphertext converted to the [OutputScaler] domain.
    fn lwe_ciphertext_modulus_switch_up<InputScalar, OutputScalar, InputCont, OutputCont>(
        output: &mut LweCiphertext<OutputCont>,
        input: &LweCiphertext<InputCont>,
    ) -> anyhow::Result<()>
    where
        InputScalar: UnsignedInteger + CastInto<OutputScalar>,
        OutputScalar: UnsignedInteger,
        InputCont: Container<Element = InputScalar>,
        OutputCont: ContainerMut<Element = OutputScalar>,
    {
        if !input.ciphertext_modulus().is_native_modulus() {
            return Err(anyhow_error_and_log(
                "Ciphertext modulus is not native, which is the only kind supported",
            ));
        }

        output
            .as_mut()
            .iter_mut()
            .zip(input.as_ref().iter())
            .for_each(|(dst, &src)| *dst = src.cast_into());
        let modulus_up: CiphertextModulus<OutputScalar> = input
            .ciphertext_modulus()
            .try_to()
            .map_err(|_| anyhow_error_and_log("Could not parse ciphertext modulus"))?;

        lwe_ciphertext_cleartext_mul_assign(
            output,
            Cleartext(modulus_up.get_power_of_two_scaling_to_native_torus()),
        );
        Ok(())
    }
}

// Map a raw, decrypted message to its real value by dividing by the appropriate shift, delta, assuming padding
pub(crate) fn from_expanded_msg<Scalar: UnsignedInteger + AsPrimitive<u128>>(
    raw_plaintext: Scalar,
    message_and_carry_mod_bits: usize,
) -> Z128 {
    // delta = q/t where t is the amount of plain text bits
    // Observe we actually divide this by 2 (i.e. subtract 1 bit) to make space for padding
    let delta_pad_bits = (Scalar::BITS as u128) - (message_and_carry_mod_bits as u128 + 1_u128);

    // compute delta / 2
    let delta_pad_half = 1 << (delta_pad_bits - 1);

    // add delta/2 to kill the negative noise, note this does not affect the message.
    let raw_msg = raw_plaintext.as_().wrapping_add(delta_pad_half) >> delta_pad_bits;

    let msg = Wrapping(raw_msg % (1 << message_and_carry_mod_bits));
    // Observe that in certain situations the computation of b-<a,s> may be negative
    // Concretely this happens when the message encrypted is 0 and randomness ends up being negative.
    // We cannot simply do the standard modulo operation then, as this would mean the message becomes
    // 2^message_mod_bits instead of 0 as it should be.
    // However the maximal negative value it can have (without a general decryption error) is delta/2
    // which we can compute as 1 << delta_pad_bits, since the padding already halves the true delta
    if raw_plaintext.as_() > Scalar::MAX.as_() - (1 << delta_pad_bits) {
        Z128::ZERO
    } else {
        msg
    }
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use num_traits::AsPrimitive;
    use tfhe::{
        core_crypto::{commons::traits::UnsignedInteger, entities::Plaintext},
        prelude::{FheDecrypt, FheEncrypt},
        FheUint8,
    };

    use crate::{
        algebra::base_ring::Z128,
        execution::{
            constants::{SMALL_TEST_KEY_PATH, SMALL_TEST_PARAM_PATH},
            tfhe_internals::{
                parameters::{AugmentedCiphertextParameters, NoiseFloodParameters},
                switch_and_squash::from_expanded_msg,
                test_feature::KeySet,
            },
        },
        file_handling::{read_as_json, read_element},
    };

    /// Map a real message, of a few bits, to the encryption domain, by applying the appropriate shift, delta.
    /// The function assumes padding will be used.
    fn to_expanded_msg(message: u64, message_mod_bits: usize) -> Plaintext<u64> {
        let sanitized_msg = message % (1 << message_mod_bits);
        // Observe we shift with u64::BITS - 1 to allow for the padding bit so PBS can be used on the ciphertext made from this
        let delta_bits = (u64::BITS - 1) - message_mod_bits as u32;
        Plaintext(sanitized_msg << delta_bits)
    }

    #[test]
    fn check_cipher_mapping() {
        for msg in 0..=17 {
            let cipher_domain: Plaintext<u64> = to_expanded_msg(msg, 4);
            let plain_domain = from_expanded_msg(cipher_domain.0, 4);
            // Compare with the message, taken modulo the message domain size, 16=1<<4
            assert_eq!(plain_domain.0, (msg as u128) % (1 << 4));
        }
    }

    #[test]
    fn sunshine_domain_switching() {
        let message = 255_u8;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        let small_ct = FheUint8::encrypt(message, &keyset.client_key);
        let large_ct = keyset
            .public_keys
            .sns_key
            .unwrap()
            .to_large_ciphertext(&small_ct.clone().into_raw_parts().0)
            .unwrap();
        let res_small: u8 = small_ct.decrypt(&keyset.client_key);
        let res_large = keyset.sns_secret_key.decrypt_128(&large_ct);
        assert_eq!(message, res_small);
        assert_eq!(message as u128, res_large);
    }

    #[test]
    fn sunshine_enc_dec() {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        for msg in 0_u8..8 {
            let small_ct = FheUint8::encrypt(msg, &keys.public_keys.public_key);
            let (raw_ct, _id) = small_ct.clone().into_raw_parts();
            let small_res: u8 = small_ct.decrypt(&keys.client_key);
            assert_eq!(msg, small_res);
            let large_ct = keys
                .public_keys
                .sns_key
                .as_ref()
                .unwrap()
                .to_large_ciphertext(&raw_ct)
                .unwrap();
            let large_res = keys.sns_secret_key.decrypt_128(&large_ct);
            assert_eq!(msg as u128, large_res);
        }
    }

    /// Tests the fixing of this bug https://github.com/zama-ai/distributed-decryption/issues/181
    /// which could result in decrypting 2^message_bits when a message 0 was encrypted and randomness
    /// in the encryption ends up being negative
    #[test]
    fn negative_wrapping() {
        let params: NoiseFloodParameters = read_as_json(SMALL_TEST_PARAM_PATH.to_string()).unwrap();
        let delta_half = 1
            << ((u128::BITS as u128 - 1_u128)
                - params.ciphertext_parameters.total_block_bits() as u128);
        // Should be rounded to 0, since it is the negative part of the numbers that should round to 0
        let msg = u128::MAX - delta_half + 1;
        let res = from_expanded_msg(
            msg,
            params.ciphertext_parameters.total_block_bits() as usize,
        );
        assert_eq!(0, res.0);

        // Check that this is where the old code failed
        let res = old_from_expanded_msg(
            msg,
            params.ciphertext_parameters.total_block_bits() as usize,
        );
        assert_ne!(0, res.0);

        // Should not be 0, but instead the maximal message allowed
        let msg = u128::MAX - delta_half - 1;
        let res = from_expanded_msg(
            msg,
            params.ciphertext_parameters.total_block_bits() as usize,
        );
        assert_eq!(
            (1 << params.ciphertext_parameters.total_block_bits()) - 1,
            res.0
        );
    }

    fn old_from_expanded_msg<Scalar: UnsignedInteger + AsPrimitive<u128>>(
        raw_plaintext: Scalar,
        message_mod_bits: usize,
    ) -> Z128 {
        let delta_bits = (Scalar::BITS as u128 - 1_u128) - message_mod_bits as u128;
        let rounding_bit = 1 << (delta_bits - 1);
        //compute the rounding bit
        let rounding = (raw_plaintext.as_() & rounding_bit) << 1;

        let msg = (raw_plaintext.as_().wrapping_add(rounding)) >> delta_bits;
        Wrapping(msg % (1 << message_mod_bits))
    }
}
