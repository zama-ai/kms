use num_traits::AsPrimitive;
use std::num::Wrapping;
use tfhe::core_crypto::commons::traits::UnsignedInteger;

use crate::algebra::{base_ring::Z128, structure_traits::Zero};

// Map a raw, decrypted message to its real value by dividing by the appropriate shift, delta, assuming padding
pub(crate) fn from_expanded_msg<Scalar: UnsignedInteger + AsPrimitive<u128>>(
    raw_plaintext: Scalar,
    message_and_carry_mod_bits: usize,
) -> Z128 {
    // delta = q/t where t is the amount of plain text bits
    // Observe that t includes the message and carry bits as well as the padding bit (hence the + 1)
    let delta_pad_bits = (Scalar::BITS as u128) - (message_and_carry_mod_bits as u128 + 1_u128);

    // Observe that in certain situations the computation of b-<a,s> may be negative
    // Concretely this happens when the message encrypted is 0 and randomness ends up being negative.
    // We cannot simply do the standard modulo operation then, as this would mean the message becomes
    // 2^message_mod_bits instead of 0 as it should be.
    // However the maximal negative value it can have (without a general decryption error) is delta/2
    // which we can compute as 1 << delta_pad_bits, since the padding already halves the true delta
    if raw_plaintext.as_() > Scalar::MAX.as_() - (1 << delta_pad_bits) {
        Z128::ZERO
    } else {
        // compute delta / 2
        let delta_pad_half = 1 << (delta_pad_bits - 1);

        // add delta/2 to kill the negative noise, note this does not affect the message.
        // and then divide by delta
        let raw_msg = raw_plaintext.as_().wrapping_add(delta_pad_half) >> delta_pad_bits;
        Wrapping(raw_msg % (1 << message_and_carry_mod_bits))
    }
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use num_traits::AsPrimitive;
    use tfhe::{
        core_crypto::{commons::traits::UnsignedInteger, entities::Plaintext},
        integer::bigint::U2048,
        prelude::{CiphertextList, FheDecrypt, FheEncrypt, SquashNoise},
        set_server_key, CompactCiphertextList, FheUint2048, FheUint8,
    };

    use crate::{
        algebra::base_ring::Z128,
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            tfhe_internals::{
                parameters::{AugmentedCiphertextParameters, DKGParams, PARAMS_TEST_BK_SNS},
                switch_and_squash::from_expanded_msg,
                test_feature::KeySet,
            },
        },
        file_handling::read_element,
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
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        tfhe::set_server_key(keyset.public_keys.server_key);

        let small_ct = FheUint8::encrypt(message, &keyset.client_key);
        let res_small: u8 = small_ct.decrypt(&keyset.client_key);

        let big_ctxt = small_ct.squash_noise().unwrap();
        let res_large: u8 = big_ctxt.decrypt(&keyset.client_key);

        assert_eq!(message, res_small);
        assert_eq!(message, res_large);
    }

    #[test]
    fn sunshine_domain_switching_large() {
        let msg1 = {
            let mut tmp = [u64::MAX; 32];
            tmp[0] = 1;
            tmp
        };
        let msg2 = {
            let mut tmp = [u64::MAX; 32];
            tmp[31] = 1;
            tmp
        };
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        set_server_key(keyset.public_keys.server_key);
        for message in [msg1, msg2] {
            let message = U2048::from(message);
            let small_ct = FheUint2048::encrypt(message, &keyset.client_key);
            let large_ct = small_ct.squash_noise().unwrap();

            let res_large: U2048 = large_ct.decrypt(&keyset.client_key);
            let res_small: U2048 = small_ct.decrypt(&keyset.client_key);

            assert_eq!(message, res_small);
            assert_eq!(message, res_large);
        }
    }

    #[test]
    fn sunshine_enc_dec() {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        set_server_key(keys.public_keys.server_key);
        let mut compact_list_builder = CompactCiphertextList::builder(&keys.public_keys.public_key);
        for msg in 0_u8..8 {
            compact_list_builder.push(msg);
        }
        let compact_list = compact_list_builder.build();
        let expanded_list = compact_list.expand().unwrap();
        for index in 0..8 {
            let small_ct: FheUint8 = expanded_list.get(index).unwrap().unwrap();
            let small_res: u8 = small_ct.decrypt(&keys.client_key);
            assert_eq!(index as u8, small_res);

            let large_ct = small_ct.squash_noise().unwrap();
            let large_res = large_ct.decrypt(&keys.client_key);
            assert_eq!(index as u128, large_res);
        }
    }

    /// Tests the fixing of this bug https://github.com/zama-ai/distributed-decryption/issues/181
    /// which could result in decrypting 2^message_bits when a message 0 was encrypted and randomness
    /// in the encryption ends up being negative
    #[test]
    fn negative_wrapping() {
        if let DKGParams::WithSnS(params) = PARAMS_TEST_BK_SNS {
            let ciphertext_parameters = params.regular_params.ciphertext_parameters;
            let delta_half = 1
                << ((u128::BITS as u128 - 1_u128)
                    - ciphertext_parameters.total_block_bits() as u128);
            // Should be rounded to 0, since it is the negative part of the numbers that should round to 0
            let msg = u128::MAX - delta_half + 1;
            let res = from_expanded_msg(msg, ciphertext_parameters.total_block_bits() as usize);
            assert_eq!(0, res.0);

            // Check that this is where the old code failed
            let res = old_from_expanded_msg(msg, ciphertext_parameters.total_block_bits() as usize);
            assert_ne!(0, res.0);

            // Should not be 0, but instead the maximal message allowed
            let msg = u128::MAX - delta_half - 1;
            let res = from_expanded_msg(msg, ciphertext_parameters.total_block_bits() as usize);
            assert_eq!((1 << ciphertext_parameters.total_block_bits()) - 1, res.0);
        } else {
            panic!("Wrong type of parameters, expected one with SnS")
        }
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
