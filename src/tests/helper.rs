#[cfg(test)]
pub mod tests {
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use crate::{
        file_handling::read_element,
        lwe::{gen_key_set, Ciphertext64, KeySet, ThresholdLWEParameters},
        tests::test_data_setup::tests::{DEFAULT_SEED, TEST_KEY_PATH},
    };

    // Deterministic key generation
    pub fn generate_keys(params: ThresholdLWEParameters) -> KeySet {
        let mut seeded_rng = AesRng::seed_from_u64(DEFAULT_SEED);
        gen_key_set(params, &mut seeded_rng)
    }

    // Deterministic cipher generation
    pub fn generate_cipher(_key_name: &str, message: u8) -> Ciphertext64 {
        let keys: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let mod_log = keys
            .pk
            .threshold_lwe_parameters
            .input_cipher_parameters
            .usable_message_modulus_log
            .0;
        if message >= 1 << mod_log {
            panic!("Message cannot be handled in a single block with current parameters!");
        }
        let mut seeded_rng = AesRng::seed_from_u64(444);
        keys.pk
            .encrypt_w_bitlimit(&mut seeded_rng, message, mod_log)
    }
}
