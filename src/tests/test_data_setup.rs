#[cfg(test)]
pub mod tests {
    use std::fs;

    use ctor::ctor;
    use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    use tfhe::shortint::{
        prelude::{
            DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
            PolynomialSize, StandardDev,
        },
        MessageModulus,
    };

    use crate::file_handling::{read_element, write_element};
    use crate::lwe::{KeySet, ThresholdLWEParameters};
    use crate::{
        file_handling::write_as_json, lwe::CiphertextParameters,
        tests::helper::tests::generate_keys,
    };

    pub const TEST_PARAM_PATH: &str = "temp/test_params.json";
    pub const TEST_KEY_PATH: &str = "temp/keys1.bin";
    pub const DEFAULT_KEY_PATH: &str = "temp/fullkeys.bin";
    pub const DEFAULT_PARAM_PATH: &str = "temp/default_params.json";
    pub const TEST_MESSAGE: u8 = 1;
    pub const DEFAULT_SEED: u64 = 1;

    // Very small parameters with very little noise, used in most tests to increase speed
    const TEST_PARAMETERS: ThresholdLWEParameters = ThresholdLWEParameters {
        input_cipher_parameters: TEST_INPUT_PARAMS,
        output_cipher_parameters: TEST_OUTPUT_PARAMS,
    };

    // TEST INPUT parameters
    const TEST_INPUT_PARAMS: CiphertextParameters<u64> = CiphertextParameters {
        lwe_dimension: LweDimension(32),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(64),
        lwe_modular_std_dev: StandardDev(1.0e-37),
        glwe_modular_std_dev: StandardDev(1.0e-37),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(8),
        ks_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        message_modulus_log: MessageModulus(4),
        usable_message_modulus_log: MessageModulus(2),
    };

    // TEST OUTPUT decryption
    const TEST_OUTPUT_PARAMS: CiphertextParameters<u128> = CiphertextParameters {
        lwe_dimension: LweDimension(96),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(128),
        lwe_modular_std_dev: StandardDev(1.0e-37),
        glwe_modular_std_dev: StandardDev(1.0e-37),
        pbs_base_log: DecompositionBaseLog(33),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(30),
        ks_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        message_modulus_log: MessageModulus(4),
        usable_message_modulus_log: MessageModulus(2),
    };

    // DEFAULT INPUT parameters
    const PARAM_CGGI_4_BITS_COMPACT_PKE_PBS_KS_INPUT: CiphertextParameters<u64> =
        CiphertextParameters {
            lwe_dimension: LweDimension(1024),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(2048),
            lwe_modular_std_dev: StandardDev(4.99029381172945e-8),
            glwe_modular_std_dev: StandardDev(3.15283466779972e-16),
            pbs_base_log: DecompositionBaseLog(21),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(8),
            ks_level: DecompositionLevelCount(4),
            ciphertext_modulus: CiphertextModulus::new_native(),
            message_modulus_log: MessageModulus(4),
            usable_message_modulus_log: MessageModulus(2),
        };

    // DEFAULT OUTPUT decryption
    const PARAM_4_BITS_CGGI_COMPACT_PKE_PBS_KS: CiphertextParameters<u128> = CiphertextParameters {
        lwe_dimension: LweDimension(3524),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(4.78655158300599e-28),
        glwe_modular_std_dev: StandardDev(1.25858184417075e-32),
        pbs_base_log: DecompositionBaseLog(33),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(30),
        ks_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        message_modulus_log: MessageModulus(4),
        usable_message_modulus_log: MessageModulus(2),
    };

    // TODO based on https://github.com/zama-ai/tfhe-rs-internal/blob/noise_gap_exp/tfhe/benches/core_crypto/noise_gap_pbs-ks.rs PARAM_CGGI_BOOLEAN_COMPACT_PKE_PBS_KS_INPUT found in noise_gap.rs in noise_gap_exp
    // Otherwise the bootstrapping will fail due to constraints on lwe_dimension, glwe_dimens and polynomial_size. See  https://github.com/zama-ai/tfhe-rs-internal/blob/cf7a16e137f68d21ea51aef5de6503586[…]2b9e4/tfhe/src/core_crypto/algorithms/glwe_sample_extraction.rs
    // TODO MULTIPLE PEOPLE SHOULD VALIDATE THAT THESE ARE INDEED THE PARAMETERS WE SHOULD RUN WITH!!!
    const DEFAULT_PARAMETERS: ThresholdLWEParameters = ThresholdLWEParameters {
        input_cipher_parameters: PARAM_CGGI_4_BITS_COMPACT_PKE_PBS_KS_INPUT,
        output_cipher_parameters: PARAM_4_BITS_CGGI_COMPACT_PKE_PBS_KS,
    };

    #[ctor]
    #[test]
    fn create_temp_dir() {
        // Ensure temp dir exists
        let _ = fs::create_dir("temp");
    }

    #[ctor]
    #[test]
    fn create_parameters_dir() {
        // Ensure parameters dir exists
        let _ = fs::create_dir("parameters");
    }

    #[ctor]
    #[test]
    fn ensure_test_keys_exist() {
        ensure_keys_exist(DEFAULT_KEY_PATH, DEFAULT_PARAMETERS);
    }

    #[ctor]
    #[test]
    fn ensure_full_keys_exist() {
        ensure_keys_exist(TEST_KEY_PATH, TEST_PARAMETERS);
    }

    fn ensure_keys_exist(path: &str, params: ThresholdLWEParameters) {
        match read_element::<KeySet>(path.to_string()) {
            Ok(_key_bytes) => (),
            Err(_e) => {
                let keys = generate_keys(params);
                write_element(path.to_string(), &keys).unwrap();
            }
        }
    }

    #[ctor]
    #[test]
    fn ensure_test_params_exist() {
        write_as_json(TEST_PARAM_PATH.to_string(), &TEST_PARAMETERS).unwrap();
    }

    #[ctor]
    #[test]
    fn ensure_default_params_exist() {
        write_as_json(DEFAULT_PARAM_PATH.to_string(), &DEFAULT_PARAMETERS).unwrap();
    }
}
