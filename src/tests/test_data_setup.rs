#[cfg(test)]
pub mod tests {
    use crate::execution::constants::{
        PARAMS_DIR, REAL_KEY_PATH, REAL_PARAM_PATH, SMALL_TEST_KEY_PATH, SMALL_TEST_PARAM_PATH,
        TEMP_DIR, TEMP_DKG_DIR,
    };
    use crate::execution::tfhe_internals::parameters::{
        NoiseFloodParameters, SwitchAndSquashParameters,
    };
    use crate::execution::tfhe_internals::test_feature::KeySet;
    use crate::file_handling::{read_element, write_element};
    use crate::{file_handling::write_as_json, tests::helper::tests::generate_keys};
    use ctor::ctor;
    use std::fs;
    use tfhe::core_crypto::commons::math::random::TUniform;
    use tfhe::integer::parameters::DynamicDistribution;
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::shortint::{
        prelude::{
            DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
            PolynomialSize,
        },
        CarryModulus, MessageModulus,
    };
    use tfhe::{
        core_crypto::commons::ciphertext_modulus::CiphertextModulus, shortint::EncryptionKeyChoice,
    };

    pub const DEFAULT_SEED: u64 = 1;

    // Very small parameters with very little noise, used in most tests to increase speed
    pub const TEST_PARAMETERS: NoiseFloodParameters = NoiseFloodParameters {
        ciphertext_parameters: TEST_INPUT_PARAMS_SMALL,
        sns_parameters: TEST_SNS_PARAMS_SMALL,
    };

    // TEST INPUT parameters
    pub const TEST_INPUT_PARAMS_SMALL: ClassicPBSParameters = ClassicPBSParameters {
        lwe_dimension: LweDimension(32),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(64),
        lwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(1)),
        glwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(1)),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(8),
        ks_level: DecompositionLevelCount(4),
        ciphertext_modulus: CiphertextModulus::<u64>::new_native(),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };

    // TEST OUTPUT decryption
    const TEST_SNS_PARAMS_SMALL: SwitchAndSquashParameters = SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(2),
        glwe_noise_distribution: TUniform::new(1),
        polynomial_size: PolynomialSize(256),
        pbs_base_log: DecompositionBaseLog(33),
        pbs_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    };

    // DEFAULT INPUT parameters, TAKING NIST P=32 AS REFERENCE (March 7th 2024)
    const PARAM_CGGI_4_BITS_COMPACT_PKE_PBS_KS_INPUT: ClassicPBSParameters = ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(41)),
        glwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(14)),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::new_native(),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };

    //TAKING NIST P=32 AS REFERENCE (March 7th 2024)
    // DEFAULT OUTPUT decryption
    const PARAM_4_BITS_CGGI_COMPACT_PKE_PBS_KS_SNS: SwitchAndSquashParameters =
        SwitchAndSquashParameters {
            glwe_dimension: GlweDimension(2),
            glwe_noise_distribution: TUniform::new(24),
            polynomial_size: PolynomialSize(2048),
            pbs_base_log: DecompositionBaseLog(24),
            pbs_level: DecompositionLevelCount(3),
            ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        };

    //TAKING NIST P=32 AS REFERENCE (March 7th 2024)
    // TODO MULTIPLE PEOPLE SHOULD VALIDATE THAT THESE ARE INDEED THE PARAMETERS WE SHOULD RUN WITH!!!
    const REAL_PARAMETERS: NoiseFloodParameters = NoiseFloodParameters {
        ciphertext_parameters: PARAM_CGGI_4_BITS_COMPACT_PKE_PBS_KS_INPUT,
        sns_parameters: PARAM_4_BITS_CGGI_COMPACT_PKE_PBS_KS_SNS,
    };

    #[ctor]
    #[test]
    fn create_temp_dir() {
        // Ensure temp dir exists to store generated keys
        let _ = fs::create_dir(TEMP_DIR);
    }

    #[ctor]
    #[test]
    fn create_temp_dkg_dir() {
        // Ensure temp/dkg dir exists
        let _ = fs::create_dir(TEMP_DKG_DIR);
    }

    #[ctor]
    #[test]
    fn create_parameters_dir() {
        // Ensure parameters dir exists to store generated parameters json files
        let _ = fs::create_dir(PARAMS_DIR);
    }

    #[ctor]
    #[test]
    fn ensure_default_keys_exist() {
        ensure_keys_exist(REAL_KEY_PATH, REAL_PARAMETERS);
    }

    #[ctor]
    #[test]
    fn ensure_small_test_keys_exist() {
        ensure_keys_exist(SMALL_TEST_KEY_PATH, TEST_PARAMETERS);
    }

    fn ensure_keys_exist(path: &str, params: NoiseFloodParameters) {
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
    fn ensure_small_test_params_exist() {
        write_as_json(SMALL_TEST_PARAM_PATH.to_string(), &TEST_PARAMETERS).unwrap();
    }

    #[ctor]
    #[test]
    fn ensure_default_params_exist() {
        write_as_json(REAL_PARAM_PATH.to_string(), &REAL_PARAMETERS).unwrap();
    }
}
