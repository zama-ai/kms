//! All these come from Nigel's script in NIST M1 document for pfail 2^-128.
//! The script is available here https://github.com/zama-ai/NIST-Threshold/blob/main/CPP-Progs/TFHE-Params/main.cpp
//! and outputs a TFHE-rs-params.txt file which is copied here.

use tfhe::{
    boolean::prelude::*,
    core_crypto::commons::ciphertext_modulus::CiphertextModulus,
    shortint::{
        parameters::{
            noise_squashing::NoiseSquashingClassicParameters, CompactCiphertextListExpansionKind,
            CompactPublicKeyEncryptionParameters, NoiseSquashingParameters,
            ShortintKeySwitchingParameters, SupportedCompactPkeZkScheme,
        },
        prelude::*,
    },
};

// Main Document Parameters
// Parameters When Main Ciphertexts are LWE

// p-fail = 2^-128
pub const NIST_PARAM_1_CARRY_1_COMPACT_PK_PBS_KS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(848),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(16),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
};

// Parameters to keyswitch from input PKE 1_1 TUniform parameters to 1_1 PBS_KS compute parameters
// arriving under the destination key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    destination_key: EncryptionKeyChoice::Small,
};

// Parameters for SwitchSquash
pub const NIST_PARAMS_NOISE_SQUASHING_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(4),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
    polynomial_size: PolynomialSize(1024),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
});

// **********************************

// p-fail = 2^-128
pub const NIST_PARAM_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1004),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
};

// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 PBS_KS compute parameters
// arriving under the destination key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    destination_key: EncryptionKeyChoice::Small,
};

// Parameters for SwitchSquash
pub const NIST_PARAMS_NOISE_SQUASHING_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(2),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
    polynomial_size: PolynomialSize(2048),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
});

// **********************************

// Parameters When Main Ciphertexts are FGLWE

// p-fail = 2^-128
pub const NIST_PARAM_1_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(729),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(49),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(16),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
};

// Parameters to keyswitch from input PKE 1_1 TUniform parameters to 1_1 KS_PBS compute parameters
// arriving under the destination key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(18),
    destination_key: EncryptionKeyChoice::Big,
};

// Parameters for SwitchSquash
pub const NIST_PARAMS_NOISE_SQUASHING_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(4),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
    polynomial_size: PolynomialSize(1024),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
});

// **********************************

// p-fail = 2^-128
pub const NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(886),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
};

// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
// arriving under the destination key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(19),
    destination_key: EncryptionKeyChoice::Big,
};

// Parameters for SwitchSquash
pub const NIST_PARAMS_NOISE_SQUASHING_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(2),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
    polynomial_size: PolynomialSize(2048),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
});
