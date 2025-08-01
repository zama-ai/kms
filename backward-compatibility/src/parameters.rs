//! These struct re-defines kms-core and tfhe-rs parameter sets in order to be independent
//! of changes made into kms-core and tfhe-rs. The idea here is to define types that are able
//! to carry the information of the used parameters without using any kms-core or tfhe-rs types.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DKGParamsSnSTest {
    pub regular_params: DKGParamsRegularTest,
    pub sns_params: SwitchAndSquashParametersTest,
    pub sns_compression_parameters: SwitchAndSquashCompressionParametersTest,
}

// Parameters `dedicated_compact_public_key_parameters` and `compression_decompression_parameters`
// are not included because they are optional tfhe-rs types, which means their backward compatibility
// is already tested.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DKGParamsRegularTest {
    pub sec: u64,
    pub ciphertext_parameters: ClassicPBSParametersTest,
    pub flag: bool,
}

// Parameter `ciphertext_modulus` is not included as it is initialized without any value
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClassicPBSParametersTest {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_gaussian: u32,
    pub glwe_noise_gaussian: u32,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: u64,
    pub carry_modulus: u64,
    pub max_noise_level: u64,
    pub log2_p_fail: f64,
    pub encryption_key_choice: Cow<'static, str>,
}

// Parameter `ciphertext_modulus` is not included as it is initialized without any value
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SwitchAndSquashParametersTest {
    pub glwe_dimension: usize,
    pub glwe_noise_distribution: u32,
    pub polynomial_size: usize,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub message_modulus: u64,
    pub carry_modulus: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SwitchAndSquashCompressionParametersTest {
    pub packing_ks_level: usize,
    pub packing_ks_base_log: usize,
    pub packing_ks_polynomial_size: usize,
    pub packing_ks_glwe_dimension: usize,
    pub lwe_per_glwe: usize,
    pub packing_ks_key_noise_distribution: u32,
    pub message_modulus: u64,
    pub carry_modulus: u64,
}
