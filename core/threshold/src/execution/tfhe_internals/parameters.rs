use std::{
    hash::{Hash, Hasher},
    path::PathBuf,
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use statrs::distribution::{Binomial, DiscreteCDF};
use tfhe::{
    core_crypto::commons::ciphertext_modulus::CiphertextModulus,
    integer::parameters::DynamicDistribution,
    shortint::{
        parameters::{
            noise_squashing::NoiseSquashingClassicParameters, CompactCiphertextListExpansionKind,
            CompactPublicKeyEncryptionParameters, CompressionParameters, DecompositionBaseLog,
            DecompositionLevelCount, GlweDimension, LweCiphertextCount, LweDimension,
            ModulusSwitchNoiseReductionParams, NoiseEstimationMeasureBound,
            NoiseSquashingCompressionParameters, NoiseSquashingParameters, PolynomialSize,
            RSigmaFactor, ShortintKeySwitchingParameters, SupportedCompactPkeZkScheme, Variance,
        },
        prelude::ModulusSwitchType,
        CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
        PBSOrder, PBSParameters,
    },
};

use crate::execution::keyset_config::KeySetConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionType {
    Bits64,
    Bits128,
}

impl EncryptionType {
    pub fn bit_len(&self) -> usize {
        match self {
            EncryptionType::Bits64 => 64,
            EncryptionType::Bits128 => 128,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct TUniformBound(pub usize);

#[derive(Debug, Clone, Copy, strum_macros::EnumIter, PartialEq, Eq)]
pub enum NoiseBounds {
    LweNoise(TUniformBound),
    LweHatNoise(TUniformBound),
    GlweNoise(TUniformBound),
    GlweNoiseSnS(TUniformBound),
    CompressionKSKNoise(TUniformBound),
    SnsCompressionKSKNoise(TUniformBound),
}

impl NoiseBounds {
    pub fn get_bound(&self) -> TUniformBound {
        match self {
            NoiseBounds::LweNoise(bound) => *bound,
            NoiseBounds::LweHatNoise(bound) => *bound,
            NoiseBounds::GlweNoise(bound) => *bound,
            NoiseBounds::GlweNoiseSnS(bound) => *bound,
            NoiseBounds::CompressionKSKNoise(bound) => *bound,
            NoiseBounds::SnsCompressionKSKNoise(bound) => *bound,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KSKParams {
    pub num_needed_noise: usize,
    pub noise_bound: NoiseBounds,
    pub decomposition_base_log: DecompositionBaseLog,
    pub decomposition_level_count: DecompositionLevelCount,
}

#[derive(Debug)]
pub struct BKParams {
    pub num_needed_noise: usize,
    pub noise_bound: NoiseBounds,
    pub decomposition_base_log: DecompositionBaseLog,
    pub decomposition_level_count: DecompositionLevelCount,
    pub enc_type: EncryptionType,
}

/// Modulus switch noise reduction key parameters
#[derive(Debug)]
pub struct MSNRKParams {
    pub num_needed_noise: usize,
    pub noise_bound: NoiseBounds,
    pub params: ModulusSwitchNoiseReductionParams,
}

#[derive(Debug)]
pub enum MSNRKConfiguration {
    Standard,
    DriftTechniqueNoiseReduction(MSNRKParams),
    CenteredMeanNoiseReduction,
}

#[derive(Debug)]
pub struct DistributedCompressionParameters {
    pub raw_compression_parameters: CompressionParameters,
    pub ksk_num_noise: usize,
    pub ksk_noisebound: NoiseBounds,
    pub bk_params: BKParams,
    pub pmax: Option<f64>,
}

#[derive(Debug)]
pub struct DistributedSnsCompressionParameters {
    pub raw_compression_parameters: NoiseSquashingCompressionParameters,
    pub ksk_num_noise: usize,
    pub ksk_noisebound: NoiseBounds,
    pub pmax: Option<f64>,
}

pub trait AugmentedCiphertextParameters {
    // Return the minimum amount of bits that can be used for a message in each block.
    fn message_modulus_log(&self) -> u32;

    // Return the minimum amount of bits that can be used for a carry in each block.
    fn carry_modulus_log(&self) -> u32;
    // Return the minimum total amounts of availble bits in each block. I.e. including both message and carry bits
    fn total_block_bits(&self) -> u32;
}

impl AugmentedCiphertextParameters for tfhe::shortint::Ciphertext {
    // Return the minimum amount of bits that can be used for a message in each block.
    fn message_modulus_log(&self) -> u32 {
        self.message_modulus.0.ilog2()
    }

    // Return the minimum amount of bits that can be used for a carry in each block.
    fn carry_modulus_log(&self) -> u32 {
        self.carry_modulus.0.ilog2()
    }

    // Return the minimum total amounts of availble bits in each block. I.e. including both message and carry bits
    fn total_block_bits(&self) -> u32 {
        self.carry_modulus_log() + self.message_modulus_log()
    }
}

impl AugmentedCiphertextParameters for ClassicPBSParameters {
    // Return the minimum amount of bits that can be used for a message in each block.
    fn message_modulus_log(&self) -> u32 {
        self.message_modulus.0.ilog2()
    }

    // Return the minimum amount of bits that can be used for a carry in each block.
    fn carry_modulus_log(&self) -> u32 {
        self.carry_modulus.0.ilog2()
    }

    // Return the minimum total amounts of availble bits in each block. I.e. including both message and carry bits
    fn total_block_bits(&self) -> u32 {
        self.carry_modulus_log() + self.message_modulus_log()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub enum DKGParams {
    WithoutSnS(DKGParamsRegular),
    WithSnS(DKGParamsSnS),
    // NOTE: do NOT modify the types above, as this would break serialization compatibility
}

impl From<DKGParams> for PBSParameters {
    fn from(val: DKGParams) -> Self {
        PBSParameters::PBS(val.get_params_basics_handle().to_classic_pbs_parameters())
    }
}

impl TryFrom<DKGParams> for DKGParamsSnS {
    type Error = anyhow::Error;

    fn try_from(value: DKGParams) -> Result<Self, Self::Error> {
        match value {
            DKGParams::WithSnS(params) => Ok(params),
            DKGParams::WithoutSnS(_) => Err(anyhow::anyhow!("Cannot convert to SnS params")),
        }
    }
}

impl TryFrom<DKGParams> for DKGParamsRegular {
    type Error = anyhow::Error;

    fn try_from(value: DKGParams) -> Result<Self, Self::Error> {
        match value {
            DKGParams::WithSnS(_) => Err(anyhow::anyhow!("Cannot convert to SnS params")),
            DKGParams::WithoutSnS(params) => Ok(params),
        }
    }
}

impl DKGParams {
    pub fn get_params_basics_handle(&self) -> &dyn DKGParamsBasics {
        match self {
            Self::WithSnS(params) => params,
            Self::WithoutSnS(params) => params,
        }
    }

    pub fn kind_to_str(&self) -> &str {
        match self {
            Self::WithSnS(_) => "SNS",
            Self::WithoutSnS(_) => "Regular",
        }
    }

    pub fn get_params_without_sns(&self) -> DKGParams {
        match self {
            Self::WithSnS(params) => DKGParams::WithoutSnS(params.regular_params),
            Self::WithoutSnS(_) => *self,
        }
    }

    pub fn to_tfhe_config(&self) -> tfhe::Config {
        let pbs_params: ClassicPBSParameters =
            self.get_params_basics_handle().to_classic_pbs_parameters();
        let compression_params = self
            .get_params_basics_handle()
            .get_compression_decompression_params();
        let noise_squashing_params = match self {
            DKGParams::WithoutSnS(_) => None,
            DKGParams::WithSnS(dkg_sns) => {
                Some((dkg_sns.sns_params, dkg_sns.sns_compression_params))
            }
        };
        let config = tfhe::ConfigBuilder::with_custom_parameters(pbs_params);
        let config = if let Some(dedicated_pk_params) =
            self.get_params_basics_handle().get_dedicated_pk_params()
        {
            config.use_dedicated_compact_public_key_parameters(dedicated_pk_params)
        } else {
            config
        };
        let config = if let Some(params) = compression_params {
            config.enable_compression(params.raw_compression_parameters)
        } else {
            config
        };
        let config = if let Some((sns_params, sns_compression_params)) = noise_squashing_params {
            let config = config.enable_noise_squashing(sns_params);
            match sns_compression_params {
                None => config,
                Some(sns_compression_params) => {
                    config.enable_noise_squashing_compression(sns_compression_params)
                }
            }
        } else {
            config
        };
        let config =
            if let Some(rerand_params) = self.get_params_basics_handle().get_rerand_params() {
                config.enable_ciphertext_re_randomization(rerand_params)
            } else {
                config
            };
        config.build()
    }
}

/// Tells us whether the DKG should be run in Z64 or Z128
/// this is checked against the size of the underlying ring
/// when calling DKG; and used to infer the domain of the keys
/// in resharing.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub enum DkgMode {
    Z64,
    Z128,
}

impl DkgMode {
    pub fn expected_bit_length(&self) -> usize {
        match self {
            DkgMode::Z64 => 64,
            DkgMode::Z128 => 128,
        }
    }
}

/// Parameters to specify the acceptable range for the hamming weight
/// of the secret keys generated by the DKG protocol.
/// Same parameters are used for all secret keys inside a keyset.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct SecretKeyDeviations {
    /// Log2 of the acceptable failure probability
    /// Plays on how many extra bits we sample to be confident that we can indeed
    /// sample our keys within the desired HW range
    pub log2_failure_proba: i64,
    /// The HW of all keys must be in [floor((1-pmax) * len) ,(pmax)*len]
    /// (Thus 0.5 < pmax < 1.0 )
    pub pmax: f64,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct DKGParamsRegular {
    /// __NOTE__: For regular params we can have Z64 or Z128,
    /// but for SnS params we can only have Z128 so this is ignored
    pub dkg_mode: DkgMode,
    ///Security parameter (related to the size of the XOF seed)
    pub sec: u64,
    pub ciphertext_parameters: ClassicPBSParameters,
    //NOTE: This should probably not be optional anymore once the whole kms codebase
    //has transitioned over to tfhe-rs.v0.8
    pub dedicated_compact_public_key_parameters: Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )>,
    pub compression_decompression_parameters: Option<CompressionParameters>,
    pub secret_key_deviations: Option<SecretKeyDeviations>,
    pub cpk_re_randomization_ksk_params: Option<ShortintKeySwitchingParameters>,
}

impl From<DKGParamsRegular> for PBSParameters {
    fn from(val: DKGParamsRegular) -> Self {
        PBSParameters::PBS(val.ciphertext_parameters)
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub struct DKGParamsSnS {
    pub regular_params: DKGParamsRegular,
    pub sns_params: NoiseSquashingParameters,
    pub sns_compression_params: Option<NoiseSquashingCompressionParameters>,
}

#[derive(Debug, Clone, Copy)]
pub struct NoiseInfo {
    pub amount: usize,
    pub bound: NoiseBounds,
}

impl NoiseInfo {
    pub fn tuniform_bound(&self) -> TUniformBound {
        self.bound.get_bound()
    }

    pub fn num_bits_needed(&self) -> usize {
        self.amount * (self.tuniform_bound().0 + 2)
    }
}

pub trait DKGParamsBasics: Sync {
    fn get_dkg_mode(&self) -> DkgMode;
    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters;

    ///This function returns a path based on
    /// - [DKGParams::message_modulus]
    /// - [DKGParams::carry_modulus]
    /// - whether SnS is allowed or not
    ///
    ///__Thus any two sets of parameters that share these characteristics
    ///will have the same prefix path, which may result in a clash.__
    fn get_prefix_path(&self) -> PathBuf;
    fn get_sec(&self) -> u64;
    fn get_message_modulus(&self) -> MessageModulus;
    fn get_carry_modulus(&self) -> CarryModulus;
    fn total_bits_required(&self, keyset_config: KeySetConfig) -> usize;
    fn total_triples_required(&self, keyset_config: KeySetConfig) -> usize;
    fn total_randomness_required(&self, keyset_config: KeySetConfig) -> usize;
    fn lwe_dimension(&self) -> LweDimension;
    fn lwe_hat_dimension(&self) -> LweDimension;
    fn glwe_dimension(&self) -> GlweDimension;
    fn lwe_tuniform_bound(&self) -> TUniformBound;
    fn lwe_hat_tuniform_bound(&self) -> TUniformBound;
    fn glwe_tuniform_bound(&self) -> TUniformBound;
    fn compression_key_tuniform_bound(&self) -> Option<TUniformBound>;
    fn polynomial_size(&self) -> PolynomialSize;
    fn lwe_sk_num_bits_to_sample(&self) -> usize;
    fn lwe_hat_sk_num_bits_to_sample(&self) -> usize;
    fn glwe_sk_num_bits_to_sample(&self) -> usize;
    fn compression_sk_num_bits_to_sample(&self) -> usize;
    fn glwe_sk_num_bits(&self) -> usize;
    fn compression_sk_num_bits(&self) -> usize;
    fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog;
    fn decomposition_base_log_pksk(&self) -> DecompositionBaseLog;
    fn decomposition_base_log_rerand_ksk(&self) -> DecompositionBaseLog;
    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog;
    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount;
    fn decomposition_level_count_pksk(&self) -> DecompositionLevelCount;
    fn decomposition_level_count_rerand_ksk(&self) -> DecompositionLevelCount;
    fn decomposition_level_count_bk(&self) -> DecompositionLevelCount;

    // `num_needed_noise_` functions do not consider take KeySetConfig into consideration
    fn num_needed_noise_pk(&self) -> NoiseInfo;
    fn num_needed_noise_ksk(&self) -> NoiseInfo;
    fn num_needed_noise_pksk(&self) -> NoiseInfo;
    fn num_needed_noise_bk(&self) -> NoiseInfo;
    fn num_needed_noise_compression_key(&self) -> NoiseInfo;
    fn num_needed_noise_decompression_key(&self) -> NoiseInfo;
    fn num_needed_noise_rerand_ksk(&self) -> NoiseInfo;
    // msnrk: modulus switch noise reduction key
    fn num_needed_noise_msnrk(&self) -> NoiseInfo;

    fn num_raw_bits(&self, keyset_config: KeySetConfig) -> usize;
    fn encryption_key_choice(&self) -> EncryptionKeyChoice;
    fn pbs_order(&self) -> PBSOrder;
    fn to_dkg_params(&self) -> DKGParams;
    fn get_dedicated_pk_params(
        &self,
    ) -> Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )>;
    fn get_compact_pk_enc_params(&self) -> CompactPublicKeyEncryptionParameters;
    fn get_pksk_destination(&self) -> Option<EncryptionKeyChoice>;
    fn has_dedicated_compact_pk_params(&self) -> bool;
    fn get_ksk_params(&self) -> KSKParams;
    fn get_pksk_params(&self) -> Option<KSKParams>;
    fn get_rerand_ksk_params(&self) -> Option<KSKParams>;
    fn get_bk_params(&self) -> BKParams;
    // msnrk: modulus switch noise reduction key
    fn get_msnrk_configuration(&self) -> MSNRKConfiguration;
    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters>;
    fn get_sns_compression_params(&self) -> Option<DistributedSnsCompressionParameters>;
    fn get_rerand_params(&self) -> Option<ShortintKeySwitchingParameters>;

    fn all_lwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    fn all_lwe_hat_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    fn all_glwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    fn all_compression_ksk_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    // This is the difference between the output bitsize and the input bitsize of the pksk
    fn pksk_rshift(&self) -> i8;
    fn get_sk_deviations(&self) -> Option<SecretKeyDeviations>;

    fn get_pmax(&self) -> Option<f64> {
        self.get_sk_deviations().map(|dev| dev.pmax)
    }
}

fn combine_noise_info(target_bound: NoiseBounds, list: &[NoiseInfo]) -> NoiseInfo {
    let mut total = 0;
    for noise_info in list {
        match (noise_info.bound, target_bound) {
            (NoiseBounds::LweNoise(_left), NoiseBounds::LweNoise(_right)) => {
                total += noise_info.amount;
                #[cfg(test)]
                assert_eq!(_left.0, _right.0);
            }
            (NoiseBounds::LweHatNoise(_left), NoiseBounds::LweHatNoise(_right)) => {
                total += noise_info.amount;
                #[cfg(test)]
                assert_eq!(_left.0, _right.0);
            }
            (NoiseBounds::GlweNoise(_left), NoiseBounds::GlweNoise(_right)) => {
                total += noise_info.amount;
                #[cfg(test)]
                assert_eq!(_left.0, _right.0);
            }
            (NoiseBounds::GlweNoiseSnS(_left), NoiseBounds::GlweNoiseSnS(_right)) => {
                total += noise_info.amount;
                #[cfg(test)]
                assert_eq!(_left.0, _right.0);
            }
            (NoiseBounds::CompressionKSKNoise(_left), NoiseBounds::CompressionKSKNoise(_right)) => {
                total += noise_info.amount;
                #[cfg(test)]
                assert_eq!(_left.0, _right.0);
            }
            _ => { /* do nothing */ }
        }
    }
    NoiseInfo {
        amount: total,
        bound: target_bound,
    }
}

impl DKGParamsBasics for DKGParamsRegular {
    fn get_dkg_mode(&self) -> DkgMode {
        self.dkg_mode
    }

    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        self.ciphertext_parameters
    }

    ///This function returns a path based on
    /// - [DKGParams::message_modulus]
    /// - [DKGParams::carry_modulus]
    /// - a hash of the whole parameter set to make it unique
    fn get_prefix_path(&self) -> PathBuf {
        let mut h = std::hash::DefaultHasher::new();
        let serialized = bc2wrap::serialize(self).unwrap();
        serialized.hash(&mut h);
        let hash = h.finish();
        PathBuf::from(format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_false_compression_{}_{}",
            self.get_message_modulus().0,
            self.get_carry_modulus().0,
            self.compression_decompression_parameters.is_some(),
            hash
        ))
    }

    fn get_sec(&self) -> u64 {
        self.sec
    }

    fn get_message_modulus(&self) -> MessageModulus {
        self.ciphertext_parameters.message_modulus
    }

    fn get_carry_modulus(&self) -> CarryModulus {
        self.ciphertext_parameters.carry_modulus
    }

    fn total_bits_required(&self, keyset_config: KeySetConfig) -> usize {
        //Need bits for the two lwe sk, glwe sk, and the compression sk
        //Counted twice if there's no dedicated pk parameter
        let mut num_bits_needed = self.num_raw_bits(keyset_config);

        match keyset_config {
            KeySetConfig::Standard(_) => {
                //And additionally, need bits to process the TUniform noises
                //(we need bound + 2 bits to sample a TUniform(bound))
                //For pk
                num_bits_needed += self.num_needed_noise_pk().num_bits_needed();

                //For ksk
                num_bits_needed += self.num_needed_noise_ksk().num_bits_needed();

                //For bk
                num_bits_needed += self.num_needed_noise_bk().num_bits_needed();

                //For pksk
                num_bits_needed += self.num_needed_noise_pksk().num_bits_needed();

                //For (de)compression keys
                //note that the bits are automatically 0
                //if compression is not supported by the parameters

                //For compression keys
                num_bits_needed += self.num_needed_noise_compression_key().num_bits_needed();

                // for msnrk
                num_bits_needed += self.num_needed_noise_msnrk().num_bits_needed();

                //For decompression keys
                num_bits_needed += self.num_needed_noise_decompression_key().num_bits_needed();

                //For ReRand keys
                num_bits_needed += self.num_needed_noise_rerand_ksk().num_bits_needed();
            }
            KeySetConfig::DecompressionOnly => {
                //For decompression keys
                num_bits_needed += self.num_needed_noise_decompression_key().num_bits_needed();
            }
        }

        num_bits_needed
    }

    fn total_triples_required(&self, keyset_config: KeySetConfig) -> usize {
        //Required for the "normal" BK
        let mut num_triples_needed = 0;

        match keyset_config {
            KeySetConfig::Standard(_) => {
                num_triples_needed += self.lwe_dimension().0 * self.glwe_sk_num_bits();

                //Required for the compression BK
                if let Some(comp_params) = self.compression_decompression_parameters {
                    num_triples_needed += self.glwe_sk_num_bits()
                        * (comp_params.packing_ks_glwe_dimension.0
                            * comp_params.packing_ks_polynomial_size.0)
                }
            }
            KeySetConfig::DecompressionOnly => {
                //Required for the compression BK
                if let Some(comp_params) = self.compression_decompression_parameters {
                    num_triples_needed += self.glwe_sk_num_bits()
                        * (comp_params.packing_ks_glwe_dimension.0
                            * comp_params.packing_ks_polynomial_size.0)
                }
            }
        }

        self.total_bits_required(keyset_config) + num_triples_needed
    }

    fn total_randomness_required(&self, keyset_config: KeySetConfig) -> usize {
        //Need 1 more element to sample the seed
        //as we always work in huge rings
        let num_randomness_needed = 1;

        self.total_bits_required(keyset_config) + num_randomness_needed
    }

    fn lwe_dimension(&self) -> LweDimension {
        self.ciphertext_parameters.lwe_dimension
    }

    fn lwe_hat_dimension(&self) -> LweDimension {
        //If there's no dedicated parameter, lwe_ha is lwe
        self.dedicated_compact_public_key_parameters
            .map_or(self.lwe_dimension(), |(p, _)| p.encryption_lwe_dimension)
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.ciphertext_parameters.glwe_dimension
    }

    fn lwe_tuniform_bound(&self) -> TUniformBound {
        match self.ciphertext_parameters.lwe_noise_distribution {
            DynamicDistribution::TUniform(noise_distribution) => {
                TUniformBound(noise_distribution.bound_log2() as usize)
            }
            _ => panic!("We only support TUniform noise distribution!"),
        }
    }

    fn lwe_hat_tuniform_bound(&self) -> TUniformBound {
        //If there's no dedicated parameter, lwe_ha is lwe
        self.dedicated_compact_public_key_parameters
            .map_or(self.lwe_tuniform_bound(), |(p, _)| {
                match p.encryption_noise_distribution {
                    DynamicDistribution::TUniform(noise_distribution) => {
                        TUniformBound(noise_distribution.bound_log2() as usize)
                    }
                    _ => panic!("We only support TUniform noise distribution!"),
                }
            })
    }

    fn glwe_tuniform_bound(&self) -> TUniformBound {
        match self.ciphertext_parameters.glwe_noise_distribution {
            DynamicDistribution::TUniform(noise_distribution) => {
                TUniformBound(noise_distribution.bound_log2() as usize)
            }
            _ => panic!("We only support TUniform noise distribution!"),
        }
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.ciphertext_parameters.polynomial_size
    }

    fn glwe_sk_num_bits(&self) -> usize {
        self.polynomial_size().0 * self.glwe_dimension().0
    }

    fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog {
        self.ciphertext_parameters.ks_base_log
    }

    fn decomposition_base_log_pksk(&self) -> DecompositionBaseLog {
        self.dedicated_compact_public_key_parameters
            .map_or(DecompositionBaseLog(0), |(_, p)| p.ks_base_log)
    }

    fn decomposition_base_log_rerand_ksk(&self) -> DecompositionBaseLog {
        self.cpk_re_randomization_ksk_params
            .map_or(DecompositionBaseLog(0), |p| p.ks_base_log)
    }

    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.ciphertext_parameters.pbs_base_log
    }

    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.ciphertext_parameters.ks_level
    }

    fn decomposition_level_count_rerand_ksk(&self) -> DecompositionLevelCount {
        self.cpk_re_randomization_ksk_params
            .map_or(DecompositionLevelCount(0), |p| p.ks_level)
    }

    fn decomposition_level_count_pksk(&self) -> DecompositionLevelCount {
        self.dedicated_compact_public_key_parameters
            .map_or(DecompositionLevelCount(0), |(_, p)| p.ks_level)
    }

    fn decomposition_level_count_bk(&self) -> DecompositionLevelCount {
        self.ciphertext_parameters.pbs_level
    }

    fn num_needed_noise_pk(&self) -> NoiseInfo {
        NoiseInfo {
            amount: self.lwe_hat_dimension().0,
            bound: NoiseBounds::LweHatNoise(self.lwe_hat_tuniform_bound()),
        }
    }

    fn num_needed_noise_pksk(&self) -> NoiseInfo {
        let amount = self.lwe_hat_dimension().0 * self.decomposition_level_count_pksk().0;

        // it doesn't matter what bound we set if the amount is 0
        let (amount, bound) = match self.get_pksk_destination() {
            Some(EncryptionKeyChoice::Big) => {
                //type = F-GLWE case
                (amount, NoiseBounds::GlweNoise(self.glwe_tuniform_bound()))
            }
            Some(EncryptionKeyChoice::Small) => {
                //type = LWE case
                (amount, NoiseBounds::LweNoise(self.lwe_tuniform_bound()))
            }
            _ => (0, NoiseBounds::LweNoise(self.lwe_tuniform_bound())),
        };
        NoiseInfo { amount, bound }
    }

    fn num_needed_noise_ksk(&self) -> NoiseInfo {
        let amount = self.glwe_dimension().0
            * self.polynomial_size().0
            * self.decomposition_level_count_ksk().0;
        let bound = NoiseBounds::LweNoise(self.lwe_tuniform_bound());
        NoiseInfo { amount, bound }
    }

    fn num_needed_noise_rerand_ksk(&self) -> NoiseInfo {
        // If there's a dedicated compact key with same parameter,
        // we won't need to generate a new rerand key.
        let amount = if self.cpk_re_randomization_ksk_params
            == self.dedicated_compact_public_key_parameters.map(|(_, p)| p)
        {
            0
        } else {
            self.lwe_hat_dimension().0 * self.decomposition_level_count_rerand_ksk().0
        };
        let bound = NoiseBounds::GlweNoise(self.glwe_tuniform_bound());
        NoiseInfo { amount, bound }
    }

    fn num_needed_noise_bk(&self) -> NoiseInfo {
        let amount = self.lwe_dimension().0
            * (self.glwe_dimension().0 + 1)
            * self.decomposition_level_count_bk().0
            * self.polynomial_size().0;
        let bound = NoiseBounds::GlweNoise(self.glwe_tuniform_bound());
        NoiseInfo { amount, bound }
    }

    fn num_needed_noise_msnrk(&self) -> NoiseInfo {
        let amount = match self
            .ciphertext_parameters
            .modulus_switch_noise_reduction_params
        {
            ModulusSwitchType::Standard => 0,
            ModulusSwitchType::DriftTechniqueNoiseReduction(
                modulus_switch_noise_reduction_params,
            ) => {
                modulus_switch_noise_reduction_params
                    .modulus_switch_zeros_count
                    .0
            }
            ModulusSwitchType::CenteredMeanNoiseReduction => 0,
        };
        let bound = NoiseBounds::LweNoise(self.lwe_tuniform_bound());
        NoiseInfo { amount, bound }
    }

    fn to_dkg_params(&self) -> DKGParams {
        DKGParams::WithoutSnS(*self)
    }

    fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        self.ciphertext_parameters.encryption_key_choice
    }

    fn pbs_order(&self) -> PBSOrder {
        PBSOrder::from(self.encryption_key_choice())
    }

    fn get_compact_pk_enc_params(&self) -> CompactPublicKeyEncryptionParameters {
        //If we are using old style keys, there's no separate CompactPublicKeyEncryptionParameters
        self.dedicated_compact_public_key_parameters.map_or_else(
            || {
                (<ClassicPBSParameters as std::convert::Into<PBSParameters>>::into(
                    self.ciphertext_parameters,
                ))
                .try_into()
                .unwrap()
            },
            |(p, _)| p,
        )
    }

    fn get_pksk_destination(&self) -> Option<EncryptionKeyChoice> {
        self.dedicated_compact_public_key_parameters
            .map(|(_, p)| p.destination_key)
    }

    fn has_dedicated_compact_pk_params(&self) -> bool {
        self.dedicated_compact_public_key_parameters.is_some()
    }

    fn get_ksk_params(&self) -> KSKParams {
        let NoiseInfo { amount, bound } = self.num_needed_noise_ksk();
        KSKParams {
            num_needed_noise: amount,
            noise_bound: bound,
            decomposition_base_log: self.decomposition_base_log_ksk(),
            decomposition_level_count: self.decomposition_level_count_ksk(),
        }
    }

    fn get_pksk_params(&self) -> Option<KSKParams> {
        let NoiseInfo { amount, bound } = self.num_needed_noise_pksk();
        self.get_pksk_destination().map(|_| KSKParams {
            num_needed_noise: amount,
            noise_bound: bound,
            decomposition_base_log: self.decomposition_base_log_pksk(),
            decomposition_level_count: self.decomposition_level_count_pksk(),
        })
    }

    fn get_rerand_ksk_params(&self) -> Option<KSKParams> {
        let NoiseInfo { amount, bound } = self.num_needed_noise_rerand_ksk();
        match (
            self.cpk_re_randomization_ksk_params,
            self.dedicated_compact_public_key_parameters,
        ) {
            (Some(cpk_re_randomization_ksk_params), Some(_)) => {
                assert!(
                    matches!(
                        cpk_re_randomization_ksk_params.destination_key,
                        EncryptionKeyChoice::Big
                    ),
                    "CompactPublicKey re-randomization can only be enabled \
                    targeting the large secret key."
                );
                Some(KSKParams {
                    num_needed_noise: amount,
                    noise_bound: bound,
                    decomposition_base_log: self.decomposition_base_log_rerand_ksk(),
                    decomposition_level_count: self.decomposition_level_count_rerand_ksk(),
                })
            }
            (_, None) => None,
            _ => panic!("Inconsistent ClientKey set-up for CompactPublicKey re-randomization."),
        }
    }

    fn get_bk_params(&self) -> BKParams {
        let NoiseInfo { amount, bound } = self.num_needed_noise_bk();
        BKParams {
            num_needed_noise: amount,
            noise_bound: bound,
            decomposition_base_log: self.decomposition_base_log_bk(),
            decomposition_level_count: self.decomposition_level_count_bk(),
            enc_type: EncryptionType::Bits64,
        }
    }

    fn get_msnrk_configuration(&self) -> MSNRKConfiguration {
        let NoiseInfo { amount, bound } = self.num_needed_noise_msnrk();
        match self
            .ciphertext_parameters
            .modulus_switch_noise_reduction_params
        {
            ModulusSwitchType::Standard => MSNRKConfiguration::Standard,
            ModulusSwitchType::DriftTechniqueNoiseReduction(
                modulus_switch_noise_reduction_params,
            ) => MSNRKConfiguration::DriftTechniqueNoiseReduction(MSNRKParams {
                num_needed_noise: amount,
                noise_bound: bound,
                params: modulus_switch_noise_reduction_params,
            }),
            ModulusSwitchType::CenteredMeanNoiseReduction => {
                MSNRKConfiguration::CenteredMeanNoiseReduction
            }
        }
    }

    fn compression_sk_num_bits(&self) -> usize {
        if let Some(comp_params) = self.compression_decompression_parameters {
            comp_params.packing_ks_glwe_dimension.0 * comp_params.packing_ks_polynomial_size.0
        } else {
            0
        }
    }

    fn num_needed_noise_compression_key(&self) -> NoiseInfo {
        // both must exist to make a valid NoiseInfo
        match (
            self.compression_decompression_parameters,
            self.compression_key_tuniform_bound(),
        ) {
            (Some(comp_params), Some(compression_key_tuniform_bound)) => {
                let amount = self.glwe_dimension().0
                    * self.polynomial_size().0
                    * comp_params.packing_ks_level.0
                    * comp_params.packing_ks_polynomial_size.0;
                NoiseInfo {
                    amount,
                    bound: NoiseBounds::CompressionKSKNoise(compression_key_tuniform_bound),
                }
            }
            _ => {
                // use a dummy bound
                NoiseInfo {
                    amount: 0,
                    bound: NoiseBounds::CompressionKSKNoise(TUniformBound::default()),
                }
            }
        }
    }

    fn num_needed_noise_decompression_key(&self) -> NoiseInfo {
        match (
            self.compression_decompression_parameters,
            self.compression_key_tuniform_bound(),
        ) {
            (Some(comp_params), Some(_compression_key_tuniform_bound)) => {
                let amount = comp_params.packing_ks_polynomial_size.0
                    * comp_params.packing_ks_glwe_dimension.0
                    * (self.glwe_dimension().0 + 1)
                    * self.polynomial_size().0
                    * comp_params.br_level.0;
                NoiseInfo {
                    amount,
                    bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
                }
            }
            _ => {
                // use a dummy bound
                NoiseInfo {
                    amount: 0,
                    bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
                }
            }
        }
    }

    fn num_raw_bits(&self, keyset_config: KeySetConfig) -> usize {
        match keyset_config {
            KeySetConfig::Standard(config) => {
                self.lwe_sk_num_bits_to_sample()
                    + self.lwe_hat_sk_num_bits_to_sample()
                    + self.glwe_sk_num_bits_to_sample()
                    + if config.is_using_existing_compression_sk() {
                        0
                    } else {
                        self.compression_sk_num_bits_to_sample()
                    }
            }
            KeySetConfig::DecompressionOnly => 0,
        }
    }

    fn all_lwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_inner_config) => {
                let target_bound = self.num_needed_noise_ksk().bound;
                let noises = &[
                    self.num_needed_noise_ksk(),
                    self.num_needed_noise_pksk(),
                    self.num_needed_noise_msnrk(),
                ];

                #[cfg(test)]
                {
                    // sanity check
                    assert!(matches!(target_bound, NoiseBounds::LweNoise(..)));
                    for noise in noises {
                        if matches!(noise.bound, NoiseBounds::LweNoise(..)) {
                            assert_eq!(noise.tuniform_bound().0, target_bound.get_bound().0);
                        }
                    }
                }
                combine_noise_info(target_bound, noises)
            }
            KeySetConfig::DecompressionOnly => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::LweNoise(self.lwe_tuniform_bound()),
            },
        }
    }

    fn all_lwe_hat_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_inner_config) => {
                let out = self.num_needed_noise_pk();
                #[cfg(test)]
                assert!(matches!(out.bound, NoiseBounds::LweHatNoise(..)));
                out
            }
            KeySetConfig::DecompressionOnly => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::LweHatNoise(self.lwe_hat_tuniform_bound()),
            },
        }
    }

    fn all_glwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        let target_bound = self.num_needed_noise_bk().bound;
        match keyset_config {
            KeySetConfig::Standard(_inner_config) => {
                let noises = &[
                    self.num_needed_noise_bk(),
                    self.num_needed_noise_pksk(),
                    self.num_needed_noise_decompression_key(),
                    self.num_needed_noise_rerand_ksk(),
                ];

                #[cfg(test)]
                {
                    assert!(matches!(target_bound, NoiseBounds::GlweNoise(..)));
                    for noise in noises {
                        if matches!(noise.bound, NoiseBounds::GlweNoise(..)) {
                            assert_eq!(noise.tuniform_bound().0, target_bound.get_bound().0);
                        }
                    }
                }
                combine_noise_info(target_bound, noises)
            }
            KeySetConfig::DecompressionOnly => {
                let noises = &[self.num_needed_noise_decompression_key()];
                combine_noise_info(target_bound, noises)
            }
        }
    }

    fn all_compression_ksk_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_inner_config) => {
                let out = self.num_needed_noise_compression_key();
                #[cfg(test)]
                {
                    if out.amount != 0 {
                        assert!(matches!(out.bound, NoiseBounds::CompressionKSKNoise(..)));
                    }
                }
                out
            }
            KeySetConfig::DecompressionOnly => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::CompressionKSKNoise(TUniformBound::default()),
            },
        }
    }

    fn compression_key_tuniform_bound(&self) -> Option<TUniformBound> {
        if let Some(comp_params) = self.compression_decompression_parameters {
            if let DynamicDistribution::TUniform(bound) =
                comp_params.packing_ks_key_noise_distribution
            {
                Some(TUniformBound(bound.bound_log2() as usize))
            } else {
                panic!("We do not support non-Tuniform noise distribution")
            }
        } else {
            None
        }
    }

    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters> {
        if let Some(comp_params) = self.compression_decompression_parameters {
            let NoiseInfo {
                amount: ksk_num_noise,
                bound: ksk_noisebound,
            } = self.num_needed_noise_compression_key();

            let NoiseInfo {
                amount: bk_num_noise,
                bound: bk_noisebound,
            } = self.num_needed_noise_decompression_key();

            let bk_params = BKParams {
                num_needed_noise: bk_num_noise,
                noise_bound: bk_noisebound,
                decomposition_base_log: comp_params.br_base_log,
                decomposition_level_count: comp_params.br_level,
                enc_type: EncryptionType::Bits64,
            };

            Some(DistributedCompressionParameters {
                raw_compression_parameters: comp_params,
                ksk_num_noise,
                ksk_noisebound,
                bk_params,
                pmax: self.get_sk_deviations().map(|d| d.pmax),
            })
        } else {
            None
        }
    }

    fn get_sns_compression_params(&self) -> Option<DistributedSnsCompressionParameters> {
        None
    }

    fn get_dedicated_pk_params(
        &self,
    ) -> Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )> {
        self.dedicated_compact_public_key_parameters
    }

    fn get_rerand_params(&self) -> Option<ShortintKeySwitchingParameters> {
        self.cpk_re_randomization_ksk_params
    }

    fn pksk_rshift(&self) -> i8 {
        let nb_bits_input = self
            .dedicated_compact_public_key_parameters
            .map(|(pk_params, _)| (pk_params.carry_modulus.0 * pk_params.carry_modulus.0).ilog2());
        let nb_bits_output = (self.get_carry_modulus().0 * self.get_carry_modulus().0).ilog2();

        nb_bits_input
            .map(|nb_bits_input| (nb_bits_output - nb_bits_input) as i8)
            .unwrap_or(0)
    }

    fn lwe_sk_num_bits_to_sample(&self) -> usize {
        let key_size = self.lwe_dimension().0;
        if let Some(deviations) = self.secret_key_deviations {
            let prob_within_range = compute_prob_hw_within_range(deviations.pmax, key_size as u64);
            let max_num_tries =
                compute_min_trials(prob_within_range, deviations.log2_failure_proba).unwrap();
            max_num_tries * key_size
        } else {
            key_size
        }
    }

    fn lwe_hat_sk_num_bits_to_sample(&self) -> usize {
        if self.has_dedicated_compact_pk_params() {
            let key_size = self.lwe_hat_dimension().0;
            if let Some(deviations) = self.secret_key_deviations {
                let prob_within_range =
                    compute_prob_hw_within_range(deviations.pmax, key_size as u64);
                let max_num_tries =
                    compute_min_trials(prob_within_range, deviations.log2_failure_proba).unwrap();
                max_num_tries * key_size
            } else {
                key_size
            }
        } else {
            0
        }
    }

    // GLWE keys should be seen as GLWE dimension keys, each of size polynomial_size
    fn glwe_sk_num_bits_to_sample(&self) -> usize {
        let key_size = self.glwe_sk_num_bits();
        if let Some(deviations) = self.secret_key_deviations {
            let individual_key_size = self.polynomial_size().0;
            let log_glwe_dim = (self.glwe_dimension().0.ilog2() + 1) as i64;
            let prob_within_range =
                compute_prob_hw_within_range(deviations.pmax, individual_key_size as u64);
            let max_num_tries_per_key = compute_min_trials(
                prob_within_range,
                deviations.log2_failure_proba - log_glwe_dim,
            )
            .unwrap();
            max_num_tries_per_key * key_size
        } else {
            key_size
        }
    }

    // GLWE keys should be seen as GLWE dimension keys, each of size polynomial_size
    fn compression_sk_num_bits_to_sample(&self) -> usize {
        let key_size = self.compression_sk_num_bits();
        if let Some(deviations) = self.secret_key_deviations {
            let (indiviual_key_size, log_glwe_dim) =
                if let Some(comp_params) = self.compression_decompression_parameters {
                    (
                        comp_params.packing_ks_polynomial_size.0,
                        (comp_params.packing_ks_glwe_dimension.0.ilog2() + 1) as i64,
                    )
                } else {
                    (0, 0)
                };
            let prob_within_range =
                compute_prob_hw_within_range(deviations.pmax, indiviual_key_size as u64);
            let max_num_tries = compute_min_trials(
                prob_within_range,
                deviations.log2_failure_proba - log_glwe_dim,
            )
            .unwrap();
            max_num_tries * key_size
        } else {
            key_size
        }
    }

    fn get_sk_deviations(&self) -> Option<SecretKeyDeviations> {
        self.secret_key_deviations
    }
}

impl DKGParamsBasics for DKGParamsSnS {
    fn get_dkg_mode(&self) -> DkgMode {
        // We can not have SnS KG in Z64
        DkgMode::Z128
    }

    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        self.regular_params.to_classic_pbs_parameters()
    }

    fn get_prefix_path(&self) -> PathBuf {
        let mut h = std::hash::DefaultHasher::new();
        let serialized = bc2wrap::serialize(self).unwrap();
        serialized.hash(&mut h);
        let hash = h.finish();
        PathBuf::from(format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_true_compression_{}_{}",
            self.get_message_modulus().0,
            self.get_carry_modulus().0,
            self.regular_params
                .compression_decompression_parameters
                .is_some(),
            hash
        ))
    }

    fn get_sec(&self) -> u64 {
        self.regular_params.get_sec()
    }

    fn get_message_modulus(&self) -> MessageModulus {
        self.regular_params.get_message_modulus()
    }

    fn get_carry_modulus(&self) -> CarryModulus {
        self.regular_params.get_carry_modulus()
    }

    fn total_bits_required(&self, keyset_config: KeySetConfig) -> usize {
        //Need the bits for regular keygen
        let mut num_bits_needed = self.regular_params.total_bits_required(keyset_config);
        match keyset_config {
            KeySetConfig::Standard(_) => {
                num_bits_needed +=
                //And for the additional glwe sk
                self.glwe_sk_num_bits_sns_to_sample() +
                //And for the noise for the bk sns
                self.all_bk_sns_noise().num_bits_needed() +
                // Number of bits of the mod switch noise reduction in the SnS key
                self.num_needed_noise_msnrk_sns().num_bits_needed() +
                // Number of bits needed for sns compression key
                self.num_needed_noise_sns_compression_key().num_bits_needed() +
                self.sns_compression_sk_num_bits_to_sample();
            }
            KeySetConfig::DecompressionOnly => {
                // do nothing since decompression is handled by regular params
            }
        }

        num_bits_needed
    }

    fn total_triples_required(&self, keyset_config: KeySetConfig) -> usize {
        let mut num_triples_needed = 0;

        match keyset_config {
            KeySetConfig::Standard(_) => {
                num_triples_needed +=
                // Raw triples necessary for the 2 BK
                self.lwe_dimension().0 * (self.glwe_sk_num_bits() + self.glwe_sk_num_bits_sns());

                // Required for the compression BK
                if let Some(comp_params) = self.regular_params.compression_decompression_parameters
                {
                    num_triples_needed += self.glwe_sk_num_bits()
                        * (comp_params.packing_ks_glwe_dimension.0
                            * comp_params.packing_ks_polynomial_size.0)
                }
            }
            KeySetConfig::DecompressionOnly => {
                // Required for the compression BK
                if let Some(comp_params) = self.regular_params.compression_decompression_parameters
                {
                    num_triples_needed += self.glwe_sk_num_bits()
                        * (comp_params.packing_ks_glwe_dimension.0
                            * comp_params.packing_ks_polynomial_size.0)
                }
            }
        }

        self.total_bits_required(keyset_config) + num_triples_needed
    }

    fn total_randomness_required(&self, keyset_config: KeySetConfig) -> usize {
        let num_randomness_needed = 1;

        self.total_bits_required(keyset_config) + num_randomness_needed
    }

    fn lwe_dimension(&self) -> LweDimension {
        self.regular_params.lwe_dimension()
    }

    fn lwe_hat_dimension(&self) -> LweDimension {
        self.regular_params.lwe_hat_dimension()
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.regular_params.glwe_dimension()
    }

    fn lwe_tuniform_bound(&self) -> TUniformBound {
        self.regular_params.lwe_tuniform_bound()
    }

    fn lwe_hat_tuniform_bound(&self) -> TUniformBound {
        self.regular_params.lwe_hat_tuniform_bound()
    }

    fn glwe_tuniform_bound(&self) -> TUniformBound {
        self.regular_params.glwe_tuniform_bound()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.regular_params.polynomial_size()
    }

    fn glwe_sk_num_bits(&self) -> usize {
        self.regular_params.glwe_sk_num_bits()
    }

    fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog {
        self.regular_params.decomposition_base_log_ksk()
    }

    fn decomposition_base_log_pksk(&self) -> DecompositionBaseLog {
        self.regular_params.decomposition_base_log_pksk()
    }

    fn decomposition_base_log_rerand_ksk(&self) -> DecompositionBaseLog {
        self.regular_params.decomposition_base_log_rerand_ksk()
    }

    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.regular_params.decomposition_base_log_bk()
    }

    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_ksk()
    }

    fn decomposition_level_count_pksk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_pksk()
    }

    fn decomposition_level_count_rerand_ksk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_rerand_ksk()
    }

    fn decomposition_level_count_bk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_bk()
    }

    fn num_needed_noise_pk(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_pk()
    }

    fn num_needed_noise_ksk(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_ksk()
    }

    fn num_needed_noise_pksk(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_pksk()
    }

    fn num_needed_noise_rerand_ksk(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_rerand_ksk()
    }

    fn num_needed_noise_bk(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_bk()
    }

    fn num_needed_noise_msnrk(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_msnrk()
    }

    fn to_dkg_params(&self) -> DKGParams {
        DKGParams::WithSnS(*self)
    }

    fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        self.regular_params.encryption_key_choice()
    }

    fn pbs_order(&self) -> PBSOrder {
        self.regular_params.pbs_order()
    }

    fn get_compact_pk_enc_params(&self) -> CompactPublicKeyEncryptionParameters {
        self.regular_params.get_compact_pk_enc_params()
    }

    fn get_pksk_destination(&self) -> Option<EncryptionKeyChoice> {
        self.regular_params.get_pksk_destination()
    }

    fn has_dedicated_compact_pk_params(&self) -> bool {
        self.regular_params.has_dedicated_compact_pk_params()
    }

    fn get_ksk_params(&self) -> KSKParams {
        self.regular_params.get_ksk_params()
    }

    fn get_pksk_params(&self) -> Option<KSKParams> {
        self.regular_params.get_pksk_params()
    }

    fn get_rerand_ksk_params(&self) -> Option<KSKParams> {
        self.regular_params.get_rerand_ksk_params()
    }

    fn get_bk_params(&self) -> BKParams {
        self.regular_params.get_bk_params()
    }

    fn get_msnrk_configuration(&self) -> MSNRKConfiguration {
        self.regular_params.get_msnrk_configuration()
    }

    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters> {
        self.regular_params.get_compression_decompression_params()
    }

    fn get_sns_compression_params(&self) -> Option<DistributedSnsCompressionParameters> {
        if let Some(comp_params) = self.sns_compression_params {
            let NoiseInfo {
                amount: ksk_num_noise,
                bound: ksk_noisebound,
            } = self.num_needed_noise_sns_compression_key();

            Some(DistributedSnsCompressionParameters {
                raw_compression_parameters: comp_params,
                ksk_num_noise,
                ksk_noisebound,
                pmax: self.get_sk_deviations().map(|d| d.pmax),
            })
        } else {
            None
        }
    }

    fn num_needed_noise_compression_key(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_compression_key()
    }

    fn num_needed_noise_decompression_key(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_decompression_key()
    }

    fn num_raw_bits(&self, keyset_config: KeySetConfig) -> usize {
        self.regular_params.num_raw_bits(keyset_config)
            + match keyset_config {
                KeySetConfig::Standard(_standard_key_set_config) => {
                    self.glwe_sk_num_bits_sns() + self.sns_compression_sk_num_bits()
                }
                KeySetConfig::DecompressionOnly => 0,
            }
    }

    fn all_lwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_inner) => {
                let regular_lwe = self.regular_params.all_lwe_noise(keyset_config);
                let sns_lwe = self.num_needed_noise_msnrk_sns();
                let target_bound = regular_lwe.bound;
                combine_noise_info(target_bound, &[regular_lwe, sns_lwe])
            }
            KeySetConfig::DecompressionOnly => self.regular_params.all_lwe_noise(keyset_config),
        }
    }

    fn all_lwe_hat_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        self.regular_params.all_lwe_hat_noise(keyset_config)
    }

    fn all_glwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        self.regular_params.all_glwe_noise(keyset_config)
    }

    fn all_compression_ksk_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        self.regular_params.all_compression_ksk_noise(keyset_config)
    }

    fn compression_key_tuniform_bound(&self) -> Option<TUniformBound> {
        self.regular_params.compression_key_tuniform_bound()
    }

    fn compression_sk_num_bits(&self) -> usize {
        self.regular_params.compression_sk_num_bits()
    }
    fn get_dedicated_pk_params(
        &self,
    ) -> Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )> {
        self.regular_params.get_dedicated_pk_params()
    }

    fn get_rerand_params(&self) -> Option<ShortintKeySwitchingParameters> {
        self.regular_params.get_rerand_params()
    }

    fn pksk_rshift(&self) -> i8 {
        self.regular_params.pksk_rshift()
    }

    fn lwe_sk_num_bits_to_sample(&self) -> usize {
        self.regular_params.lwe_sk_num_bits_to_sample()
    }

    fn lwe_hat_sk_num_bits_to_sample(&self) -> usize {
        self.regular_params.lwe_hat_sk_num_bits_to_sample()
    }

    fn glwe_sk_num_bits_to_sample(&self) -> usize {
        self.regular_params.glwe_sk_num_bits_to_sample()
    }

    fn compression_sk_num_bits_to_sample(&self) -> usize {
        self.regular_params.compression_sk_num_bits_to_sample()
    }

    fn get_sk_deviations(&self) -> Option<SecretKeyDeviations> {
        self.regular_params.get_sk_deviations()
    }
}

impl DKGParamsSnS {
    pub fn glwe_tuniform_bound_sns(&self) -> TUniformBound {
        match self.sns_params.glwe_noise_distribution() {
            DynamicDistribution::Gaussian(_) => panic!("we only support tuniform!"),
            DynamicDistribution::TUniform(tuniform) => {
                TUniformBound(tuniform.bound_log2() as usize)
            }
        }
    }

    pub fn polynomial_size_sns(&self) -> PolynomialSize {
        self.sns_params.polynomial_size()
    }

    pub fn glwe_dimension_sns(&self) -> GlweDimension {
        self.sns_params.glwe_dimension()
    }

    pub fn glwe_sk_num_bits_sns(&self) -> usize {
        self.polynomial_size_sns().0 * self.glwe_dimension_sns().0
    }

    // GLWE keys should be seen as GLWE dimension keys, each of size polynomial_size
    pub fn glwe_sk_num_bits_sns_to_sample(&self) -> usize {
        let key_size = self.glwe_sk_num_bits_sns();
        if let Some(deviations) = self.get_sk_deviations() {
            let indiviual_key_size = self.polynomial_size_sns().0;
            let log_glwe_dim = (self.glwe_dimension_sns().0.ilog2() + 1) as i64;
            let prob_within_range =
                compute_prob_hw_within_range(deviations.pmax, indiviual_key_size as u64);
            let max_num_tries = compute_min_trials(
                prob_within_range,
                deviations.log2_failure_proba - log_glwe_dim,
            )
            .unwrap();
            max_num_tries * key_size
        } else {
            key_size
        }
    }

    pub fn decomposition_base_log_bk_sns(&self) -> DecompositionBaseLog {
        self.sns_params.decomp_base_log()
    }

    pub fn decomposition_level_count_bk_sns(&self) -> DecompositionLevelCount {
        self.sns_params.decomp_level_count()
    }

    pub fn all_bk_sns_noise(&self) -> NoiseInfo {
        let amount = self.lwe_dimension().0
            * (self.glwe_dimension_sns().0 + 1)
            * self.decomposition_level_count_bk_sns().0
            * self.polynomial_size_sns().0;
        NoiseInfo {
            amount,
            bound: NoiseBounds::GlweNoiseSnS(self.glwe_tuniform_bound_sns()),
        }
    }

    pub fn get_bk_sns_params(&self) -> BKParams {
        let NoiseInfo {
            amount: num_needed_noise,
            bound: noise_bound,
        } = self.all_bk_sns_noise();
        BKParams {
            num_needed_noise,
            noise_bound,
            decomposition_base_log: self.decomposition_base_log_bk_sns(),
            decomposition_level_count: self.decomposition_level_count_bk_sns(),
            enc_type: EncryptionType::Bits128,
        }
    }

    pub fn sns_compression_sk_num_bits(&self) -> usize {
        match self.sns_compression_params {
            Some(param) => param.packing_ks_polynomial_size.0 * param.packing_ks_glwe_dimension.0,
            None => 0,
        }
    }

    pub fn sns_compression_sk_num_bits_to_sample(&self) -> usize {
        if self.sns_compression_params.is_none() {
            return 0;
        }
        let key_size = self.sns_compression_sk_num_bits();
        if let Some(deviations) = self.get_sk_deviations() {
            let (indiviual_key_size, log_glwe_dim) =
                if let Some(sns_comp_params) = self.sns_compression_params {
                    (
                        sns_comp_params.packing_ks_polynomial_size.0,
                        (sns_comp_params.packing_ks_glwe_dimension.0.ilog2() + 1) as i64,
                    )
                } else {
                    (0, 0)
                };
            let prob_within_range =
                compute_prob_hw_within_range(deviations.pmax, indiviual_key_size as u64);
            let max_num_tries = compute_min_trials(
                prob_within_range,
                deviations.log2_failure_proba - log_glwe_dim,
            )
            .unwrap();
            max_num_tries * key_size
        } else {
            key_size
        }
    }

    fn sns_compression_key_tuniform_bound(&self) -> Option<TUniformBound> {
        if let Some(params) = self.sns_compression_params {
            if let DynamicDistribution::TUniform(bound) = params.packing_ks_key_noise_distribution {
                Some(TUniformBound(bound.bound_log2() as usize))
            } else {
                panic!("We do not support non-Tuniform noise distribution")
            }
        } else {
            None
        }
    }

    pub fn num_needed_noise_sns_compression_key(&self) -> NoiseInfo {
        // both must exist to make a valid NoiseInfo
        match (
            self.sns_compression_params,
            self.sns_compression_key_tuniform_bound(),
        ) {
            (Some(comp_params), Some(compression_key_tuniform_bound)) => {
                let amount = self.sns_params.glwe_dimension().0
                    * self.sns_params.polynomial_size().0
                    * comp_params.packing_ks_level.0
                    * comp_params.packing_ks_polynomial_size.0;
                NoiseInfo {
                    amount,
                    bound: NoiseBounds::SnsCompressionKSKNoise(compression_key_tuniform_bound),
                }
            }
            _ => {
                // use a dummy bound
                NoiseInfo {
                    amount: 0,
                    bound: NoiseBounds::SnsCompressionKSKNoise(TUniformBound::default()),
                }
            }
        }
    }

    fn get_classic_sns_params(&self) -> NoiseSquashingClassicParameters {
        match self.sns_params {
            NoiseSquashingParameters::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters
            }
            NoiseSquashingParameters::MultiBit(_) => {
                panic!("We do not support multi bit SnS params yet")
            }
        }
    }

    fn num_needed_noise_msnrk_sns(&self) -> NoiseInfo {
        let classic_sns_params = self.get_classic_sns_params();
        let amount = match classic_sns_params.modulus_switch_noise_reduction_params {
            ModulusSwitchType::Standard => 0,
            ModulusSwitchType::DriftTechniqueNoiseReduction(
                modulus_switch_noise_reduction_params,
            ) => {
                modulus_switch_noise_reduction_params
                    .modulus_switch_zeros_count
                    .0
            }
            ModulusSwitchType::CenteredMeanNoiseReduction => 0,
        };
        let bound = NoiseBounds::LweNoise(self.lwe_tuniform_bound());
        NoiseInfo { amount, bound }
    }

    pub fn get_msnrk_configuration_sns(&self) -> MSNRKConfiguration {
        let classic_sns_params = self.get_classic_sns_params();
        let NoiseInfo { amount, bound } = self.num_needed_noise_msnrk_sns();
        match classic_sns_params.modulus_switch_noise_reduction_params {
            ModulusSwitchType::Standard => MSNRKConfiguration::Standard,
            ModulusSwitchType::DriftTechniqueNoiseReduction(
                modulus_switch_noise_reduction_params,
            ) => MSNRKConfiguration::DriftTechniqueNoiseReduction(MSNRKParams {
                num_needed_noise: amount,
                noise_bound: bound,
                params: modulus_switch_noise_reduction_params,
            }),
            ModulusSwitchType::CenteredMeanNoiseReduction => {
                MSNRKConfiguration::CenteredMeanNoiseReduction
            }
        }
    }
}

/// Computes the probability that the Hamming weight of a binary string is within
/// [(1-pmax)*size; pmax*size]
fn compute_prob_hw_within_range(pmax: f64, size: u64) -> f64 {
    assert!(pmax > 0.5 && pmax < 1.0);
    let distribution = Binomial::new(0.5, size).unwrap();
    let (min_hw, max_hw) = compute_min_max_hw(pmax, size);
    distribution.cdf(max_hw) - distribution.cdf(min_hw)
}

/// Computes the minimum number of trials k needed to achieve at least one success
/// with probability >=1-p_failure, where each trial has success probability p.
///
/// Formula: k >= log_p_failure/log2(1 - p)
fn compute_min_trials(p: f64, log2_p_failure: i64) -> Result<usize, String> {
    // Input validation
    if p <= 0.0 || p >= 1.0 {
        return Err(format!("p={} must be in the range (0, 1).", p));
    }

    let one_minus_p = 1.0 - p;

    let k_float = (log2_p_failure as f64) / one_minus_p.log2();

    // Round up to get the minimum integer number of trials
    let k = k_float.ceil() as usize;

    Ok(k)
}

pub(crate) fn compute_min_max_hw(pmax: f64, size: u64) -> (u64, u64) {
    assert!(pmax > 0.5 && pmax < 1.0);
    let max_hw = (pmax * size as f64).floor() as u64;
    let min_hw = ((1.0 - pmax) * size as f64).floor() as u64;
    (min_hw, max_hw)
}

#[cfg_attr(test, derive(strum_macros::EnumIter))]
#[derive(ValueEnum, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum DkgParamsAvailable {
    NIST_PARAMS_P32_NO_SNS_FGLWE,
    NIST_PARAMS_P32_SNS_FGLWE,
    NIST_PARAMS_P8_NO_SNS_FGLWE,
    NIST_PARAMS_P8_SNS_FGLWE,
    NIST_PARAMS_P32_NO_SNS_LWE,
    NIST_PARAMS_P32_SNS_LWE,
    NIST_PARAMS_P8_NO_SNS_LWE,
    NIST_PARAMS_P8_SNS_LWE,
    BC_PARAMS_NO_SNS,
    BC_PARAMS_SNS,
    BC_PARAMS_NIGEL_NO_SNS,
    BC_PARAMS_NIGEL_SNS,
    PARAMS_TEST_BK_SNS,
}

impl DkgParamsAvailable {
    pub fn to_param(&self) -> DKGParams {
        match self {
            DkgParamsAvailable::NIST_PARAMS_P32_NO_SNS_FGLWE => NIST_PARAMS_P32_NO_SNS_FGLWE,
            DkgParamsAvailable::NIST_PARAMS_P32_SNS_FGLWE => NIST_PARAMS_P32_SNS_FGLWE,
            DkgParamsAvailable::NIST_PARAMS_P8_NO_SNS_FGLWE => NIST_PARAMS_P8_NO_SNS_FGLWE,
            DkgParamsAvailable::NIST_PARAMS_P8_SNS_FGLWE => NIST_PARAMS_P8_SNS_FGLWE,
            DkgParamsAvailable::NIST_PARAMS_P32_NO_SNS_LWE => NIST_PARAMS_P32_NO_SNS_LWE,
            DkgParamsAvailable::NIST_PARAMS_P32_SNS_LWE => NIST_PARAMS_P32_SNS_LWE,
            DkgParamsAvailable::NIST_PARAMS_P8_NO_SNS_LWE => NIST_PARAMS_P8_NO_SNS_LWE,
            DkgParamsAvailable::NIST_PARAMS_P8_SNS_LWE => NIST_PARAMS_P8_SNS_LWE,
            DkgParamsAvailable::BC_PARAMS_NO_SNS => BC_PARAMS_NO_SNS,
            DkgParamsAvailable::BC_PARAMS_SNS => BC_PARAMS_SNS,
            DkgParamsAvailable::BC_PARAMS_NIGEL_NO_SNS => BC_PARAMS_NIGEL_NO_SNS,
            DkgParamsAvailable::BC_PARAMS_NIGEL_SNS => BC_PARAMS_NIGEL_SNS,
            DkgParamsAvailable::PARAMS_TEST_BK_SNS => PARAMS_TEST_BK_SNS,
        }
    }
}

/// Blockchain Parameters (with pfail `2^-128`), using parameters in tfhe-rs codebase
pub const BC_PARAMS: DKGParamsRegular = DKGParamsRegular {
    dkg_mode: DkgMode::Z128,
    sec: 128,
    ciphertext_parameters:
        tfhe::shortint::parameters::current_params::V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        tfhe::shortint::parameters::current_params::V1_4_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        tfhe::shortint::parameters::current_params::V1_4_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: Some(
        tfhe::shortint::parameters::current_params::V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    secret_key_deviations: None,
    cpk_re_randomization_ksk_params: Some(tfhe::shortint::parameters::current_params::V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
};

/// Blockchain Parameters without SnS (with pfail `2^-128`), using parameters in tfhe-rs codebase
pub const BC_PARAMS_NO_SNS: DKGParams = DKGParams::WithoutSnS(BC_PARAMS);

/// Blockchain Parameters with SnS (with pfail `2^-128`), using parameters in tfhe-rs codebase
/// and SnS params taken from tfhe-rs as well.
pub const BC_PARAMS_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: BC_PARAMS,
    sns_params: tfhe::shortint::parameters::current_params::V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    sns_compression_params: Some(tfhe::shortint::parameters::current_params::V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
});

/// Blockchain Parameters (with pfail `2^-64`), using parameters generated by Nigel's script
/// (PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M64)
const BC_PARAMS_NIGEL: DKGParamsRegular = DKGParamsRegular {
    dkg_mode: DkgMode::Z128,
    sec: 128,
    ciphertext_parameters: ClassicPBSParameters {
        lwe_dimension: LweDimension(928),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -64.0629,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        //Note: Not sure about this one
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    },
    dedicated_compact_public_key_parameters: Some((
        CompactPublicKeyEncryptionParameters {
            encryption_lwe_dimension: LweDimension(1024),
            encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            ciphertext_modulus: CiphertextModulus::new_native(),
            expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
            zk_scheme: SupportedCompactPkeZkScheme::V1,
        },
        ShortintKeySwitchingParameters {
            ks_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(17),
            destination_key: EncryptionKeyChoice::Big,
        },
    )),
    compression_decompression_parameters: None,
    secret_key_deviations: None,
    cpk_re_randomization_ksk_params: Some(ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(17),
        destination_key: EncryptionKeyChoice::Big,
    }),
};

/// Blockchain Parameters without SnS (with pfail `2^-64`), using parameters generated by Nigel's script
pub const BC_PARAMS_NIGEL_NO_SNS: DKGParams = DKGParams::WithoutSnS(BC_PARAMS_NIGEL);

/// Blockchain Parameters with SnS (with pfail `2^-64`), using parameters generated by Nigel's script
/// and SnS params taken from Nigel's script (PARAMS_P32_SNS_LWE)
pub const BC_PARAMS_NIGEL_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: BC_PARAMS_NIGEL,
    sns_params: NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(2),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
        polynomial_size: PolynomialSize(2048),
        decomp_base_log: DecompositionBaseLog(24),
        decomp_level_count: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        // we keep the same message and carry modulus
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
    }),
    sns_compression_params: None,
});

/// __INSECURE__ Used for testing only
/// Note that this parameter set uses the V1 proofs.
///
/// Normally the bound_log2 value in the tuniform distribution is set to 3.
/// But we change it to 0 because it's much ligher on the preprocessing
/// and maintains correctness. But this may be inconsistent with the ms_*
/// values under modulus_switch_noise_reduction_params. Since these parameters
/// are for testing, we're fine with this inconsistency.
pub const PARAMS_TEST_BK_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: DKGParamsRegular {
        dkg_mode: DkgMode::Z128,
        sec: 128,
        ciphertext_parameters: ClassicPBSParameters {
            lwe_dimension: LweDimension(1),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(256),
            lwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
            glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
            pbs_base_log: DecompositionBaseLog(24),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(37),
            ks_level: DecompositionLevelCount(1),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            max_noise_level: MaxNoiseLevel::new(5),
            log2_p_fail: -64f64,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
            modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
                ModulusSwitchNoiseReductionParams {
                    modulus_switch_zeros_count: LweCiphertextCount(10),
                    ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                    ms_r_sigma_factor: RSigmaFactor(9.75539320076416),
                    ms_input_variance: Variance(1.92631390716519e-10),
                },
            ),
        },
        compression_decompression_parameters: Some(CompressionParameters {
            br_level: DecompositionLevelCount(1),
            br_base_log: DecompositionBaseLog(24),
            packing_ks_level: DecompositionLevelCount(1),
            packing_ks_base_log: DecompositionBaseLog(27),
            packing_ks_polynomial_size: PolynomialSize(256),
            packing_ks_glwe_dimension: GlweDimension(1),
            lwe_per_glwe: LweCiphertextCount(256),
            storage_log_modulus: tfhe::core_crypto::prelude::CiphertextModulusLog(9),
            packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(0),
        }),
        dedicated_compact_public_key_parameters: Some((
            CompactPublicKeyEncryptionParameters {
                encryption_lwe_dimension: LweDimension(512),
                encryption_noise_distribution: DynamicDistribution::new_t_uniform(0),
                message_modulus: MessageModulus(4),
                carry_modulus: CarryModulus(4),
                ciphertext_modulus: CiphertextModulus::new_native(),
                expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
                zk_scheme: SupportedCompactPkeZkScheme::V2,
            },
            ShortintKeySwitchingParameters {
                ks_level: DecompositionLevelCount(1),
                ks_base_log: DecompositionBaseLog(37),
                destination_key: EncryptionKeyChoice::Small,
            },
        )),
        // Note that lwe dim (=1) is too small to really allow for any meaningful
        // deviation here
        secret_key_deviations: None,
        cpk_re_randomization_ksk_params: Some(ShortintKeySwitchingParameters {
            ks_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(17),
            destination_key: EncryptionKeyChoice::Big,
        }),
    },
    sns_params: NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(1),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
        polynomial_size: PolynomialSize(256),
        decomp_base_log: DecompositionBaseLog(33),
        decomp_level_count: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(8),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(9.2),
                ms_input_variance: Variance(2.182718682903484e-224),
            },
        ),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
    }),
    sns_compression_params: Some(NoiseSquashingCompressionParameters {
        packing_ks_level: DecompositionLevelCount(1),
        packing_ks_base_log: DecompositionBaseLog(61),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(1),
        lwe_per_glwe: LweCiphertextCount(128),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
    }),
});

pub const NIST_PARAMS_P8_INTERNAL_LWE: DKGParamsRegular = DKGParamsRegular {
    dkg_mode: DkgMode::Z128,
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_1_CARRY_1_COMPACT_PK_PBS_KS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    secret_key_deviations: Some(SecretKeyDeviations{ log2_failure_proba: -80, pmax: 0.798 }),
    cpk_re_randomization_ksk_params: Some(super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128)
};

pub const NIST_PARAMS_P8_NO_SNS_LWE: DKGParams = DKGParams::WithoutSnS(NIST_PARAMS_P8_INTERNAL_LWE);

pub const NIST_PARAMS_P8_SNS_LWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P8_INTERNAL_LWE,
    sns_params:
        super::raw_parameters::NIST_PARAMS_NOISE_SQUASHING_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128,
    sns_compression_params: None,
});

pub const NIST_PARAMS_P32_INTERNAL_LWE: DKGParamsRegular = DKGParamsRegular {
    dkg_mode: DkgMode::Z128,
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    secret_key_deviations: Some(SecretKeyDeviations{ log2_failure_proba: -80, pmax: 0.8044 }),
    cpk_re_randomization_ksk_params: Some(super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
};

pub const NIST_PARAMS_P32_NO_SNS_LWE: DKGParams =
    DKGParams::WithoutSnS(NIST_PARAMS_P32_INTERNAL_LWE);

pub const NIST_PARAMS_P32_SNS_LWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P32_INTERNAL_LWE,
    sns_params:
        super::raw_parameters::NIST_PARAMS_NOISE_SQUASHING_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128,
    sns_compression_params: None,
});

pub const NIST_PARAMS_P8_INTERNAL_FGLWE: DKGParamsRegular = DKGParamsRegular {
    dkg_mode: DkgMode::Z128,
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_1_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    secret_key_deviations: Some(SecretKeyDeviations{ log2_failure_proba: -80, pmax: 0.5022 }),
    cpk_re_randomization_ksk_params: Some(super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128)
};

pub const NIST_PARAMS_P8_NO_SNS_FGLWE: DKGParams =
    DKGParams::WithoutSnS(NIST_PARAMS_P8_INTERNAL_FGLWE);

// Parameters for SwitchSquash
pub const NIST_PARAMS_P8_SNS_FGLWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P8_INTERNAL_FGLWE,
    sns_params:
        super::raw_parameters::NIST_PARAMS_NOISE_SQUASHING_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    sns_compression_params: None,
});

pub const NIST_PARAMS_P32_INTERNAL_FGLWE: DKGParamsRegular = DKGParamsRegular {
    dkg_mode: DkgMode::Z128,
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    secret_key_deviations: Some(SecretKeyDeviations{ log2_failure_proba: -80, pmax: 0.7499 }),
    cpk_re_randomization_ksk_params: Some(super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
};

pub const NIST_PARAMS_P32_NO_SNS_FGLWE: DKGParams =
    DKGParams::WithoutSnS(NIST_PARAMS_P32_INTERNAL_FGLWE);

// Parameters for SwitchSquash
pub const NIST_PARAMS_P32_SNS_FGLWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P32_INTERNAL_FGLWE,
    sns_params:
        super::raw_parameters::NIST_PARAMS_NOISE_SQUASHING_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    sns_compression_params: None,
});

#[cfg(test)]
mod tests {
    use crate::execution::{
        keyset_config::KeySetConfig,
        tfhe_internals::parameters::{
            compute_min_trials, compute_prob_hw_within_range, BC_PARAMS_SNS,
        },
    };

    use super::{DkgParamsAvailable, BC_PARAMS_NO_SNS};
    use strum::IntoEnumIterator;

    #[test]
    fn test_all_noise() {
        let keyset_config = KeySetConfig::default();
        for param in DkgParamsAvailable::iter() {
            let p = param.to_param();
            let h = p.get_params_basics_handle();
            let _ = h.all_compression_ksk_noise(keyset_config);
            let _ = h.all_glwe_noise(keyset_config);
            let _ = h.all_lwe_hat_noise(keyset_config);
            let _ = h.all_lwe_noise(keyset_config);
        }
    }

    #[test]
    fn test_required_preproc() {
        let keyset_config = KeySetConfig::default();
        // Note that BC_PARAMS_NO_SNS doesn't have fixed HW
        // so sk_num_bits_to_sample == sk_num_bits
        let param = BC_PARAMS_NO_SNS;
        let h = param.get_params_basics_handle();
        let sk_total = h.lwe_dimension().0
            + h.lwe_hat_dimension().0
            + h.glwe_sk_num_bits()
            + h.compression_sk_num_bits();
        assert_eq!(sk_total, h.num_raw_bits(keyset_config));
        let noise_total = h.all_compression_ksk_noise(keyset_config).num_bits_needed()
            + h.all_glwe_noise(keyset_config).num_bits_needed()
            + h.all_lwe_hat_noise(keyset_config).num_bits_needed()
            + h.all_lwe_noise(keyset_config).num_bits_needed();

        assert_eq!(sk_total + noise_total, h.total_bits_required(keyset_config));
    }

    #[test]
    fn test_required_preproc_sns() {
        let keyset_config = KeySetConfig::default();
        let param = BC_PARAMS_SNS;
        let sns_param = match param {
            crate::execution::tfhe_internals::parameters::DKGParams::WithSnS(p) => p,
            _ => panic!("Expected WithSnS parameters"),
        };
        let h = param.get_params_basics_handle();
        let sk_total = h.lwe_dimension().0
            + h.lwe_hat_dimension().0
            + h.glwe_sk_num_bits()
            + h.compression_sk_num_bits()
            + sns_param.glwe_sk_num_bits_sns()
            + sns_param.sns_compression_sk_num_bits();
        assert_eq!(sk_total, h.num_raw_bits(keyset_config));
        let noise_total = h.all_compression_ksk_noise(keyset_config).num_bits_needed()
            + h.all_glwe_noise(keyset_config).num_bits_needed()
            + h.all_lwe_hat_noise(keyset_config).num_bits_needed()
            + h.all_lwe_noise(keyset_config).num_bits_needed()
            + sns_param.all_bk_sns_noise().num_bits_needed()
            + sns_param
                .num_needed_noise_sns_compression_key()
                .num_bits_needed();

        assert_eq!(sk_total + noise_total, h.total_bits_required(keyset_config));
    }

    #[test]
    fn test_required_preproc_decompression() {
        let keyset_config = KeySetConfig::DecompressionOnly;
        for param in [BC_PARAMS_SNS, BC_PARAMS_NO_SNS] {
            let h = param.get_params_basics_handle();
            let sk_total = 0;
            assert_eq!(sk_total, h.num_raw_bits(keyset_config));
            let noise_total = h.num_needed_noise_decompression_key().num_bits_needed();

            assert_eq!(sk_total + noise_total, h.total_bits_required(keyset_config));
            assert_eq!(
                sk_total + noise_total,
                h.all_glwe_noise(keyset_config).num_bits_needed()
            );
        }
    }

    #[test]
    fn test_compute_prob_hw_within_range() {
        // For len 100, the std dev is 5, setting pmax=0.6 means we accept
        // hw within 2std dev, so we should get around 95% probability (assuming normal approximation)
        let pmax = 0.6;
        let key_size = 100;
        let result = compute_prob_hw_within_range(pmax, key_size);
        // Bound is a bit loose to cope with f64 precision
        assert!(result > 0.95 && result < 0.96);
    }

    #[test]
    fn test_compute_min_trials() {
        // If each trial has only a 0.25 chance of success, we expect to need 49 trials
        // to have a 1 - 2^-20 chance of at least one success.
        // (as (0.75)**49 < 2**-20 but (0.75)**48 > 2**-20)
        let p = 0.25;
        let log2_p_failure = -20;
        let result = compute_min_trials(p, log2_p_failure).unwrap();
        assert_eq!(result, 49);
    }
}
