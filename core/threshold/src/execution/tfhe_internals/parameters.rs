use std::{
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::{
        commons::{ciphertext_modulus::CiphertextModulus, math::random::TUniform},
        entities::LweCiphertextOwned,
    },
    integer::{ciphertext::BaseRadixCiphertext, parameters::DynamicDistribution},
    named::Named,
    shortint::{
        parameters::{
            CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
            CompressionParameters, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
            LweCiphertextCount, LweDimension, ModulusSwitchNoiseReductionParams,
            NoiseEstimationMeasureBound, PolynomialSize, RSigmaFactor,
            ShortintKeySwitchingParameters, SupportedCompactPkeZkScheme, Variance,
        },
        CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
        PBSOrder, PBSParameters,
    },
    Versionize,
};
use tfhe_versionable::VersionsDispatch;

use crate::{
    execution::keyset_config::KeySetConfig,
    file_handling::{read_as_json, write_as_json},
};

pub type Ciphertext64 = BaseRadixCiphertext<tfhe::shortint::Ciphertext>;
pub type Ciphertext64Block = tfhe::shortint::Ciphertext;

#[derive(VersionsDispatch)]
pub enum Ciphertext128Versioned {
    V0(Ciphertext128),
}

// Observe that tfhe-rs is hard-coded to use u64, hence we require custom types for the 128 bit versions for now.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(Ciphertext128Versioned)]
pub struct Ciphertext128 {
    pub inner: Vec<Ciphertext128Block>,
}

impl Named for Ciphertext128 {
    const NAME: &'static str = "Ciphertext128";
}

impl Ciphertext128 {
    pub fn new(inner: Vec<Ciphertext128Block>) -> Self {
        Self { inner }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

pub type Ciphertext128Block = LweCiphertextOwned<u128>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionType {
    Bits64,
    Bits128,
}

pub enum LowLevelCiphertext {
    Big(Ciphertext128),
    Small(Ciphertext64),
}

impl LowLevelCiphertext {
    pub fn try_get_big_ct(self) -> anyhow::Result<Ciphertext128> {
        match self {
            LowLevelCiphertext::Big(ct128) => Ok(ct128),
            LowLevelCiphertext::Small(_) => {
                anyhow::bail!("expected big ciphertext but got a small one")
            }
        }
    }
    pub fn try_get_small_ct(self) -> anyhow::Result<Ciphertext64> {
        match self {
            LowLevelCiphertext::Big(_) => {
                anyhow::bail!("expected small ciphertext but got a big one")
            }
            LowLevelCiphertext::Small(ct64) => Ok(ct64),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug, Default)]
pub struct TUniformBound(pub usize);

#[derive(Debug, Clone, Copy, strum_macros::EnumIter)]
pub enum NoiseBounds {
    LweNoise(TUniformBound),
    LweHatNoise(TUniformBound),
    GlweNoise(TUniformBound),
    GlweNoiseSnS(TUniformBound),
    CompressionKSKNoise(TUniformBound),
}

impl NoiseBounds {
    pub fn get_bound(&self) -> TUniformBound {
        match self {
            NoiseBounds::LweNoise(bound) => *bound,
            NoiseBounds::LweHatNoise(bound) => *bound,
            NoiseBounds::GlweNoise(bound) => *bound,
            NoiseBounds::GlweNoiseSnS(bound) => *bound,
            NoiseBounds::CompressionKSKNoise(bound) => *bound,
        }
    }
}

// TODO we should switch to the tfhe-rs types for SnS parameters when tfhe-rs v1.1 is out
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct SwitchAndSquashParameters {
    pub glwe_dimension: GlweDimension,
    pub glwe_noise_distribution: TUniform<u128>,
    pub polynomial_size: PolynomialSize,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<u128>,
}

#[derive(Debug)]
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
pub struct DistributedCompressionParameters {
    pub raw_compression_parameters: CompressionParameters,
    pub ksk_num_noise: usize,
    pub ksk_noisebound: NoiseBounds,
    pub bk_params: BKParams,
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

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub enum DKGParams {
    WithoutSnS(DKGParamsRegular),
    WithSnS(DKGParamsSnS),
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
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct DKGParamsRegular {
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
    ///States whether we want compressed ciphertexts
    pub flag: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub struct DKGParamsSnS {
    pub regular_params: DKGParamsRegular,
    pub sns_params: SwitchAndSquashParameters,
}

#[derive(Debug, Clone)]
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
    fn write_to_file(&self, path: &Path) -> anyhow::Result<()>;
    fn read_from_file(path: &Path) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized;

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
    fn glwe_sk_num_bits(&self) -> usize;
    fn compression_sk_num_bits(&self) -> usize;
    fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog;
    fn decomposition_base_log_pksk(&self) -> DecompositionBaseLog;
    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog;
    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount;
    fn decomposition_level_count_pksk(&self) -> DecompositionLevelCount;
    fn decomposition_level_count_bk(&self) -> DecompositionLevelCount;

    // `num_needed_noise_` functions do not consider take KeySetConfig into consideration
    fn num_needed_noise_pk(&self) -> NoiseInfo;
    fn num_needed_noise_ksk(&self) -> NoiseInfo;
    fn num_needed_noise_pksk(&self) -> NoiseInfo;
    fn num_needed_noise_bk(&self) -> NoiseInfo;
    fn num_needed_noise_compression_key(&self) -> NoiseInfo;
    fn num_needed_noise_decompression_key(&self) -> NoiseInfo;
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
    fn get_bk_params(&self) -> BKParams;
    // msnrk: modulus switch noise reduction key
    fn get_msnrk_params(&self) -> Option<MSNRKParams>;
    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters>;

    fn all_lwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    fn all_lwe_hat_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    fn all_glwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
    fn all_compression_ksk_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo;
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
    fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        write_as_json(&path, self)
    }

    fn read_from_file(path: &Path) -> anyhow::Result<Self> {
        read_as_json(&path)
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
        let serialized = bincode::serialize(self).unwrap();
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

        if keyset_config.is_standard() {
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
        }
        //For decompression keys
        num_bits_needed += self.num_needed_noise_decompression_key().num_bits_needed();

        num_bits_needed
    }

    fn total_triples_required(&self, keyset_config: KeySetConfig) -> usize {
        //Required for the "normal" BK
        let mut num_triples_needed = 0;
        if keyset_config.is_standard() {
            num_triples_needed += self.lwe_dimension().0 * self.glwe_sk_num_bits();
        }

        //Required for the compression BK
        if let Some(comp_params) = self.compression_decompression_parameters {
            num_triples_needed += self.glwe_sk_num_bits()
                * (comp_params.packing_ks_glwe_dimension.0
                    * comp_params.packing_ks_polynomial_size.0)
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

    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.ciphertext_parameters.pbs_base_log
    }

    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.ciphertext_parameters.ks_level
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
            Some(param) => param.modulus_switch_zeros_count.0,
            None => 0,
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

    fn get_msnrk_params(&self) -> Option<MSNRKParams> {
        let NoiseInfo { amount, bound } = self.num_needed_noise_msnrk();
        self.ciphertext_parameters
            .modulus_switch_noise_reduction_params
            .map(|params| MSNRKParams {
                num_needed_noise: amount,
                noise_bound: bound,
                params,
            })
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
                self.lwe_dimension().0
                    + self.lwe_hat_dimension().0
                    + self.glwe_sk_num_bits()
                    + if config.is_using_existing_compression_sk() {
                        0
                    } else {
                        self.compression_sk_num_bits()
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
            })
        } else {
            None
        }
    }

    fn get_dedicated_pk_params(
        &self,
    ) -> Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )> {
        self.dedicated_compact_public_key_parameters
    }
}

impl DKGParamsBasics for DKGParamsSnS {
    fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        write_as_json(&path, self)
    }

    fn read_from_file(path: &Path) -> anyhow::Result<Self> {
        read_as_json(&path)
    }

    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        self.regular_params.to_classic_pbs_parameters()
    }

    fn get_prefix_path(&self) -> PathBuf {
        let mut h = std::hash::DefaultHasher::new();
        let serialized = bincode::serialize(self).unwrap();
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
        if keyset_config.is_standard() {
            num_bits_needed +=
            //And for the additional glwe sk
            self.glwe_sk_num_bits_sns() +
            //And for the noise for the bk sns
            self.all_bk_sns_noise().num_bits_needed();
        }
        num_bits_needed
    }

    fn total_triples_required(&self, keyset_config: KeySetConfig) -> usize {
        let mut num_triples_needed = 0;
        if keyset_config.is_standard() {
            num_triples_needed +=
            // Raw triples necessary for the 2 BK
            self.lwe_dimension().0 * (self.glwe_sk_num_bits() + self.glwe_sk_num_bits_sns());
        }

        //Required for the compression BK
        if let Some(comp_params) = self.regular_params.compression_decompression_parameters {
            num_triples_needed += self.glwe_sk_num_bits()
                * (comp_params.packing_ks_glwe_dimension.0
                    * comp_params.packing_ks_polynomial_size.0)
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

    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.regular_params.decomposition_base_log_bk()
    }

    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_ksk()
    }

    fn decomposition_level_count_pksk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_pksk()
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

    fn get_bk_params(&self) -> BKParams {
        self.regular_params.get_bk_params()
    }

    fn get_msnrk_params(&self) -> Option<MSNRKParams> {
        self.regular_params.get_msnrk_params()
    }

    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters> {
        self.regular_params.get_compression_decompression_params()
    }

    fn num_needed_noise_compression_key(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_compression_key()
    }

    fn num_needed_noise_decompression_key(&self) -> NoiseInfo {
        self.regular_params.num_needed_noise_decompression_key()
    }

    fn num_raw_bits(&self, keyset_config: KeySetConfig) -> usize {
        self.regular_params.num_raw_bits(keyset_config)
            + if keyset_config.is_standard() {
                self.glwe_sk_num_bits_sns()
            } else {
                0
            }
    }

    fn all_lwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        self.regular_params.all_lwe_noise(keyset_config)
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
}

impl DKGParamsSnS {
    pub fn glwe_tuniform_bound_sns(&self) -> TUniformBound {
        TUniformBound(self.sns_params.glwe_noise_distribution.bound_log2() as usize)
    }

    pub fn polynomial_size_sns(&self) -> PolynomialSize {
        self.sns_params.polynomial_size
    }

    pub fn glwe_dimension_sns(&self) -> GlweDimension {
        self.sns_params.glwe_dimension
    }

    pub fn glwe_sk_num_bits_sns(&self) -> usize {
        self.polynomial_size_sns().0 * self.glwe_dimension_sns().0
    }

    pub fn decomposition_base_log_bk_sns(&self) -> DecompositionBaseLog {
        self.sns_params.pbs_base_log
    }

    pub fn decomposition_level_count_bk_sns(&self) -> DecompositionLevelCount {
        self.sns_params.pbs_level
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
    BC_PARAMS_SAM_NO_SNS,
    BC_PARAMS_SAM_SNS,
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
            DkgParamsAvailable::BC_PARAMS_SAM_NO_SNS => BC_PARAMS_SAM_NO_SNS,
            DkgParamsAvailable::BC_PARAMS_SAM_SNS => BC_PARAMS_SAM_SNS,
            DkgParamsAvailable::BC_PARAMS_NIGEL_NO_SNS => BC_PARAMS_NIGEL_NO_SNS,
            DkgParamsAvailable::BC_PARAMS_NIGEL_SNS => BC_PARAMS_NIGEL_SNS,
            DkgParamsAvailable::PARAMS_TEST_BK_SNS => PARAMS_TEST_BK_SNS,
        }
    }
}

/// Blokchain Parameters (with pfail `2^-128`), using parameters in tfhe-rs codebase
const BC_PARAMS_SAM: DKGParamsRegular = DKGParamsRegular {
    sec: 128,
    ciphertext_parameters:
        tfhe::shortint::parameters::v1_0::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        tfhe::shortint::parameters::v1_0::V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        tfhe::shortint::parameters::v1_0::V1_0_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: Some(
        tfhe::shortint::parameters::v1_0::V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    flag: true,
};

/// Blokchain Parameters without SnS (with pfail `2^-64`), using parameters in tfhe-rs codebase
pub const BC_PARAMS_SAM_NO_SNS: DKGParams = DKGParams::WithoutSnS(BC_PARAMS_SAM);

/// Blokchain Parameters with SnS (with pfail `2^-64`), using parameters in tfhe-rs codebase
/// and SnS params taken from Nigel's script (PARAMS_P32_SNS_LWE)
pub const BC_PARAMS_SAM_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: BC_PARAMS_SAM,
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(2),
        glwe_noise_distribution: TUniform::new(27),
        polynomial_size: PolynomialSize(2048),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
});

/// Blokchain Parameters (with pfail `2^-64`), using parameters generated by Nigel's script
/// (PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M64)
const BC_PARAMS_NIGEL: DKGParamsRegular = DKGParamsRegular {
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
        modulus_switch_noise_reduction_params: None,
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
    flag: true,
};

/// Blokchain Parameters without SnS (with pfail `2^-64`), using parameters generated by Nigel's script
pub const BC_PARAMS_NIGEL_NO_SNS: DKGParams = DKGParams::WithoutSnS(BC_PARAMS_NIGEL);

/// Blokchain Parameters with SnS (with pfail `2^-64`), using parameters generated by Nigel's script
/// and SnS params taken from Nigel's script (PARAMS_P32_SNS_LWE)
pub const BC_PARAMS_NIGEL_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: BC_PARAMS_NIGEL,
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(2),
        glwe_noise_distribution: TUniform::new(27),
        polynomial_size: PolynomialSize(2048),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
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
            modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(10),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(9.75539320076416),
                ms_input_variance: Variance(1.92631390716519e-10),
            }),
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
                encryption_lwe_dimension: LweDimension(256),
                encryption_noise_distribution: DynamicDistribution::new_t_uniform(0),
                message_modulus: MessageModulus(4),
                carry_modulus: CarryModulus(4),
                ciphertext_modulus: CiphertextModulus::new_native(),
                expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
                zk_scheme: SupportedCompactPkeZkScheme::V1,
            },
            ShortintKeySwitchingParameters {
                ks_level: DecompositionLevelCount(1),
                ks_base_log: DecompositionBaseLog(37),
                destination_key: EncryptionKeyChoice::Small,
            },
        )),
        flag: true,
    },
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(1),
        glwe_noise_distribution: TUniform::new(0),
        polynomial_size: PolynomialSize(256),
        pbs_base_log: DecompositionBaseLog(33),
        pbs_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        // TODO use the following when we switch to tfhe-rs v1.1
        // modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
        //     modulus_switch_zeros_count: LweCiphertextCount(8),
        //     ms_bound: NoiseEstimationMeasureBound(288230376151711744),
        //     ms_r_sigma_factor: RSigmaFactor(9.2),
        //     ms_input_variance: Variance(2.182718682903484e-224),
        // }),
    },
});

// Old set of parameters from before we had dedicated pk parameters and PKSK
pub const OLD_PARAMS_P32_REAL_WITH_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: DKGParamsRegular {
        sec: 128,
        ciphertext_parameters: ClassicPBSParameters {
            lwe_dimension: LweDimension(1024),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(2048),
            lwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(41)),
            glwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(14)),
            pbs_base_log: DecompositionBaseLog(21),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(6),
            ks_level: DecompositionLevelCount(3),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            max_noise_level: MaxNoiseLevel::from_msg_carry_modulus(
                MessageModulus(4),
                CarryModulus(4),
            ),
            log2_p_fail: -80., //most likely not true, but these should be deprecated anyway
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Small,
            modulus_switch_noise_reduction_params: None,
        },
        compression_decompression_parameters: None,
        dedicated_compact_public_key_parameters: None,
        flag: true,
    },
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(2),
        glwe_noise_distribution: TUniform::new(24),
        polynomial_size: PolynomialSize(2048),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
});

pub const NIST_PARAMS_P8_INTERNAL_LWE: DKGParamsRegular = DKGParamsRegular {
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_1_CARRY_1_COMPACT_PK_PBS_KS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    flag: true,
};

pub const NIST_PARAMS_P8_NO_SNS_LWE: DKGParams = DKGParams::WithoutSnS(NIST_PARAMS_P8_INTERNAL_LWE);

pub const NIST_PARAMS_P8_SNS_LWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P8_INTERNAL_LWE,
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(4),
        glwe_noise_distribution: TUniform::new(27),
        polynomial_size: PolynomialSize(1024),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
});

pub const NIST_PARAMS_P32_INTERNAL_LWE: DKGParamsRegular = DKGParamsRegular {
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    flag: true,
};

pub const NIST_PARAMS_P32_NO_SNS_LWE: DKGParams =
    DKGParams::WithoutSnS(NIST_PARAMS_P32_INTERNAL_LWE);

pub const NIST_PARAMS_P32_SNS_LWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P32_INTERNAL_LWE,
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(1),
        glwe_noise_distribution: TUniform::new(27),
        polynomial_size: PolynomialSize(4096),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
});

pub const NIST_PARAMS_P8_INTERNAL_FGLWE: DKGParamsRegular = DKGParamsRegular {
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_1_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    flag: true,
};

pub const NIST_PARAMS_P8_NO_SNS_FGLWE: DKGParams =
    DKGParams::WithoutSnS(NIST_PARAMS_P8_INTERNAL_FGLWE);

// Parameters for SwitchSquash
pub const NIST_PARAMS_P8_SNS_FGLWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P8_INTERNAL_FGLWE,
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(4),
        glwe_noise_distribution: TUniform::new(27),
        polynomial_size: PolynomialSize(1024),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
});

pub const NIST_PARAMS_P32_INTERNAL_FGLWE: DKGParamsRegular = DKGParamsRegular {
    sec: 128,
    ciphertext_parameters:
        super::raw_parameters::NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
    dedicated_compact_public_key_parameters: Some((
        super::raw_parameters::NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        super::raw_parameters::NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )),
    compression_decompression_parameters: None,
    flag: true,
};

pub const NIST_PARAMS_P32_NO_SNS_FGLWE: DKGParams =
    DKGParams::WithoutSnS(NIST_PARAMS_P32_INTERNAL_FGLWE);

// Parameters for SwitchSquash
pub const NIST_PARAMS_P32_SNS_FGLWE: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: NIST_PARAMS_P32_INTERNAL_FGLWE,
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(1),
        glwe_noise_distribution: TUniform::new(27),
        polynomial_size: PolynomialSize(4096),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
    },
});

#[cfg(test)]
mod tests {
    use crate::execution::keyset_config::KeySetConfig;

    use super::{DkgParamsAvailable, BC_PARAMS_SAM_NO_SNS};
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
        let param = BC_PARAMS_SAM_NO_SNS;
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
    fn test_required_preproc_decompression() {
        let keyset_config = KeySetConfig::DecompressionOnly;
        let param = BC_PARAMS_SAM_NO_SNS;
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
