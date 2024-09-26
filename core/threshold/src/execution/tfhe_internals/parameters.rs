use std::hash::{Hash, Hasher};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::{
        commons::{ciphertext_modulus::CiphertextModulus, math::random::TUniform},
        entities::LweCiphertextOwned,
    },
    integer::{ciphertext::BaseRadixCiphertext, parameters::DynamicDistribution},
    shortint::{
        parameters::{
            list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
            CompressionParameters, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
            LweDimension, PolynomialSize, ShortintKeySwitchingParameters,
        },
        CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
        PBSOrder, PBSParameters,
    },
};

use crate::file_handling::{read_as_json, write_as_json};

pub type Ciphertext64 = BaseRadixCiphertext<tfhe::shortint::Ciphertext>;
pub type Ciphertext64Block = tfhe::shortint::Ciphertext;
// Observe that tfhe-rs is hard-coded to use u64, hence we require custom types for the 128 bit versions for now.
pub type Ciphertext128 = Vec<Ciphertext128Block>;
pub type Ciphertext128Block = LweCiphertextOwned<u128>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionType {
    Bits64,
    Bits128,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
pub struct TUniformBound(pub usize);

#[derive(Debug, Clone, Copy)]
pub enum NoiseBounds {
    LweNoise(TUniformBound),
    LweHatNoise(TUniformBound),
    GlweNoise(TUniformBound),
    GlweNoiseSnS(TUniformBound),
    CompressionKSKNoise(TUniformBound),
}

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

pub trait DKGParamsBasics: Sync {
    fn write_to_file(&self, path: String) -> anyhow::Result<()>;
    fn read_from_file(path: String) -> anyhow::Result<Self>
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
    fn get_prefix_path(&self) -> String;
    fn get_sec(&self) -> u64;
    fn get_message_modulus(&self) -> MessageModulus;
    fn get_carry_modulus(&self) -> CarryModulus;
    fn total_bits_required(&self) -> usize;
    fn total_triples_required(&self) -> usize;
    fn total_randomness_required(&self) -> usize;
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
    fn num_needed_noise_pk(&self) -> usize;
    fn num_needed_noise_ksk(&self) -> usize;
    fn num_needed_noise_pksk(&self) -> usize;
    fn num_needed_noise_bk(&self) -> usize;
    fn num_needed_noise_compression_key(&self) -> usize;
    fn num_needed_noise_decompression_key(&self) -> usize;
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
    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters>;
}

impl DKGParamsBasics for DKGParamsRegular {
    fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_as_json(path, self)
    }

    fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_as_json(path)
    }

    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        self.ciphertext_parameters
    }

    ///This function returns a path based on
    /// - [DKGParams::message_modulus]
    /// - [DKGParams::carry_modulus]
    /// - a hash of the whole parameter set to make it unique
    fn get_prefix_path(&self) -> String {
        let mut h = std::hash::DefaultHasher::new();
        let serialized = bincode::serialize(self).unwrap();
        serialized.hash(&mut h);
        let hash = h.finish();
        format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_false_compression_{}_{}",
            self.get_message_modulus().0,
            self.get_carry_modulus().0,
            self.compression_decompression_parameters.is_some(),
            hash
        )
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

    fn total_bits_required(&self) -> usize {
        //Need bits for the two lwe sk, glwe sk
        //Counted twice if there's no dedicated pk parameter
        let mut num_bits_needed =
            self.lwe_dimension().0 + self.lwe_hat_dimension().0 + self.glwe_sk_num_bits();

        //And additionally, need bits to process the TUniform noises
        //(we need bound + 2 bits to sample a TUniform(bound))
        //For pk
        num_bits_needed += self.num_needed_noise_pk() * (self.lwe_hat_tuniform_bound().0 + 2);

        //For ksk
        num_bits_needed += self.num_needed_noise_ksk() * (self.lwe_tuniform_bound().0 + 2);

        //For bk
        num_bits_needed += self.num_needed_noise_bk() * (self.glwe_tuniform_bound().0 + 2);

        //For pksk
        num_bits_needed += self.num_needed_noise_pksk()
            * match self.get_pksk_destination() {
                Some(EncryptionKeyChoice::Big) => self.glwe_tuniform_bound().0 + 2,
                Some(EncryptionKeyChoice::Small) => self.lwe_tuniform_bound().0 + 2,
                _ => 0,
            };

        //For (de)compression keys
        // using let Some instead of unwrap
        if let Some(compression_key_tuniform_bound) = self.compression_key_tuniform_bound() {
            //For (de)compression private key
            num_bits_needed += self.compression_sk_num_bits();
            //For compression keys
            num_bits_needed +=
                self.num_needed_noise_compression_key() * (compression_key_tuniform_bound.0 + 2);
            //For decompression keys
            num_bits_needed +=
                self.num_needed_noise_decompression_key() * (self.glwe_tuniform_bound().0 + 2);
        };

        num_bits_needed
    }

    fn total_triples_required(&self) -> usize {
        //Required for the "normal" BK
        let mut num_triples_needed = self.lwe_dimension().0 * self.glwe_sk_num_bits();

        //Required for the compression BK
        if let Some(comp_params) = self.compression_decompression_parameters {
            num_triples_needed += self.glwe_sk_num_bits()
                * (comp_params.packing_ks_glwe_dimension.0
                    * comp_params.packing_ks_polynomial_size.0)
        }

        self.total_bits_required() + num_triples_needed
    }

    fn total_randomness_required(&self) -> usize {
        //Need 1 more element to sample the seed
        //as we always work in huge rings
        let num_randomness_needed = 1;

        self.total_bits_required() + num_randomness_needed
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

    fn num_needed_noise_pk(&self) -> usize {
        self.lwe_hat_dimension().0
    }

    fn num_needed_noise_pksk(&self) -> usize {
        self.lwe_hat_dimension().0 * self.decomposition_level_count_pksk().0
    }

    fn num_needed_noise_ksk(&self) -> usize {
        self.glwe_dimension().0 * self.polynomial_size().0 * self.decomposition_level_count_ksk().0
    }

    fn num_needed_noise_bk(&self) -> usize {
        self.lwe_dimension().0
            * (self.glwe_dimension().0 + 1)
            * self.decomposition_level_count_bk().0
            * self.polynomial_size().0
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
        self.dedicated_compact_public_key_parameters.map_or(
            (<ClassicPBSParameters as std::convert::Into<PBSParameters>>::into(
                self.ciphertext_parameters,
            ))
            .try_into()
            .unwrap(),
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
        KSKParams {
            num_needed_noise: self.num_needed_noise_ksk(),
            noise_bound: NoiseBounds::LweNoise(self.lwe_tuniform_bound()),
            decomposition_base_log: self.decomposition_base_log_ksk(),
            decomposition_level_count: self.decomposition_level_count_ksk(),
        }
    }

    fn get_pksk_params(&self) -> Option<KSKParams> {
        match self.get_pksk_destination() {
            Some(EncryptionKeyChoice::Big) => Some(KSKParams {
                num_needed_noise: self.num_needed_noise_pksk(),
                noise_bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
                decomposition_base_log: self.decomposition_base_log_pksk(),
                decomposition_level_count: self.decomposition_level_count_pksk(),
            }),
            Some(EncryptionKeyChoice::Small) => Some(KSKParams {
                num_needed_noise: self.num_needed_noise_pksk(),
                noise_bound: NoiseBounds::LweNoise(self.lwe_tuniform_bound()),
                decomposition_base_log: self.decomposition_base_log_pksk(),
                decomposition_level_count: self.decomposition_level_count_pksk(),
            }),
            None => None,
        }
    }

    fn get_bk_params(&self) -> BKParams {
        BKParams {
            num_needed_noise: self.num_needed_noise_bk(),
            noise_bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
            decomposition_base_log: self.decomposition_base_log_bk(),
            decomposition_level_count: self.decomposition_level_count_bk(),
            enc_type: EncryptionType::Bits64,
        }
    }

    fn compression_sk_num_bits(&self) -> usize {
        if let Some(comp_params) = self.compression_decompression_parameters {
            comp_params.packing_ks_glwe_dimension.0 * comp_params.packing_ks_polynomial_size.0
        } else {
            0
        }
    }

    fn num_needed_noise_compression_key(&self) -> usize {
        if let Some(comp_params) = self.compression_decompression_parameters {
            self.glwe_dimension().0
                * self.polynomial_size().0
                * comp_params.packing_ks_level.0
                * comp_params.packing_ks_polynomial_size.0
        } else {
            0
        }
    }

    fn num_needed_noise_decompression_key(&self) -> usize {
        if let Some(comp_params) = self.compression_decompression_parameters {
            comp_params.packing_ks_polynomial_size.0
                * comp_params.packing_ks_glwe_dimension.0
                * (self.glwe_dimension().0 + 1)
                * self.polynomial_size().0
                * comp_params.br_level.0
        } else {
            0
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
            let ksk_num_noise = self.num_needed_noise_compression_key();

            let ksk_noisebound = if let DynamicDistribution::TUniform(bound) =
                comp_params.packing_ks_key_noise_distribution
            {
                NoiseBounds::CompressionKSKNoise(TUniformBound(bound.bound_log2() as usize))
            } else {
                panic!("We do not support non TUniform noise distribution for compression keys.",);
            };

            let bk_num_needed_noise = self.num_needed_noise_decompression_key();

            let bk_params = BKParams {
                num_needed_noise: bk_num_needed_noise,
                noise_bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
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
    fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_as_json(path, self)
    }

    fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_as_json(path)
    }

    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        self.regular_params.to_classic_pbs_parameters()
    }

    fn get_prefix_path(&self) -> String {
        let mut h = std::hash::DefaultHasher::new();
        let serialized = bincode::serialize(self).unwrap();
        serialized.hash(&mut h);
        let hash = h.finish();
        format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_true_{}",
            self.get_message_modulus().0,
            self.get_carry_modulus().0,
            hash
        )
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

    fn total_bits_required(&self) -> usize {
        //Need the bits for regular keygen
        self.regular_params.total_bits_required() +
        //And for the additional glwe sk
        self.glwe_sk_num_bits_sns() +
        //And for the noise for the bk sns
        self.num_needed_noise_bk_sns()
        * (self
            .glwe_tuniform_bound_sns()
            .0
            + 2)
    }

    fn total_triples_required(&self) -> usize {
        // Raw triples necessary for the 2 BK
        let mut num_triples_needed =
            self.lwe_dimension().0 * (self.glwe_sk_num_bits() + self.glwe_sk_num_bits_sns());

        //Required for the compression BK
        if let Some(comp_params) = self.regular_params.compression_decompression_parameters {
            num_triples_needed += self.glwe_sk_num_bits()
                * (comp_params.packing_ks_glwe_dimension.0
                    * comp_params.packing_ks_polynomial_size.0)
        }

        self.total_bits_required() + num_triples_needed
    }

    fn total_randomness_required(&self) -> usize {
        let num_randomness_needed = 1;

        self.total_bits_required() + num_randomness_needed
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

    fn num_needed_noise_pk(&self) -> usize {
        self.regular_params.num_needed_noise_pk()
    }

    fn num_needed_noise_ksk(&self) -> usize {
        self.regular_params.num_needed_noise_ksk()
    }

    fn num_needed_noise_pksk(&self) -> usize {
        self.regular_params.num_needed_noise_pksk()
    }

    fn num_needed_noise_bk(&self) -> usize {
        self.regular_params.num_needed_noise_bk()
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

    fn get_compression_decompression_params(&self) -> Option<DistributedCompressionParameters> {
        self.regular_params.get_compression_decompression_params()
    }

    fn num_needed_noise_compression_key(&self) -> usize {
        self.regular_params.num_needed_noise_compression_key()
    }

    fn num_needed_noise_decompression_key(&self) -> usize {
        self.regular_params.num_needed_noise_decompression_key()
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

    pub fn num_needed_noise_bk_sns(&self) -> usize {
        self.lwe_dimension().0
            * (self.glwe_dimension_sns().0 + 1)
            * self.decomposition_level_count_bk_sns().0
            * self.polynomial_size_sns().0
    }

    pub fn get_bk_sns_params(&self) -> BKParams {
        BKParams {
            num_needed_noise: self.num_needed_noise_bk_sns(),
            noise_bound: NoiseBounds::GlweNoiseSnS(self.glwe_tuniform_bound_sns()),
            decomposition_base_log: self.decomposition_base_log_bk_sns(),
            decomposition_level_count: self.decomposition_level_count_bk_sns(),
            enc_type: EncryptionType::Bits128,
        }
    }
}

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

/// Blokchain Parameters (with pfail `2^-64`), using parameters in tfhe-rs codebase
const BC_PARAMS_SAM : DKGParamsRegular = DKGParamsRegular {
    sec: 128,
    ciphertext_parameters: tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    dedicated_compact_public_key_parameters: Some((tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 )),
    compression_decompression_parameters: Some(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64),
    flag: true
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
    },
    dedicated_compact_public_key_parameters: Some((
        CompactPublicKeyEncryptionParameters {
            encryption_lwe_dimension: LweDimension(1024),
            encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            ciphertext_modulus: CiphertextModulus::new_native(),
            expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
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

/// This parameter set somewhat match the ones in [`distributed_decryption::tests::test_data_setup::TEST_PARAMETERS`]
/// Used for testing BK_SNS generation and Switch and Squash
pub const PARAMS_TEST_BK_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: DKGParamsRegular {
        sec: 128,
        ciphertext_parameters: ClassicPBSParameters {
            lwe_dimension: LweDimension(32),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(64),
            lwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(0)),
            glwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(0)),
            pbs_base_log: DecompositionBaseLog(21),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(8),
            ks_level: DecompositionLevelCount(4),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            max_noise_level: MaxNoiseLevel::from_msg_carry_modulus(
                MessageModulus(4),
                CarryModulus(4),
            ),
            log2_p_fail: -80., // dummy parameter
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Small,
        },
        compression_decompression_parameters: None,
        dedicated_compact_public_key_parameters: None,
        flag: true,
    },
    sns_params: SwitchAndSquashParameters {
        glwe_dimension: GlweDimension(2),
        glwe_noise_distribution: TUniform::new(0),
        polynomial_size: PolynomialSize(256),
        pbs_base_log: DecompositionBaseLog(33),
        pbs_level: DecompositionLevelCount(2),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
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
