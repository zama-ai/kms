use serde::{Deserialize, Serialize};
use tfhe::shortint::{
    parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    },
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MessageModulus,
};

use crate::{
    execution::online::secret_distributions::TUniformBound,
    file_handling::{read_as_json, write_as_json},
    lwe::{CiphertextParameters, ThresholdLWEParameters},
};

#[derive(Clone, Copy, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct DKGParamsRegular {
    ///Security parameter (related to the size of the XOF seed)
    sec: u64,
    ///The lwe dimension (length of the secret key)
    l: LweDimension,
    ///The degree of the GLWE cyclotomic polynomial
    N: PolynomialSize,
    ///The glwe dimension (length of the secret key)
    w: GlweDimension,
    ///Log of the bound for the TUniform distribution in lwe ciphertexts
    b_l: TUniformBound,
    ///Log of the bound for the TUniform distribution in glwe ciphertexts
    b_wn: TUniformBound,
    ///Log of the base for the decomposition of the key-switch-key
    beta_ksk: DecompositionBaseLog,
    ///Number of levels for the decomposition of the key-switch-key
    nu_ksk: DecompositionLevelCount,
    ///Log of the base for the decomposition of the bootstrapping key
    beta_bk: DecompositionBaseLog,
    ///Number of levels for the decomposition of bootstrapping key
    nu_bk: DecompositionLevelCount,
    ///In-extenso (**NOT** log) message modulus
    message_modulus: MessageModulus,
    ///In-extenso (**NOT** log) carry modulus
    carry_modulus: CarryModulus,
    ///States whether we want compressed ciphertexts
    flag: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct DKGParamsSnS {
    regular_params: DKGParamsRegular,
    ///**Switch-and-Squah Output domain** The degree of the GLWE cyclotomic polynomial
    o_N: PolynomialSize,
    ///**Switch-and-Squah Output domain** The glwe dimension (length of the secret key)
    o_w: GlweDimension,
    ///**Switch-and-Squah Output domain** Log of the base for the decomposition of the SnS-bootstrapping key
    o_beta_bk: DecompositionBaseLog,
    ///**Switch-and-Squah Output domain** Number of levels for the decomposition of the SnS-bootstrapping key
    o_nu_bk: DecompositionLevelCount,
    ///**Switch-and-Squah Output domain** Log of the bound for the TUniform distribution in glwe ciphertexts
    o_b_wn: TUniformBound,
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
    fn glwe_dimension(&self) -> GlweDimension;
    fn lwe_tuniform_bound(&self) -> TUniformBound;
    fn glwe_tuniform_bound(&self) -> TUniformBound;
    fn polynomial_size(&self) -> PolynomialSize;
    fn glwe_sk_num_bits(&self) -> usize;
    fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog;
    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog;
    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount;
    fn decomposition_level_count_bk(&self) -> DecompositionLevelCount;
    fn num_needed_noise_pk(&self) -> usize;
    fn num_needed_noise_ksk(&self) -> usize;
    fn num_needed_noise_bk(&self) -> usize;
    fn to_dkg_params(&self) -> DKGParams;
}

impl DKGParamsBasics for DKGParamsRegular {
    fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_as_json(path, self)
    }

    fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_as_json(path)
    }

    fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        ClassicPBSParameters {
            lwe_dimension: self.l,
            glwe_dimension: self.w,
            polynomial_size: self.N,
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            lwe_modular_std_dev: StandardDev(1e-37),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            glwe_modular_std_dev: StandardDev(1e-37),
            pbs_base_log: self.beta_bk,
            pbs_level: self.nu_bk,
            ks_base_log: self.beta_ksk,
            ks_level: self.nu_ksk,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Small,
        }
    }

    ///This function returns a path based on
    /// - [DKGParams::message_modulus]
    /// - [DKGParams::carry_modulus]
    ///
    ///__Thus any two sets of parameters that share these characteristics
    ///will have the same prefix path, which may result in a clash.__
    fn get_prefix_path(&self) -> String {
        format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_false",
            self.message_modulus.0, self.carry_modulus.0
        )
    }

    fn get_sec(&self) -> u64 {
        self.sec
    }

    fn get_message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }

    fn get_carry_modulus(&self) -> CarryModulus {
        self.carry_modulus
    }

    fn total_bits_required(&self) -> usize {
        //Need bits for lwe sk, glwe sk
        let mut num_bits_needed = self.lwe_dimension().0 + self.glwe_sk_num_bits();

        //And additionally, need bits to process the TUniform noises
        //(we need bound + 2 bits to sample a TUniform(bound))
        //For pk
        num_bits_needed += self.num_needed_noise_pk() * (self.lwe_tuniform_bound().0 + 2);

        //For ksk
        num_bits_needed += self.num_needed_noise_ksk() * (self.lwe_tuniform_bound().0 + 2);

        //For bk
        num_bits_needed += self.num_needed_noise_bk() * (self.glwe_tuniform_bound().0 + 2);

        num_bits_needed
    }

    fn total_triples_required(&self) -> usize {
        let num_triples_needed = self.lwe_dimension().0 * self.glwe_sk_num_bits();

        self.total_bits_required() + num_triples_needed
    }

    fn total_randomness_required(&self) -> usize {
        //Need 1 more element to sample the seed
        //as we always work in huge rings
        let num_randomness_needed = 1;

        self.total_bits_required() + num_randomness_needed
    }

    fn lwe_dimension(&self) -> LweDimension {
        self.l
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.w
    }

    fn lwe_tuniform_bound(&self) -> TUniformBound {
        self.b_l
    }

    fn glwe_tuniform_bound(&self) -> TUniformBound {
        self.b_wn
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.N
    }

    fn glwe_sk_num_bits(&self) -> usize {
        self.N.0 * self.w.0
    }

    fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog {
        self.beta_ksk
    }

    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.beta_bk
    }

    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.nu_ksk
    }

    fn decomposition_level_count_bk(&self) -> DecompositionLevelCount {
        self.nu_bk
    }

    fn num_needed_noise_pk(&self) -> usize {
        self.lwe_dimension().0
    }

    fn num_needed_noise_ksk(&self) -> usize {
        self.w.0 * self.N.0 * self.nu_ksk.0
    }

    fn num_needed_noise_bk(&self) -> usize {
        self.l.0 * (self.w.0 + 1) * self.nu_bk.0 * self.N.0
    }

    fn to_dkg_params(&self) -> DKGParams {
        DKGParams::WithoutSnS(*self)
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
        format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_true",
            self.regular_params.message_modulus.0, self.regular_params.carry_modulus.0
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
        let num_triples_needed =
            self.lwe_dimension().0 * (self.glwe_sk_num_bits() + self.glwe_sk_num_bits_sns());

        self.total_bits_required() + num_triples_needed
    }

    fn total_randomness_required(&self) -> usize {
        let num_randomness_needed = 1;

        self.total_bits_required() + num_randomness_needed
    }

    fn lwe_dimension(&self) -> LweDimension {
        self.regular_params.lwe_dimension()
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.regular_params.glwe_dimension()
    }

    fn lwe_tuniform_bound(&self) -> TUniformBound {
        self.regular_params.lwe_tuniform_bound()
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

    fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.regular_params.decomposition_base_log_bk()
    }

    fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.regular_params.decomposition_level_count_ksk()
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

    fn num_needed_noise_bk(&self) -> usize {
        self.regular_params.num_needed_noise_bk()
    }

    fn to_dkg_params(&self) -> DKGParams {
        DKGParams::WithSnS(*self)
    }
}

impl DKGParamsSnS {
    pub fn glwe_tuniform_bound_sns(&self) -> TUniformBound {
        self.o_b_wn
    }

    pub fn polynomial_size_sns(&self) -> PolynomialSize {
        self.o_N
    }

    pub fn glwe_dimension_sns(&self) -> GlweDimension {
        self.o_w
    }

    pub fn glwe_sk_num_bits_sns(&self) -> usize {
        self.o_N.0 * self.o_w.0
    }

    pub fn decomposition_base_log_bk_sns(&self) -> DecompositionBaseLog {
        self.o_beta_bk
    }

    pub fn decomposition_level_count_bk_sns(&self) -> DecompositionLevelCount {
        self.o_nu_bk
    }

    pub fn num_needed_noise_bk_sns(&self) -> usize {
        self.regular_params.l.0 * (self.o_w.0 + 1) * self.o_nu_bk.0 * self.o_N.0
    }
    pub fn to_threshold_parameters(&self) -> ThresholdLWEParameters {
        let input_ciphertext_parameters = CiphertextParameters {
            lwe_dimension: self.lwe_dimension(),
            glwe_dimension: self.glwe_dimension(),
            polynomial_size: self.polynomial_size(),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            lwe_modular_std_dev: StandardDev(1e-37),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            glwe_modular_std_dev: StandardDev(1e-37),
            pbs_base_log: self.decomposition_base_log_bk(),
            pbs_level: self.decomposition_level_count_bk(),
            ks_base_log: self.decomposition_base_log_ksk(),
            ks_level: self.decomposition_level_count_ksk(),
            message_modulus_log: self.regular_params.message_modulus,
            usable_message_modulus_log: self.regular_params.message_modulus, //TODO: NEED TO MAP THESE PARAM STRUCTURE CORRECTLY WITH TFHERS
            ciphertext_modulus: CiphertextModulus::new_native(),
        };
        let output_ciphertext_parameters = CiphertextParameters {
            lwe_dimension: self.lwe_dimension(),
            glwe_dimension: self.o_w,
            polynomial_size: self.polynomial_size_sns(),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            lwe_modular_std_dev: StandardDev(1e-37),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            glwe_modular_std_dev: StandardDev(1e-37),
            pbs_base_log: self.decomposition_base_log_bk_sns(),
            pbs_level: self.decomposition_level_count_bk_sns(),
            ks_base_log: self.decomposition_base_log_ksk(),
            ks_level: self.decomposition_level_count_ksk(),
            message_modulus_log: self.regular_params.message_modulus,
            usable_message_modulus_log: self.regular_params.message_modulus, //TODO: NEED TO MAP THESE PARAM STRUCTURE CORRECTLY WITH TFHERS
            ciphertext_modulus: tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus::<
                u128,
            >::new_native(),
        };

        ThresholdLWEParameters {
            input_cipher_parameters: input_ciphertext_parameters,
            output_cipher_parameters: output_ciphertext_parameters,
        }
    }
}

///Small-ish parameter set with 2 bit plaintext modulus
///and 2 bit carry modulus and no Switch and Squash
pub const PARAMS_P32_SMALL_NO_SNS: DKGParams = DKGParams::WithoutSnS(DKGParamsRegular {
    sec: 128,
    l: LweDimension(1024),
    N: PolynomialSize(2048),
    w: GlweDimension(1),
    b_l: TUniformBound(1),
    b_wn: TUniformBound(1),
    beta_ksk: DecompositionBaseLog(6),
    nu_ksk: DecompositionLevelCount(3),
    beta_bk: DecompositionBaseLog(21),
    nu_bk: DecompositionLevelCount(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    flag: true,
});

//Small-ish parameter set with 1 bit plaintext modulus
//and 1 bit carry modulus and no Switch and Squash
pub const PARAMS_P8_SMALL_NO_SNS: DKGParams = DKGParams::WithoutSnS(DKGParamsRegular {
    sec: 128,
    l: LweDimension(512),
    N: PolynomialSize(512),
    w: GlweDimension(1),
    b_l: TUniformBound(1),
    b_wn: TUniformBound(1),
    beta_ksk: DecompositionBaseLog(11),
    nu_ksk: DecompositionLevelCount(1),
    beta_bk: DecompositionBaseLog(16),
    nu_bk: DecompositionLevelCount(1),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    flag: true,
});

///This parameter set somewhat match the ones in [`distributed_decryption::tests::test_data_setup::TEST_PARAMETERS`]
///Used for testing BK_SNS generation and Switch and Squash
pub const PARAMS_TEST_BK_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: DKGParamsRegular {
        sec: 128,
        l: LweDimension(32),
        N: PolynomialSize(64),
        w: GlweDimension(1),
        b_l: TUniformBound(0),
        b_wn: TUniformBound(0),
        beta_ksk: DecompositionBaseLog(8),
        nu_ksk: DecompositionLevelCount(4),
        beta_bk: DecompositionBaseLog(21),
        nu_bk: DecompositionLevelCount(1),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        flag: true,
    },
    o_N: PolynomialSize(256),
    o_w: GlweDimension(2),
    o_beta_bk: DecompositionBaseLog(33),
    o_nu_bk: DecompositionLevelCount(2),
    o_b_wn: TUniformBound(0),
});

///This parameter set corresponds to P8 in NIST
///(except for the noise part which is set to be 3)
pub const PARAMS_P8_REAL_WITH_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: DKGParamsRegular {
        sec: 128,
        l: LweDimension(1024),
        N: PolynomialSize(512),
        w: GlweDimension(3),
        b_l: TUniformBound(3), //NOISE ISNT REAL
        b_wn: TUniformBound(3),
        beta_ksk: DecompositionBaseLog(6),
        nu_ksk: DecompositionLevelCount(2),
        beta_bk: DecompositionBaseLog(18),
        nu_bk: DecompositionLevelCount(1),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        flag: true,
    },
    o_N: PolynomialSize(1024),
    o_w: GlweDimension(4),
    o_beta_bk: DecompositionBaseLog(24),
    o_nu_bk: DecompositionLevelCount(3),
    o_b_wn: TUniformBound(3),
});

///This parameter set corresponds to P32 in NIST
///(except for the noise part which is set to be 3)
pub const PARAMS_P32_REAL_WITH_SNS: DKGParams = DKGParams::WithSnS(DKGParamsSnS {
    regular_params: DKGParamsRegular {
        sec: 128,
        l: LweDimension(1024),
        N: PolynomialSize(2048),
        w: GlweDimension(1),
        b_l: TUniformBound(3), //NOISE ISNT REAL
        b_wn: TUniformBound(3),
        beta_ksk: DecompositionBaseLog(6),
        nu_ksk: DecompositionLevelCount(3),
        beta_bk: DecompositionBaseLog(21),
        nu_bk: DecompositionLevelCount(1),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        flag: true,
    },
    o_N: PolynomialSize(2048),
    o_w: GlweDimension(2),
    o_beta_bk: DecompositionBaseLog(24),
    o_nu_bk: DecompositionLevelCount(3),
    o_b_wn: TUniformBound(3),
});
