use tfhe::shortint::{
    parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    },
    CarryModulus, MessageModulus,
};

use crate::execution::endpoints::keygen::{DKGParams, TUniformBound};

///Small-ish parameter set with 2 bit plaintext modulus
///and 2 bit carry modulus and no Switch and Squash
pub const PARAMS_P32_SMALL_NO_SNS: DKGParams = DKGParams {
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
    o_N: Some(PolynomialSize(2048)),
    o_w: Some(GlweDimension(2)),
    o_beta_bk: Some(DecompositionBaseLog(24)),
    o_nu_bk: Some(DecompositionLevelCount(3)),
    o_b_wn: Some(TUniformBound(1)),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    flag: true,
    o_flag: false,
};

//Small-ish parameter set with 1 bit plaintext modulus
//and 1 bit carry modulus and no Switch and Squash
pub const PARAMS_P8_SMALL_NO_SNS: DKGParams = DKGParams {
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
    o_N: Some(PolynomialSize(512)),
    o_w: Some(GlweDimension(4)),
    o_beta_bk: Some(DecompositionBaseLog(23)),
    o_nu_bk: Some(DecompositionLevelCount(3)),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    o_b_wn: Some(TUniformBound(1)),
    flag: true,
    o_flag: false,
};

///This parameter set somewhat match the ones in [`distributed_decryption::tests::test_data_setup::TEST_PARAMETERS`]
///Used for testing BK_SNS generation and Switch and Squash
pub const PARAMS_TEST_BK_SNS: DKGParams = DKGParams {
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
    o_N: Some(PolynomialSize(256)),
    o_w: Some(GlweDimension(2)),
    o_beta_bk: Some(DecompositionBaseLog(33)),
    o_nu_bk: Some(DecompositionLevelCount(2)),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
    o_b_wn: Some(TUniformBound(0)),
    flag: true,
    o_flag: true,
};

///This parameter set corresponds to P8 in NIST
///(except for the noise part which is set to be 3)
pub const PARAMS_P8_REAL_WITH_SNS: DKGParams = DKGParams {
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
    o_N: Some(PolynomialSize(1024)),
    o_w: Some(GlweDimension(4)),
    o_beta_bk: Some(DecompositionBaseLog(24)),
    o_nu_bk: Some(DecompositionLevelCount(3)),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    o_b_wn: Some(TUniformBound(3)),
    flag: true,
    o_flag: true,
};

///This parameter set corresponds to P32 in NIST
///(except for the noise part which is set to be 3)
pub const PARAMS_P32_REAL_WITH_SNS: DKGParams = DKGParams {
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
    o_N: Some(PolynomialSize(2048)),
    o_w: Some(GlweDimension(2)),
    o_beta_bk: Some(DecompositionBaseLog(24)),
    o_nu_bk: Some(DecompositionLevelCount(3)),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    o_b_wn: Some(TUniformBound(3)),
    flag: true,
    o_flag: true,
};
