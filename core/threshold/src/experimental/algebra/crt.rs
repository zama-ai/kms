use crypto_bigint::{NonZero, U1536};

use crate::experimental::algebra::levels::{
    CryptoModulus, GenericModulus, LevelEight, LevelEleven, LevelFifteen, LevelFive, LevelFour,
    LevelFourteen, LevelKsw, LevelNine, LevelOne, LevelR, LevelSeven, LevelSix, LevelTen,
    LevelThirteen, LevelThree, LevelTwelve, LevelTwo,
};

#[derive(Debug)]
pub(crate) struct LevelKswCrtRepresentation {
    pub(crate) value_level_one: LevelOne,
    pub(crate) value_level_two: LevelTwo,
    pub(crate) value_level_three: LevelThree,
    pub(crate) value_level_four: LevelFour,
    pub(crate) value_level_five: LevelFive,
    pub(crate) value_level_six: LevelSix,
    pub(crate) value_level_seven: LevelSeven,
    pub(crate) value_level_eight: LevelEight,
    pub(crate) value_level_nine: LevelNine,
    pub(crate) value_level_ten: LevelTen,
    pub(crate) value_level_eleven: LevelEleven,
    pub(crate) value_level_twelve: LevelTwelve,
    pub(crate) value_level_thirteen: LevelThirteen,
    pub(crate) value_level_fourteen: LevelFourteen,
    pub(crate) value_level_fifteen: LevelFifteen,
    pub(crate) value_level_r: LevelR,
}

const LEVEL_1_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0f2df64d47a7c90df836961e8b672da6c40b723a2338b9967a4cfc06f076a0415f8b336d4a87ff2b5b321d8f0412fba80375bb08e50eaaaf5f4511b2a0e792c0a0f0a54a5dc4a56b5513b79dd5bd4e201e522c9003ff23eb45a39698a50073aa160a9ba09c8a44ad21a7b5eac6dbd2fec36cbca9c0f5206478c728144499a7fc74726a506a9f91ed8f2a74c824c74b91e94b1598fb7cc98082f95266ced3cdebc6b415ec4393582c1b162a1cca2474fc71665d188780a24b2b4ab60d4f24adb8")) };

const LEVEL_2_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0a1ad8ac53edc50b051ff3e2d9b17935b1c736c35987ee028e585067d96cceacb05fd56433be326b0aaa3042993e25ff4a4c360e11081e4e7968c43870f2a6d2cb9f2b64969dd1e110381650854a022cb831d52c184a80bc98aa80edac7414c86bbb1486925cee73a3b57ab51ef1eb63d8678003dc9cc9b2b7e4f3f4de7be8e5f992904b69d6f802efe28ee9d31b5a678b87b41bd782b4b7404b2f9c20ef9894e9e4d5d3fe4b1b7add55d890e9314312ea21de50959bb5a996519afa55eb0606")) };

const LEVEL_3_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("05bd9e617898193988eaa91b561199433de8078e4dc96254f35fb6e8bd78245ef31b6578507c800c2ec84accf6beff71654de508da571e826bd51b2fad0347ecb2699bbec5507956d7a5f9b11c5b0ccd67cd4c27bbe5239173a81d1b2a7a8b040368a9da4478fa5bcbbb3d367abaf64f5a8c75eab474dcdfb11536cca1b6a46a857c72c65f1500504aa0a0ba1715065d85ce36a253b1c6437d769cbeb63fdc53ae928586b275eb21f79a1a2b777ac9902af7221244d9fd1aea03daf28642c222")) };

const LEVEL_4_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0330a7904672c505ff8a75765dfa370b6457e14317fb45085b7c371839ef882139717bd705c43f30ce65994a0be157fce4a946a0c4bda3c9ab6955e42b087a68fca64e4ae14872339f954517568a194ccd32974af5e81b111ebfe2499fadae101bdd636dc59f17d718c98e5945fadedf81ca11442a3bafc0f30955182da232f95bf6c943cee8e8c3e0afec8cb6305c660a9c30020f6ea8158d81cdfc0f79f9a0c4fab9ae402e4681fb345516c8100d15044975aa241ff723850d095dc7cf8412")) };

const LEVEL_5_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("05a16db29e17815beaea40e9302c94ad20413506873fd58da5229aa0b9c600f4d229b40d6c708614ee8562065a5898622f4d53cde7ed9fde8fa8e720c87c5bad0da28633d6b7f001c85eac7a19b5f9bc8ccffe1738bec0c8d7843d06591025616bd62081ec14af8e4828c40fa75fea246b6a1d0333e5bdd4a0db0f158290cc904cb0308ea0c8defad85cb5176efc17a79426a53fb2d38ab19035f0e39cdaace37027cc40ee6058af086bdf2b607295727032d0be51e6a7532961e92e2f5ef989")) };

const LEVEL_6_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0c3cbb4acf0130bc830096fbee229dc0c6e144f755f5e004d296e2128e355a7bfd0debbb2b673dd09ca38f2a57956df16e2437e252a70e0864066da6e2b9cbd5eda9b55ab6940f8bec15cd06d7f08e0bd27feec0004a3b9cfecf1e5fc787745cf154347178c654683231da5c8a918b32293451e0d7d9e0db60998d69a7d54f28f60cfd6180a403a49c88c77d1ab397e794316decc53ab9f3f646de5fe7ed46bd3361c701d728fe77eba0327b14bf3553fd9ef459cfdf52afb53066d605b299a3")) };

const LEVEL_7_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0ec44476fb0ac8d857546c40b8752de11a9ae341d40d4d1353c1eba1ab9bb6b42b788feeb96b9bfda4f2d80943f82f749c089e43949fbc49bb8b7c0b435fc9564ff0b0d00a408d23099f23e28b34660beb2ae3d7c6bd2e7ae6ff362629e8757cf14d3d1bb9335932d1645e8690aa9c6969110200af6581da4ad837fd10882d59fe25b7e8bc14b57040c24b93cbb58051384f436d88357a9e7cdc80ea6a2dfa6118dc67557348200e046e1da291f5e2a450bd638549af8da11942778f0ecab17f")) };

const LEVEL_8_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("07e761a29f88d4ea99930b6f998432e5a860997140e973d2e9fa1e90a5fddcb12670ac4d9486b97567e144c263b4d2cd0918d2bf334dc0b0677b032d2e2a33362ef68b1c19fd0985ada03d87747088583bbf6cb13a4b021443900d21afa1d80c6e71cb7b72c12d4a6ccc504542288cffbabe03025c3998e79b09511676e606f9f269e863a145339f7157e8c5dac18e3c9b9acc5488cb2088361d1e3a3482c737664596aa281777be017da124f7cc24295c9853f7ed59aba9792ca1e0afb750cf")) };

const LEVEL_9_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("090b27911cada4d26395a928d45b9a954f0f2dc6b99c7b5dc222914808752f8fd4d0774cbf9ba6bdf79a1ee9c5812cf0b0994b8e1bd67d4c8469371cc045bfe53c8130f18ca570d868e6b824da462313813ff164e3039527684809acb9d5d62536d0368ce87ec64aab63b842919a9b01dd8a98062af5eb0fbedf4e9012c2bbdf884bd95566fe7e6bb11e571fab6ea997576b78c7cb90bf830d46165ef45d5141a2d6f95fddc4a0c78406f9049a49d303ff02cdc47ede7a5404f1eee174d94c2b")) };

const LEVEL_10_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("09fdecead915c85741db8e6af1c72c3e60e59a191173f968941d4ea1ae42fd5e5eed7a382c9db4a0f3664eef5592e0fcd4c55b2272206439a68a35a6448da84cae47043bfe4b6c2be8494d48e075902b52b7cb1e5852f4821fad010201df9c4f3e07dc38ec4729da3095c247c86c9e5906d75ed74cb8253d05f477d31ed87cfd50f5a7b156cb5990ebb2ae0fb1db2a041fc451e74afef63209f716416094e999ffca66c97484f6466e495151f8adb2aa4bdc2186add32aa92f28c8cd3fa027f2")) };

const LEVEL_11_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0a13baeff7f690b1afeebc47a98a14b6a1af26a39652d871b66c6c1452ddb6dbc8036b66c0e6b09a8019c173b615163e365925cebc53a21ddbd0b25f84ca8169cfb82f61a623c3aa169720fcd5a18278ff24ccffe7153932ef5bc88525c1fe6b70ef69bc7fd0fd0e660fa63d187f03647b7f949b64992269f827d36399c0698816c994ca195d3b5abf9eb02702ddf8296a27990beb5e1cf4afe8603c133c75346ea38bd488be92fa3da43235d1aa5503ea8cc0f607bf4df25a1f4d2f4e866104")) };

const LEVEL_12_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0d5135def0176b60498d3f8de54795d32e7eec71136b0ff89376feb0471fdaf8520fcd8c1d6321e980d7f96568c04e559049ddc1e73ed9242213da9d931f4b6540d2412bdfa14712cae3ddf87a604d053d2f0acd25b10d157371ccda09ae024e581239b0f017d25e556a8d222ff8c4d3b9c29508696de78007146bb7463c7fe1e49e287fdd7f1fd17205afc8ab46d18db8d8621f4f969ad7ae4847b640b639c51d4c01a13d6b8bd1f2c7c5470ad162f3e2cc612d159977cf7cbcbbcd9a68f00f")) };

const LEVEL_13_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00c6190459d5fc98781ef67d0ae552f7c96cc1b028a84305f36525e89723e156e1373c2fc8bbfcfac705c9929f929819caabc921f6180013036a00056255d3e1d4dc60f6aa820748771342a8e71b9416f9d0a59b19b0e35b0aaa4a7f7a840ccae1153d7ff9a72b1d004a4fe0e23ad188769ce8addb551983d0b8523c45b3f247b914ae5f15805ad8e6e274eba09b8c90561e85a719c697005db96e8b95d4df3d741a87216ad251f4b7c45e9a4574155ca7c10a6d952b035008f1a22c92b24e4a")) };

const LEVEL_14_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("075f1f7a8cbef17d86ce5e79cf0b1357b825a3bc44b0e9f01996c702d946a1e3359c165da761cbcf3b3db116c13028bddd761f850802ac38eee28cdc2f115eed52e6c7b1bc3e1b07bc14d4e770b385ee8a8178b925a942fba23a60bcc969bc7dc166d855185a6d2712295b5ee86d931a4251874d62da43579cb77ca0d34f89df91a79102b9ebe12e513be55965823d6eb12c4fa0b5eeeedc0e215325f06b97e438f3717fc6c8c72971d25e369e1cd2b3aa4f89b0ae6932aa61ba4b8ef9cc1eaa")) };

const LEVEL_15_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0c3834396b5729c431ae9cd3b719a2f4c0dc22f7d349e74cfc42d87eb20b3fbabccc1884255e68e055de7b595179c1adc4e3eb6b2097906f075175468ae7acef628d85286a05567ce958d133ac04bf630e29af40ee0e320a49175977e83214c31c338cf7568b58606f772bad02b2e030001d95aa9db5600c0577cc6d3b1110c061ab9850e9333eb956585083d6af32f3c5111b86bda5dfd689fbc7500b2e6de34019ac41b5d09cd26e02bab866744fac740771883665ad82e99dc1c2b1d38bd7")) };

const LEVEL_R_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0f3e81f1854972d34f1150a44ced12560a742447a007112e60820898f81b81f4fc6e66f8f683c56827f9e7686685d8e7f700369fc363f63b9a1d4d902591a980af6bdb7aaa59c9c0613b0fbf4ca73346e8929350ffc00ad5bc0152da9ac1597d6b4878c73f07111323f7e5c0fcd0b38498a1790153490629a6c8a6ec8e1e1ce8ab682f3cd53bbb35f74ab4373e6bb62a3c020ec4120b7e299a4a92594bb3681cfd72bbcf1e0b279f6710ba4a9887657fd10404514edf4ee7c9a4091cca53b2a3")) };

pub(crate) fn to_crt(input: LevelKsw) -> LevelKswCrtRepresentation {
    let modulus_r: U1536 = LevelR::MODULUS.as_ref().into();
    let value_level_r = LevelR {
        value: GenericModulus((&input.value.0.rem(&NonZero::new(modulus_r).unwrap())).into()),
    };

    let modulus_one: U1536 = LevelOne::MODULUS.as_ref().into();
    let value_level_one = LevelOne {
        value: GenericModulus((&input.value.0.rem(&NonZero::new(modulus_one).unwrap())).into()),
    };

    let modulus_two = LevelTwo::MODULUS.as_ref().to_limbs()[0];
    let value_level_two = LevelTwo {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_two).unwrap())
                .into(),
        ),
    };

    let modulus_three = LevelThree::MODULUS.as_ref().to_limbs()[0];
    let value_level_three = LevelThree {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_three).unwrap())
                .into(),
        ),
    };

    let modulus_four = LevelFour::MODULUS.as_ref().to_limbs()[0];
    let value_level_four = LevelFour {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_four).unwrap())
                .into(),
        ),
    };

    let modulus_five = LevelFive::MODULUS.as_ref().to_limbs()[0];
    let value_level_five = LevelFive {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_five).unwrap())
                .into(),
        ),
    };

    let modulus_six = LevelSix::MODULUS.as_ref().to_limbs()[0];
    let value_level_six = LevelSix {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_six).unwrap())
                .into(),
        ),
    };

    let modulus_seven = LevelSeven::MODULUS.as_ref().to_limbs()[0];
    let value_level_seven = LevelSeven {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_seven).unwrap())
                .into(),
        ),
    };

    let modulus_eight = LevelEight::MODULUS.as_ref().to_limbs()[0];
    let value_level_eight = LevelEight {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_eight).unwrap())
                .into(),
        ),
    };

    let modulus_nine = LevelNine::MODULUS.as_ref().to_limbs()[0];
    let value_level_nine = LevelNine {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_nine).unwrap())
                .into(),
        ),
    };

    let modulus_ten = LevelTen::MODULUS.as_ref().to_limbs()[0];
    let value_level_ten = LevelTen {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_ten).unwrap())
                .into(),
        ),
    };

    let modulus_eleven = LevelEleven::MODULUS.as_ref().to_limbs()[0];
    let value_level_eleven = LevelEleven {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_eleven).unwrap())
                .into(),
        ),
    };

    let modulus_twelve = LevelTwelve::MODULUS.as_ref().to_limbs()[0];
    let value_level_twelve = LevelTwelve {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_twelve).unwrap())
                .into(),
        ),
    };

    let modulus_thirteen = LevelThirteen::MODULUS.as_ref().to_limbs()[0];
    let value_level_thirteen = LevelThirteen {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_thirteen).unwrap())
                .into(),
        ),
    };

    let modulus_fourteen = LevelFourteen::MODULUS.as_ref().to_limbs()[0];
    let value_level_fourteen = LevelFourteen {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_fourteen).unwrap())
                .into(),
        ),
    };

    let modulus_fifteen = LevelFifteen::MODULUS.as_ref().to_limbs()[0];
    let value_level_fifteen = LevelFifteen {
        value: GenericModulus(
            input
                .value
                .0
                .rem_limb(NonZero::new(modulus_fifteen).unwrap())
                .into(),
        ),
    };

    LevelKswCrtRepresentation {
        value_level_one,
        value_level_two,
        value_level_three,
        value_level_four,
        value_level_five,
        value_level_six,
        value_level_seven,
        value_level_eight,
        value_level_nine,
        value_level_ten,
        value_level_eleven,
        value_level_twelve,
        value_level_thirteen,
        value_level_fourteen,
        value_level_fifteen,
        value_level_r,
    }
}

pub(crate) fn from_crt(crt_rep: LevelKswCrtRepresentation) -> LevelKsw {
    let mut res = LevelKsw {
        value: GenericModulus((&crt_rep.value_level_one.value.0).into()),
    } * LEVEL_1_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_two.value.0).into()),
    } * LEVEL_2_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_three.value.0).into()),
    } * LEVEL_3_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_four.value.0).into()),
    } * LEVEL_4_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_five.value.0).into()),
    } * LEVEL_5_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_six.value.0).into()),
    } * LEVEL_6_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_seven.value.0).into()),
    } * LEVEL_7_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_eight.value.0).into()),
    } * LEVEL_8_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_nine.value.0).into()),
    } * LEVEL_9_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_ten.value.0).into()),
    } * LEVEL_10_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_eleven.value.0).into()),
    } * LEVEL_11_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_twelve.value.0).into()),
    } * LEVEL_12_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_thirteen.value.0).into()),
    } * LEVEL_13_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_fourteen.value.0).into()),
    } * LEVEL_14_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_fifteen.value.0).into()),
    } * LEVEL_15_CRT_COEF;

    res += LevelKsw {
        value: GenericModulus((&crt_rep.value_level_r.value.0).into()),
    } * LEVEL_R_CRT_COEF;

    res
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use super::*;
    use crate::{algebra::structure_traits::Sample, experimental::algebra::levels::LevelKsw};

    #[test]
    fn test_crt_dec_rec() {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = LevelKsw::sample(&mut rng);
        let crt_dec = to_crt(secret);
        let crt_rec = from_crt(crt_dec);
        assert_eq!(secret, crt_rec);
    }
}
