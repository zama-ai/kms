use crypto_bigint::{NonZero, U1536};

use super::bgv_algebra::{
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

const LEVEL_1_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000001edc0e1a249280474c7312b8fea1ad485e2a8e704fff5b277579421b7880415c500b9c1689120b1c14e2323c4376cb2b177bc1455a13a1b14bad287b3d2b4fcfee3d90ceaea86300b968543eba023d1ebbb93fbcda35b40e287090cc46e802abdf9d97e42bb4175cd72df6808d3724f20514e5bb70e828117eeda58a5291a2830474bfd2f415276b717761f7c0c225a636466b396be851485e791a76ff8d9f9fd5bb2dee9bfcf0eecd43a4f86aab982b78f45c1ca66b2b74f039597b5e")) };

const LEVEL_2_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000001d3318fe0dafb9a605f46e962d6f677918f5e50a1b9cd60cfa21dbd10ad6d9c9a67e9f3274d4f67ee4a83191cb66ed69255882310ec80423df6005ee05f2f02b117e708ede2c9fe251a3db775eb7395f2c6b6e15ef8be44c70eacbf1a70b6c5c94b15b895c8921a94c3fa56354d87442b3ba8539cc700eb4f279d60103a5d391d711aa2888a86cf930fb66c0a46f6d37e04f99e898df8c0bef3281d1d6b629338958665c15309a73d0731d67e9a3be9086cc534ba2f82c8168fd1a24d9")) };

const LEVEL_3_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("000000106081399b903c9e2389cf1c9565d19e211e38e314a425d5d86ffc6f0f59648d10dcbbda1b921b040aa5c67cde97500821dc14374a05a9b782ab7a83cccd6099bf28772132f9d726d4a8b09c439692f08bb0fc54cc1b05c68f3d6f1c1e7bd174a1d5db1aa01d833ffebadf4e7c3f1b8d7376a451674ccd5aec7bc6b3eacbe97117b8cbf8ad70c56e80151fd1b5b83a75200b30767b6ee44f0e38a00ee61abcec0bdd53a23db973053dc333aa44f023a54d2e23b4af8e2751346a6c194c")) };

const LEVEL_4_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("000000006f9218d5b767e6ae6c1ef9ad2018f2f75c987178487970ab0fad7b9b31ecda1348ea4d8dd09d7dd292cff0c137158361c3ba889dff12d2d8b1a74468b3bb31bb237827aa7fcc2adb8e43645fcfff68b664301b137b84a13042ed093d1713d11080a156809b9ae4a91cac741c3a83dd59c2c43fabd17dddc3941956f4db17ce452b5f4b76e2404641968016c6bb809675a6c50b73862b3b73f16a7ecd00522c84ea0c46819426e27ad5030ff02af753763bbcd22ddd0c1319d1b6478f")) };

const LEVEL_5_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000001131b01bc124d2c01277b79dd520acba3a4fe6303d0a12451852ebe4fe3cb64fc87f84764d353c09139694d7738ea815249b2bfc7e680d37239aac6bc3091bff9869f7c9730d0744ebb3a744fd57bb3915dc8ca083f17ab196f921096051facaf6575a4db153159fe90a79239c8246ed5febb7489b65826def377822140b530e6db46c8511923b3d873b1ab982d2fb8423ab58b0cfbc211b23cc94807c7935b55731ede2c3d3b5d843aa4ccb424d0eaad50bb7e92ba13170e84c28cd78")) };

const LEVEL_6_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000e79353441406336fb4a0a263f6ebe61a8e0a3a26893c00e531408433a681003713a2fd4d150cb6f9017cdc926a59fb352945b7fe64eafcd9d3b48e9a8e91ff1f5d8d1b7dbcd964e0eb7d3e672bfdd497af1311d29fec738edd37a23cad67a9cdad156792f58ad4c21ed43af58853adcde913e448d678686bef11b80f586a695f948db055a469c7185293d2fc6d7f4a3f9462c70bc2029b31501c32ae99cfcd482c70e9a4f674461a2423d71178061e5203fa396830095ffca7a0bcc47")) };

const LEVEL_7_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000357f937946768d4a25aed281d09c22b3d0176c7502acaa70070f3ace80c6817b32c72c5a1bb4dbd0cd87b0d5331a1aef41e1f5db58847d467650dc81f8f9f7f1b6703130d5a3fa1bb060b9af7e887e8291ee80b990297f88bf4e0be92ea272434194e21b4e6754551be6ec03935842b94f38b19c54a6095cf19a5c8d070f768e3e9766f27f1a79496b41ecbf7ff6a148594bfb43d20fcc60b2f933ff8f90818d67dbf40f60c998d56b7d98af3498e8681376d875cbc2253fe36a4e6ae")) };

const LEVEL_8_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000dd46357f248c481f9a96791aaf12941d7e81f177450380a4728141beaf01b45192fcdd5449e6ba5fb53be187a101439acd48e9561eda5e800b27f9761510d3e7543ec3e50f13674ce60e16020123fa16356f1b459f198c182fd47788c3094fc04ed19badd06bc07f94e149e702b6847aede4c5d6304eeba55012490cfcbe2377459694866cae523fff1a465f9f0cbb75ca821b48b9fa4da266a55e16349aef8341cc0d5a0be866db07722059a7d16709a7696385853814de3ad5cdb48")) };

const LEVEL_9_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000007c21ce7ce9ec9ccb91ce9ae8cd52138cc45137a9d56e794b0cf19f2a3d7cde5ee287c80206ded786830b622920c50eac745e551e358215070ab933b2ad422990bbc1bb746be360f7f1c6ed10e1fdc932eacf362a357bc98a2d6dc8f36f64654558f8a5a3d59e3b0daa390820867966354ae4c6e502f343c7d71f5b3fe0f7fd8cafe60d99dbbc99d2d8f731945b9f4d53ca99b6f278ebafe4852282f0c9f6cf9324b62808626b44aa485698ba660be71d9216bb10ff635b8c4b14bf637")) };

const LEVEL_10_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000005eaeab375f761b1f3dd27129f7129c0f3e6b6da3ca41df47ce19d9d8650fffc5b37d7385e2636bb5dc48be481e2a8c222e685ee0b8df9751b5256e90a1862f37d70940dc1a0bfb913ec1c93465cf29340a9ff0e8e1e810d0cc4061dff08d7e667ff3e780a0d68d364fe3ed11fdd618101821dce1061257d2a966f363201cb873da34f8dd6fc8ad52edc5b070ea94b2beb850f3b19ae3fad09902ef29ce429de9b6ebc70e1cc984ae511cebfb8b127eaafa38bb5f048be8934c54de5db")) };

const LEVEL_11_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("000000122ee28de25ee43ea1340645b496ee81196478eba05824e874a907759311de54ce3f37a0ca4fd9032bdcd765802e288f14b50076c00d9f94b85161d82fb2374a3997a48b3eee11b5953911aa4054455f8b46b43a0de6f0e665c952739908eefde8a2492a01b4d0c320fb109c6fffa56d60fa48d136655a83a66b5c77356b71fed967af5ad10e741a46ff83a3f83660b177236ad00f415f465f469aa7e623dd658810a55e1ea13707d45f65f65bf50175b392c83446e5a4d7b7f2a7e9e8")) };

const LEVEL_12_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000001a68a0e9c0ddb47a458a6e0254faae1947625b44731d93a704d33cdb6455d2e56c4035c313ad4da1e3a646d2a8c065b99001d7853fe53ded7c5cf5152c3b259dc7d12e0f63d07ff57820292da4a6a1f6edd85758f9cb6ff356b2e5429da1caaefe712c981ad218d8bc215144557fdbec3a503585d7eeb0d084b3f60189974682ebd2c56eba3accabecc7a35c139544a009057e1ee48998017893a785ac978a96f0bc866cce39c4716026d4e602c25d3e9a5b90c5e21a4b38e6d4704b67")) };

const LEVEL_13_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000001acfc6b045076749ca775612b5f535cfb14a718eaca6fd59e8f73f372b744e46f4706877e591fca61aa53038c361d29cd2b561f28d6f2f5c0693e17b985f9254a637d4f306d737e1a3716a8e412085b18ba076395090ae730e1a4be631d173ed3103ea04e17a72dd3db5cb86ef941d110b7bdd11eef015ad6129f98d5759074f6d105dc1d79253102170f7533195acb0dcc4529f1ae3823eb22746e1f3461fd0be3347acf911e9e104dc75d58f44e07d22b68614a5ab39416838b28498")) };

const LEVEL_14_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000003133c9576a76d4190c9bba35a34bede9ead8a454bee667f9df2c1be9a7b3e9639966e9f930679e615b9fcb3699b4175a0cd21c15da6f352c68e450c7c7878941356acd084130f60fb641ae972292e40d683655d20bd82c84f17049a49d6880f106cda4e0752901fca46ff50bb1fa4efa0998bff170d93feee97c2526bbd46e27308d15f6ba6782ead3f5f2edc24109680f466e9567ea0784c365da2c63572d70c497d39a66827fc491004e3627ee74285ab4c4a48dfd0e72348a86516")) };

const LEVEL_15_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000b61d940aa766044db5c4d208321978a6cff20c885b7b1fe8d2bec6940976713c6cd2af0594e4ae9483eb3d36444d75d933f194aac0985b4acb485c36786660335482718224147c039ac6262abb9c1123a536e827ff9094674892c1bf49a7d81fe916492e2adac4e4370c2ed10b315f4feec64d69583f565bdd3232210f54f606c12e04b9014c6394d368339f9c5d57e3c2b3269b2ffe90aa1e846f99a66a3f052492f7f28c660153963d9acc8c6c0499fca331d62a6e82ff8f6533f5e")) };

const LEVEL_R_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000001ca6b3f467064e15fd68d18ce7ce3c4c6245b53c7b5570db1f020e843b57529b07378c8a9a504bfd8d7e5ce371ea07441ae92afef99549292042baeaf3f34df9e804bd88a9adcf3885b5f54d6199c739d40b6aa14df069771275ba57095f4182bbc56d322cb95fdf78ba3dcd3fd63b84e83d438bfebdff27d845767e8df75dafd1db6fb507dbcbf6e387491eaa0f8911e1a54add4d02d36e635f8f3f5df724e43d7b324979b1f5ef4e24ea8a8305a7e38f253940a947bd004e9f8568d4")) };

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

    use crate::{
        algebra::structure_traits::Sample,
        experimental::{
            bgv_algebra::LevelKsw,
            crt::{from_crt, to_crt},
        },
    };

    #[test]
    fn test_crt_dec_rec() {
        let mut rng = AesRng::seed_from_u64(0);
        let secret = LevelKsw::sample(&mut rng);
        let crt_dec = to_crt(secret);
        let crt_rec = from_crt(crt_dec);
        assert_eq!(secret, crt_rec);
    }
}
