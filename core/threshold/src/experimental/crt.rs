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

const LEVEL_1_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000004c041b0ccb0f8696a39b3d01d65280cc0c2291342cd0c42b2bc4fd76671412ed077e3603affa4866045c8775a51ee30b3fd84f46583b6a2f3de934cb649b8a95ec760df5ce76a828681cb6c5274d66e7450568c3efdeaa51340a234c9783ac5a4c068ab9881b20d9839ffb26c999373d0b8ea6526f7c09d67df06d075d861f76d57743d1f51a89fc409145bff88f03697edb6f5a301f903426c7ee4b94c9ff95d109cc06aaf3a3060ff853455038162716778c03cebe37891e7b")) };

const LEVEL_2_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000003326fb70e1d7f6c68db56456b3ddae618e01f6d2bdc2d0070d4f5543068a57a305a2c4cab2c116c2904823f29ade382362d3bfcdf39084e2781b9a15e38cf6cda3a0b128d6843b4d986c9cb23bd3dd560fb28ba3240a98f31ad9fc18d870c2053ba729d5f5cd944480ab9ff99a031c44cf52e37a26f5d781deb5e98ce7d5ce3fe04558afbcf7458e245277192d171d5d2e69c07ff7437f87291de5f7c01b8ac8cb8b2065020fe2bb795941d263eca21ca6e4ea5fe3e478a3b868")) };

const LEVEL_3_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000000000002e8bb0368dd0d39daf0acb1b548a063d609a5bd39a6313f4c0d8c02dfd53f139f29894c26fe301611e3c6f46f911242c4c03272924c50258922cfac572ca420944d5d817bc860eb82c7d477fe9f494c2a4710eb9c2b66f6f22a1887de1493b9cc9089ffb99fd6130f383905a837bf77e8b11e9eb136f6f581315ff514ca1fe30e7da97ed04f70bd5d7a50faf10d3fd34401dcd289fae084050252499f83a1f43f45d2257eaec6c13d34d5ca46e3182c19a7afc1509e23119ab2")) };

const LEVEL_4_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000003a5683fb67d8cc4e24f8a07f35a82c8321403199e2394b8d5d684e0bc6d6b9f50dc292c4e536176be26355904333452a4a61ea0708d598cb0a03e68d428d7dc2f514e8b69597eb80ad0c2b4acae1c6ceec19bf6992bf43ca60817ea252feac511c6d40fecb91c84bf9608342868c261c7c84a482a8062e47f95489f6f73aee58a4d6574f3cd2b622907b22a59b6e0f5c0b15bb05df023bc279bcc44d5d82f2828006c7146c0e9c618824e84548ed7f17bb0033cd310a59fd7699")) };

const LEVEL_5_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000000098095630325b7b3962456a052b0a40686faca525e95ec80338f4865d2543b44861df4555b61d50a8679719e212999cf833b0ce3069db175490a352c05398f7388ec07479551f76ca6bce46d09f32377b8f58fe60e9f7dd7d38a81bee3eb4aeb55d1ab8caf010d396dc2b2690389d72579acfc4904aa18effaedcea8f0388912291264f46e46d93d3d5332f91d01db998c5925e0912985af4bccda00aa7e3860fe477a15ccfe68d7315ae651985d45a38cd55e569d19332d6be")) };

const LEVEL_6_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000003758a56a9ab180a9fbc5a0f692dd2198dc94251199dea2af4f6415994b1d3daa11418276253a408871f92417aca4a76e070a6844d4b2af5ec0fdcfbb619c7426b5c3145cc040f90f98dc2874b24f17fa5898a8253cddc0038708eef3573f61cc8283fdf4f6fd284dd8eecde07de1b446e29d4006601a73a48983171247faef80b62c9882fadec15bfe95d90d8c4946027672bc87c25514f3cd62d02385b654595a5cddac6874e892e2a53b63324fa0a04c7e1a5cf1ff754a4bb3")) };

const LEVEL_7_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000000000031938ed5b1bac1e813097a5eeab7cd395c7d03b607f17273b186c098c6867263742e6fd77bf36f6ea2ec26b8068ad07f1dc0e4f572e10eb079b0edc684a7f70de11ed5ce6cabc25e6c1aff1860afeb35a5c2303c95d67fbcff17fe471ba7a11c703eabe63c24c12e373347472b1ba85d52037380d6a1aad6306fac637d61f4c8c43f6edafabf0f17ed27bd2f97e03cdcd3e12674695100cd0145e7f683b9423e7a6e6d4e9eff883dc697777da16babbbb1d0872718a1090d2c7b")) };

const LEVEL_8_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000003fd51562600fdd962e3c37cba601fd43aeb4549af74d1863169d49970acef946ac97b35ba100aa4579d24ae77734f6933083286de301a7263e34e04db783f58ecbd71e68cceae5b16f69a1780bb5875bfd9ed2c31d0fa7abe410f70160cc01241ea57c93f9990cf4fe6417d9a5c69009b15df1f1c1f6124173e214f102448be1755790e7e2c05280cd983a60ece5a9ac005a945bd26035afbc4dd9e08b0ab46831a1f9dbf027f214707caa13aad56ca2c5c69362bedae54f88c8")) };

const LEVEL_9_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000000000016807f5761529612e81be9ed56d6b00667248094f7953aff3478f0a592180d421b8fd1149ee7068a40881c7d7b754cc232ed3c2c076c27845b5fad9d9515086ac2582736791672e130b7e17b280aeb55c3f3d58b6884812306904123e2e598085697a787c7204abee5aeeee15718f32efb384377d85182efb8bde2e7c23c65434fd216319edc8c796b57654b28480c67a8976eab42e2011c11f921ae4da99db1774ae476a468e13187db844e7cb915ab22c86a943944424b5bdf")) };

const LEVEL_10_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000001cbea84fa4bd7da3f5be0ee9712d3865238813b42c1ecc07935db16105cbb46d0db5d5dc0ef09406467341c478d25def4a983fe52c109b7bebdcb316194906130d05c3e60fd57c2e76f548d938ec720e2d715d8634e5f8dfa39d707dcd017a33d69db523e34d63ee620d316943386f284f368ee1bc5d27ebb7eb1635be4475eb0ce365c473ecb902190264d18905fb45afe66072f6f5c23aa2541612fa69e1506e76d5cbf6aab144dabfe1841dbff5ed4b3cd25aa8bad10afb30")) };

const LEVEL_11_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000000000017c88f9b02be043f5b6e49e2eecea339fef90ba49ed9d31f7ec08a51d24281df02b25a8c2c1e4bcfab12cb30f55b22d9d68505e7f42b52e40472eb785ba42659dd9748d397341fd2d85e372fcb4c5b7ac05d7bef536ddf92abe9069affe72ee6e4d7ebde8cf826460d916b15a3e4debb634990b1262d3f2c0ac5786fc71895cdaf4ee12c1b0b75c913cf071b6f2ba42b2cbfe8a8122b8ee07ec0fe7fe3a0101b447435990d5ab5944aaf5c55f1beba33fe4b6117d5776c9ca3e9")) };

const LEVEL_12_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000002a03196d63c890d70317c7767a8e565b0a635e0809b7d17f84a317a396cd656d0eac1b79324c8c56f9031d8e11ed2ab6733c807d6a9f317af2ccc5eb3ad56007b1dc0739151c567d823a4aa5e1041f4583a25ef9a9b0e9edb1041b514f7a233d639c13e1b72b2376cac73592f52f2208994f3ffb82953bf9d8731baf5834afd59f4621dac6c4afe1291dca8f6d76f063ba5f7d96f6610ea691690e6c08bf2ac5762089120ba987c44f6a6cc877da6a8de283477b0c0ae5407790")) };

const LEVEL_13_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000000613d374fa8282dfa99ecbd010c53f42537bcef2ba824a55168a765f3d10160d71a4ec511ee7b2cbc48840d1f77bf44805fc5b5bb1a6b714cd29e38792e57ed621494bb1036cb39a5514b3b4ff706e8eb147508baf5491863506659554c0a11de80908f54c09d4c5d58aff39820979746e3cac7e5279d8b6a0a36613d058518b040c8ce93858cbff67eb4d325ac12456303d91148f031204a503a53d39a0ee6272aeb752e4b58fd8b0c0a29ebc5a04e12061c4e7511880ad9f67")) };

const LEVEL_14_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("000000000000137ea68a23a3db0d680f0a30d5523e8540233e889f7885c145d979278d97dc2bd616c46115da18e2d0c4db208b5a21b62eadef73fa6213bdd34cfe11c6ca3aa2525ba986051c287db0793d055ab0f9a4e3a34fe0a4b142f7d1110945ebd634a1e60936c6c35eeedfa7addfa583470fe2d56c3b15ac9d113f7f6f713e1b0b7f0710522bbf878d0502b099d7b856383ae509554ffd42f901521ae81f7dde61367273ab4d589dbf76fff0614fa7b7321a4fa0a46614e62851339c4b")) };

const LEVEL_15_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("0000000000003e4e173a9e35cd2fadfbdff8a6f9b7b6887654e3da6b4309b8ccdbe47bdc804696c501bca00211352115c55d90676dfc76a8645a17a508342d26c6d0ec8c9902db47e138f04e20ca29e8fcbd3ca9b0acdfc7f944b3855940ad664c510c84e37daa7e521ba833f23e3db7373ca11e4659ba320e6b3f8da3a7062165bed5dfdff3e7efd9393dcd07afe509d37accd5ff911b7a491650dd137862ed0dbc839bbc5993480d248328ed0bc49498d937d21a9d5c2146a0e7719bba4fe4")) };

const LEVEL_R_CRT_COEF: LevelKsw = LevelKsw { value: GenericModulus(U1536::from_be_hex("00000000000033fdeb492fa58b805f5c6c51fcdad00a79b9bad1be277e4318ee4a1bf9f7f3b09c055341c4b93831b94527b423e2cff104f91d967a65a1e0324958aeccac171365d6c9f14f72f0ab8f9c9925c1e20a55da4dec3e4beae33f2b90c0e435c91211c33b7f4880e6148d2aa97d179d801b7c93e34744189a8ef48c9aa7b56a52b450828a5c2257b0e25deeb67d865fa3750c70051ca3ab3c22de278ae8ade73c4d30ca39082910cc6c5c847de864a7835ef2bd4183dc5280894b4209")) };

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
