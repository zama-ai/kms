//! Data generation for kms-core v0.9
//! This file provides the code that is used to generate all the data to serialize and versionize
//! for kms-core v0.9.

use std::{borrow::Cow, fs::create_dir_all};

use aes_prng::AesRng;
use distributed_decryption_0_9::execution::endpoints::keygen::FhePubKeySet;
use distributed_decryption_0_9::{
    algebra::residue_poly::{ResiduePoly128, ResiduePoly64},
    execution::{
        runtime::party::Role,
        tfhe_internals::{
            parameters::{
                DKGParamsRegular, DKGParamsSnS, NoiseFloodParameters, SwitchAndSquashParameters,
            },
            test_feature::initialize_key_material,
        },
        zk::ceremony::PublicParameter,
    },
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};

use kms_0_9::util::key_setup::FhePublicKey;
use kms_0_9::{
    cryptography::central_kms::{gen_sig_keys, generate_client_fhe_key, KmsFheKeyHandles},
    rpc::rpc_types::SignedPubDataHandleInternal,
    threshold::threshold_kms::{compute_all_info, ThresholdFheKeys},
};

use rand::SeedableRng;
use tfhe_0_8::{
    core_crypto::commons::{
        ciphertext_modulus::CiphertextModulus,
        generators::DeterministicSeeder,
        math::random::{ActivatedRandomGenerator, Seed, TUniform},
    },
    shortint::{
        engine::ShortintEngine,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize,
        },
        CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
    },
};
use tokio::runtime::Runtime;

use crate::{
    generate::{
        store_versioned_auxiliary_02, store_versioned_test_02, KMSCoreVersion, TEST_DKG_PARAMS_SNS,
    },
    parameters::{
        ClassicPBSParametersTest, DKGParamsRegularTest, DKGParamsSnSTest,
        SwitchAndSquashParametersTest,
    },
    KmsFheKeyHandlesTest, PRSSSetupTest, PrivateSigKeyTest, PublicParameterTest, PublicSigKeyTest,
    SignedPubDataHandleInternalTest, TestMetadataDD, TestMetadataKMS, ThresholdFheKeysTest,
    DISTRIBUTED_DECRYPTION_MODULE_NAME, KMS_MODULE_NAME,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_02($msg, $dir, $test_filename)
    };
}

impl From<DKGParamsSnSTest> for DKGParamsSnS {
    fn from(value: DKGParamsSnSTest) -> Self {
        DKGParamsSnS {
            regular_params: value.regular_params.into(),
            sns_params: value.sns_params.into(),
        }
    }
}

impl From<DKGParamsRegularTest> for DKGParamsRegular {
    fn from(value: DKGParamsRegularTest) -> Self {
        DKGParamsRegular {
            sec: value.sec,
            ciphertext_parameters: value.ciphertext_parameters.into(),
            dedicated_compact_public_key_parameters: None,
            flag: value.flag,
        }
    }
}

impl From<ClassicPBSParametersTest> for ClassicPBSParameters {
    fn from(value: ClassicPBSParametersTest) -> Self {
        ClassicPBSParameters {
            lwe_dimension: LweDimension(value.lwe_dimension),
            glwe_dimension: GlweDimension(value.glwe_dimension),
            polynomial_size: PolynomialSize(value.polynomial_size),
            lwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(
                value.lwe_noise_gaussian,
            )),
            glwe_noise_distribution: DynamicDistribution::TUniform(TUniform::new(0)),
            pbs_base_log: DecompositionBaseLog(value.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_level),
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            ks_level: DecompositionLevelCount(value.ks_level),
            message_modulus: MessageModulus(value.message_modulus),
            carry_modulus: CarryModulus(value.carry_modulus),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
        }
    }
}

impl From<SwitchAndSquashParametersTest> for SwitchAndSquashParameters {
    fn from(value: SwitchAndSquashParametersTest) -> Self {
        SwitchAndSquashParameters {
            glwe_dimension: GlweDimension(value.glwe_dimension),
            glwe_noise_distribution: TUniform::new(value.glwe_noise_distribution),
            polynomial_size: PolynomialSize(value.polynomial_size),
            pbs_base_log: DecompositionBaseLog(value.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_level),
            ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        }
    }
}

// Distributed Decryption test
const PUBLIC_PARAMETER_TEST: PublicParameterTest = PublicParameterTest {
    test_filename: Cow::Borrowed("public_parameter"),
    witness_dim: 2,
    max_num_bits: Some(1),
};

// Distributed Decryption test
const PRSS_SETUP_RPOLY_64_TEST: PRSSSetupTest = PRSSSetupTest {
    test_filename: Cow::Borrowed("prss_setup_rpoly_64"),
    amount: 10,
    threshold: 3,
    role_i: 1,
    residue_poly_size: 64,
};

// Distributed Decryption test
const PRSS_SETUP_RPOLY_128_TEST: PRSSSetupTest = PRSSSetupTest {
    test_filename: Cow::Borrowed("prss_setup_rpoly_128"),
    amount: 10,
    threshold: 3,
    role_i: 1,
    residue_poly_size: 128,
};

// KMS test
const PRIVATE_SIG_KEY_TEST: PrivateSigKeyTest = PrivateSigKeyTest {
    test_filename: Cow::Borrowed("private_sig_key"),
    state: 100,
};

// KMS test
const PUBLIC_SIG_KEY_TEST: PublicSigKeyTest = PublicSigKeyTest {
    test_filename: Cow::Borrowed("public_sig_key"),
    state: 100,
};

// KMS test
const SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST: SignedPubDataHandleInternalTest =
    SignedPubDataHandleInternalTest {
        test_filename: Cow::Borrowed("signed_pub_data_handle_internal"),
        state: 100,
        key_handle: Cow::Borrowed("key_handle"),
        signature: [1, 2, 3],
    };

// KMS test
const KMS_FHE_KEY_HANDLES_TEST: KmsFheKeyHandlesTest = KmsFheKeyHandlesTest {
    test_filename: Cow::Borrowed("kms_fhe_key_handles"),
    client_key_filename: Cow::Borrowed("client_key_handle"),
    public_key_filename: Cow::Borrowed("public_key_handle"),
    server_key_filename: Cow::Borrowed("server_key_handle"),
    sig_key_filename: Cow::Borrowed("sig_key_handle"),
    state: 100,
    seed: 100,
    element: Cow::Borrowed("element"),
    dkg_parameters_sns: TEST_DKG_PARAMS_SNS,
};

// KMS test
const THRESHOLD_FHE_KEYS_TEST: ThresholdFheKeysTest = ThresholdFheKeysTest {
    test_filename: Cow::Borrowed("threshold_fhe_keys"),
    private_key_set_filename: Cow::Borrowed("private_key_set"),
    sns_key_filename: Cow::Borrowed("sns_key"),
    info_filename: Cow::Borrowed("info"),
    state: 100,
    amount: 2,
    threshold: 1,
    role_i: 1,
    element: Cow::Borrowed("element"),
    dkg_parameters_sns: TEST_DKG_PARAMS_SNS,
};

pub struct V0_9;

impl KMSCoreVersion for V0_9 {
    const VERSION_NUMBER: &'static str = "0.9";

    // Without this, some keys will be generated differently every time we run the script
    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });
    }

    fn gen_kms_data() -> Vec<TestMetadataKMS> {
        let dir = Self::data_dir().join(KMS_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // PrivateSigKey
        let mut rng = AesRng::seed_from_u64(PRIVATE_SIG_KEY_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);

        store_versioned_test!(&private_sig_key, &dir, &PRIVATE_SIG_KEY_TEST.test_filename);

        // PublicSigKey
        let mut rng = AesRng::seed_from_u64(PUBLIC_SIG_KEY_TEST.state);
        let (public_sig_key, _) = gen_sig_keys(&mut rng);

        store_versioned_test!(&public_sig_key, &dir, &PUBLIC_SIG_KEY_TEST.test_filename);

        // SignedPubDataHandleInternal
        let signed_pub_data_handle_internal = SignedPubDataHandleInternal::new(
            SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST.key_handle.to_string(),
            SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST.signature.to_vec(),
        );

        store_versioned_test!(
            &signed_pub_data_handle_internal,
            &dir,
            &SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST.test_filename
        );

        // KmsFheKeyHandles
        let mut rng = AesRng::seed_from_u64(KMS_FHE_KEY_HANDLES_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);
        store_versioned_auxiliary_02(
            &private_sig_key,
            &dir,
            &KMS_FHE_KEY_HANDLES_TEST.sig_key_filename,
        );

        let dkg_params: DKGParamsSnS = KMS_FHE_KEY_HANDLES_TEST.dkg_parameters_sns.into();
        let params: NoiseFloodParameters = dkg_params.to_noiseflood_parameters();
        let seed = Some(Seed(KMS_FHE_KEY_HANDLES_TEST.seed));

        let client_key = generate_client_fhe_key(params, seed);
        store_versioned_auxiliary_02(
            &client_key,
            &dir,
            &KMS_FHE_KEY_HANDLES_TEST.client_key_filename,
        );

        let server_key = client_key.generate_server_key();
        store_versioned_auxiliary_02(
            &server_key,
            &dir,
            &KMS_FHE_KEY_HANDLES_TEST.server_key_filename,
        );

        let public_key = FhePublicKey::new(&client_key);
        store_versioned_auxiliary_02(
            &public_key,
            &dir,
            &KMS_FHE_KEY_HANDLES_TEST.public_key_filename,
        );

        let public_keys = FhePubKeySet {
            public_key,
            server_key,
            sns_key: None,
        };

        let kms_fhe_key_handles =
            KmsFheKeyHandles::new(&private_sig_key, client_key, &public_keys).unwrap();

        store_versioned_test!(
            &kms_fhe_key_handles,
            &dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename
        );

        // ThresholdFheKeys
        let role = Role::indexed_by_one(THRESHOLD_FHE_KEYS_TEST.role_i);
        let mut base_session = get_networkless_base_session_for_parties(
            THRESHOLD_FHE_KEYS_TEST.amount,
            THRESHOLD_FHE_KEYS_TEST.threshold,
            role,
        );
        let dkg_params: DKGParamsSnS = THRESHOLD_FHE_KEYS_TEST.dkg_parameters_sns.into();
        let params: NoiseFloodParameters = dkg_params.to_noiseflood_parameters();

        let rt = Runtime::new().unwrap();
        let (fhe_pub_key_set, private_key_set) = rt.block_on(async {
            initialize_key_material(&mut base_session, params)
                .await
                .unwrap()
        });
        store_versioned_auxiliary_02(
            &private_key_set,
            &dir,
            &THRESHOLD_FHE_KEYS_TEST.private_key_set_filename,
        );

        let sns_key = fhe_pub_key_set.sns_key.clone().unwrap();
        store_versioned_auxiliary_02(&sns_key, &dir, &THRESHOLD_FHE_KEYS_TEST.sns_key_filename);

        let mut rng = AesRng::seed_from_u64(THRESHOLD_FHE_KEYS_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);
        let info = compute_all_info(&private_sig_key, &fhe_pub_key_set).unwrap();
        store_versioned_auxiliary_02(&info, &dir, &THRESHOLD_FHE_KEYS_TEST.info_filename);

        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: private_key_set,
            sns_key,
            pk_meta_data: info,
        };

        store_versioned_test!(
            &threshold_fhe_keys,
            &dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename
        );

        vec![
            TestMetadataKMS::PrivateSigKey(PRIVATE_SIG_KEY_TEST),
            TestMetadataKMS::PublicSigKey(PUBLIC_SIG_KEY_TEST),
            TestMetadataKMS::SignedPubDataHandleInternal(SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST),
            TestMetadataKMS::KmsFheKeyHandles(KMS_FHE_KEY_HANDLES_TEST),
            TestMetadataKMS::ThresholdFheKeys(THRESHOLD_FHE_KEYS_TEST),
        ]
    }

    fn gen_distributed_decryption_data() -> Vec<TestMetadataDD> {
        let dir = Self::data_dir().join(DISTRIBUTED_DECRYPTION_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // PublicParameter
        let public_parameter = PublicParameter::new(
            PUBLIC_PARAMETER_TEST.witness_dim,
            PUBLIC_PARAMETER_TEST.max_num_bits,
        );

        store_versioned_test!(
            &public_parameter,
            &dir,
            &PUBLIC_PARAMETER_TEST.test_filename
        );

        // PRSSSetup (ResiduePoly64)
        let role = Role::indexed_by_one(PRSS_SETUP_RPOLY_64_TEST.role_i);
        let base_session = get_networkless_base_session_for_parties(
            PRSS_SETUP_RPOLY_64_TEST.amount,
            PRSS_SETUP_RPOLY_64_TEST.threshold,
            role,
        );
        let prss_setup = get_dummy_prss_setup::<ResiduePoly64>(base_session);

        store_versioned_test!(&prss_setup, &dir, &PRSS_SETUP_RPOLY_64_TEST.test_filename);

        // PRSSSetup (ResiduePoly128)
        let role = Role::indexed_by_one(PRSS_SETUP_RPOLY_128_TEST.role_i);
        let base_session = get_networkless_base_session_for_parties(
            PRSS_SETUP_RPOLY_128_TEST.amount,
            PRSS_SETUP_RPOLY_128_TEST.threshold,
            role,
        );
        let prss_setup = get_dummy_prss_setup::<ResiduePoly128>(base_session);

        store_versioned_test!(&prss_setup, &dir, &PRSS_SETUP_RPOLY_128_TEST.test_filename);

        vec![
            TestMetadataDD::PublicParameter(PUBLIC_PARAMETER_TEST),
            TestMetadataDD::PRSSSetup(PRSS_SETUP_RPOLY_64_TEST),
            TestMetadataDD::PRSSSetup(PRSS_SETUP_RPOLY_128_TEST),
        ]
    }
}
