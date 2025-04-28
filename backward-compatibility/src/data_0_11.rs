//! Data generation for kms-core v0.11
//! This file provides the code that is used to generate all the data to serialize and versionize
//! for kms-core v0.11.

use aes_prng::AesRng;
use kms_0_11::engine::base::{gen_sig_keys, KmsFheKeyHandles};
use kms_0_11::engine::centralized::central_kms::generate_client_fhe_key;
use kms_0_11::engine::threshold::service_real::{compute_all_info, ThresholdFheKeys};
use kms_0_11::util::key_setup::FhePublicKey;
use std::{borrow::Cow, fs::create_dir_all, path::PathBuf};
use tfhe_1_1::shortint::parameters::NoiseSquashingParameters;
use threshold_fhe_0_11::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
use threshold_fhe_0_11::execution::endpoints::keygen::FhePubKeySet;
use threshold_fhe_0_11::execution::small_execution::prf::PrfKey;
use threshold_fhe_0_11::{
    execution::{
        runtime::party::Role,
        tfhe_internals::{
            parameters::{DKGParams, DKGParamsRegular, DKGParamsSnS},
            test_feature::initialize_key_material,
        },
    },
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};

use kms_0_11::vault::keychain::AppKeyBlob;
use kms_grpc_0_11::rpc_types::{PubDataType, PublicKeyType, SignedPubDataHandleInternal};
use rand::{RngCore, SeedableRng};
use tfhe_1_1::{
    core_crypto::commons::{
        ciphertext_modulus::CiphertextModulus,
        generators::DeterministicSeeder,
        math::random::{DefaultRandomGenerator, Seed, TUniform},
    },
    shortint::{
        engine::ShortintEngine,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize,
        },
        CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
    },
    ServerKey,
};
use tokio::runtime::Runtime;

use crate::{
    generate::{
        store_versioned_auxiliary_05, store_versioned_test_05, KMSCoreVersion, TEST_DKG_PARAMS_SNS,
    },
    parameters::{
        ClassicPBSParametersTest, DKGParamsRegularTest, DKGParamsSnSTest,
        SwitchAndSquashParametersTest,
    },
    KmsFheKeyHandlesTest, PRSSSetupTest, PrivateSigKeyTest, PublicSigKeyTest,
    SignedPubDataHandleInternalTest, TestMetadataDD, TestMetadataKMS, ThresholdFheKeysTest,
    DISTRIBUTED_DECRYPTION_MODULE_NAME, KMS_MODULE_NAME,
};
use crate::{
    AppKeyBlobTest, PrfKeyTest, PubDataTypeTest, PublicKeyTypeTest, TestMetadataKmsGrpc,
    KMS_GRPC_MODULE_NAME,
};

// Macro to store a versioned test
macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_05($msg, $dir, $test_filename)
    };
}

// Macro to store a versioned auxiliary data associated to a test
macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_name:expr, $filename:expr $(,)? ) => {
        store_versioned_auxiliary_05($msg, $dir, $test_name, $filename)
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

// Parameters `dedicated_compact_public_key_parameters` and `compression_decompression_parameters`
// are set to None because they are optional tfhe-rs types, which means their backward compatibility
// is already tested.
impl From<DKGParamsRegularTest> for DKGParamsRegular {
    fn from(value: DKGParamsRegularTest) -> Self {
        DKGParamsRegular {
            sec: value.sec,
            ciphertext_parameters: value.ciphertext_parameters.into(),
            dedicated_compact_public_key_parameters: None,
            flag: value.flag,
            compression_decompression_parameters: None,
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
            // no need to test this as it's from tfhe-rs
            modulus_switch_noise_reduction_params: None,
        }
    }
}

impl From<SwitchAndSquashParametersTest> for NoiseSquashingParameters {
    fn from(value: SwitchAndSquashParametersTest) -> Self {
        NoiseSquashingParameters {
            glwe_dimension: GlweDimension(value.glwe_dimension),
            glwe_noise_distribution: DynamicDistribution::new_t_uniform(
                value.glwe_noise_distribution,
            ),
            polynomial_size: PolynomialSize(value.polynomial_size),
            decomp_base_log: DecompositionBaseLog(value.pbs_base_log),
            decomp_level_count: DecompositionLevelCount(value.pbs_level),
            ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
            modulus_switch_noise_reduction_params: None,
            message_modulus: MessageModulus(value.message_modulus),
            carry_modulus: CarryModulus(value.carry_modulus),
        }
    }
}

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

const PRF_KEY_TEST: PrfKeyTest = PrfKeyTest {
    test_filename: Cow::Borrowed("prf_key"),
    seed: 100,
};

// KMS test
const PRIVATE_SIG_KEY_TEST: PrivateSigKeyTest = PrivateSigKeyTest {
    test_filename: Cow::Borrowed("private_sig_key"),
    state: 100,
};

// KMS-grpc test
const SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST: SignedPubDataHandleInternalTest =
    SignedPubDataHandleInternalTest {
        test_filename: Cow::Borrowed("signed_pub_data_handle_internal"),
        state: 100,
        key_handle: Cow::Borrowed("key_handle"),
        signature: [1, 2, 3],
        external_signature: [4, 5, 6],
    };

const PUBLIC_KEY_TYPE: PublicKeyTypeTest = PublicKeyTypeTest {
    test_filename: Cow::Borrowed("public_key_type"),
};

const PUB_DATA_TYPE: PubDataTypeTest = PubDataTypeTest {
    test_filename: Cow::Borrowed("pub_data_type"),
};

// KMS test
const PUBLIC_SIG_KEY_TEST: PublicSigKeyTest = PublicSigKeyTest {
    test_filename: Cow::Borrowed("public_sig_key"),
    state: 100,
};

// KMS test
// TODO: include eip712_domain parameter
const KMS_FHE_KEY_HANDLES_TEST: KmsFheKeyHandlesTest = KmsFheKeyHandlesTest {
    test_filename: Cow::Borrowed("kms_fhe_key_handles"),
    client_key_filename: Cow::Borrowed("client_key_handle"),
    public_key_filename: Cow::Borrowed("public_key_handle"),
    server_key_filename: Cow::Borrowed("server_key_handle"),
    sig_key_filename: Cow::Borrowed("sig_key_handle"),
    decompression_key_filename: Cow::Borrowed("decompression_key"),
    state: 100,
    seed: 100,
    element: Cow::Borrowed("element"),
    dkg_parameters_sns: TEST_DKG_PARAMS_SNS,
};

// KMS test
const THRESHOLD_FHE_KEYS_TEST: ThresholdFheKeysTest = ThresholdFheKeysTest {
    test_filename: Cow::Borrowed("threshold_fhe_keys"),
    private_key_set_filename: Cow::Borrowed("private_key_set"),
    integer_server_key_filename: Cow::Borrowed("integer_server_key"),
    sns_key_filename: Cow::Borrowed("sns_key"),
    info_filename: Cow::Borrowed("info"),
    decompression_key_filename: Cow::Borrowed("decompression_key"),
    state: 100,
    amount: 2,
    threshold: 1,
    role_i: 1,
    element: Cow::Borrowed("element"),
    dkg_parameters_sns: TEST_DKG_PARAMS_SNS,
};

// KMS test
const APP_KEY_BLOB_TEST: AppKeyBlobTest = AppKeyBlobTest {
    test_filename: Cow::Borrowed("app_key_blob"),
    root_key_id: Cow::Borrowed("root_key_id"),
    data_key_blob: Cow::Borrowed("data_key_blob"),
    ciphertext: Cow::Borrowed("ciphertext"),
    iv: Cow::Borrowed("iv"),
    auth_tag: Cow::Borrowed("auth_tag"),
};

fn dummy_domain() -> alloy_sol_types_1_0_0::Eip712Domain {
    alloy_sol_types_1_0_0::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: alloy_primitives_1_0_0::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
    )
}

pub struct V0_11;

struct KmsV0_11;

impl KmsV0_11 {
    fn gen_private_sig_key(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(PRIVATE_SIG_KEY_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);

        store_versioned_test!(&private_sig_key, dir, &PRIVATE_SIG_KEY_TEST.test_filename);

        TestMetadataKMS::PrivateSigKey(PRIVATE_SIG_KEY_TEST)
    }

    fn gen_public_sig_key(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(PUBLIC_SIG_KEY_TEST.state);
        let (public_sig_key, _) = gen_sig_keys(&mut rng);

        store_versioned_test!(&public_sig_key, dir, &PUBLIC_SIG_KEY_TEST.test_filename);

        TestMetadataKMS::PublicSigKey(PUBLIC_SIG_KEY_TEST)
    }

    fn gen_app_key_blob(dir: &PathBuf) -> TestMetadataKMS {
        let app_key_blob = AppKeyBlob {
            root_key_id: APP_KEY_BLOB_TEST.root_key_id.to_string(),
            data_key_blob: APP_KEY_BLOB_TEST.data_key_blob.into_owned().into(),
            ciphertext: APP_KEY_BLOB_TEST.ciphertext.into_owned().into(),
            iv: APP_KEY_BLOB_TEST.iv.into_owned().into(),
            auth_tag: APP_KEY_BLOB_TEST.auth_tag.into_owned().into(),
        };

        store_versioned_test!(&app_key_blob, dir, &APP_KEY_BLOB_TEST.test_filename);
        TestMetadataKMS::AppKeyBlob(APP_KEY_BLOB_TEST)
    }

    fn gen_kms_fhe_key_handles(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(KMS_FHE_KEY_HANDLES_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);
        store_versioned_auxiliary!(
            &private_sig_key,
            dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename,
            &KMS_FHE_KEY_HANDLES_TEST.sig_key_filename,
        );

        let dkg_params: DKGParams =
            DKGParams::WithSnS(KMS_FHE_KEY_HANDLES_TEST.dkg_parameters_sns.into());
        let seed = Some(Seed(KMS_FHE_KEY_HANDLES_TEST.seed));

        let client_key = generate_client_fhe_key(dkg_params, seed);
        store_versioned_auxiliary!(
            &client_key,
            dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename,
            &KMS_FHE_KEY_HANDLES_TEST.client_key_filename,
        );

        // The following code is basically the same as in `generate_fhe_keys` in
        // `service/src/cryptography/central_kms.rs`, because we need to retrieve and save some of
        // its intermediate values in order to be able to re-build a KmsFheKeyHandles in tests
        let server_key = client_key.generate_server_key();
        let server_key = server_key.into_raw_parts();
        let decompression_key = server_key.3.clone();

        store_versioned_auxiliary!(
            &decompression_key,
            dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename,
            &KMS_FHE_KEY_HANDLES_TEST.decompression_key_filename,
        );

        let server_key = ServerKey::from_raw_parts(
            server_key.0,
            server_key.1,
            server_key.2,
            server_key.3,
            server_key.4,
            server_key.5,
        );

        store_versioned_auxiliary!(
            &server_key,
            dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename,
            &KMS_FHE_KEY_HANDLES_TEST.server_key_filename,
        );

        let public_key = FhePublicKey::new(&client_key);
        store_versioned_auxiliary!(
            &public_key,
            dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename,
            &KMS_FHE_KEY_HANDLES_TEST.public_key_filename,
        );

        let public_key_set = FhePubKeySet {
            public_key,
            server_key,
        };

        // NOTE: kms_fhe_key_handles.public_key_info is a HashMap
        // so generation is not deterministic
        let kms_fhe_key_handles = KmsFheKeyHandles::new(
            &private_sig_key,
            client_key,
            &public_key_set,
            decompression_key,
            Some(&dummy_domain()),
        )
        .unwrap();

        store_versioned_test!(
            &kms_fhe_key_handles,
            dir,
            &KMS_FHE_KEY_HANDLES_TEST.test_filename
        );

        TestMetadataKMS::KmsFheKeyHandles(KMS_FHE_KEY_HANDLES_TEST)
    }

    fn gen_threshold_fhe_keys(dir: &PathBuf) -> TestMetadataKMS {
        let role = Role::indexed_by_one(THRESHOLD_FHE_KEYS_TEST.role_i);
        let mut base_session = get_networkless_base_session_for_parties(
            THRESHOLD_FHE_KEYS_TEST.amount,
            THRESHOLD_FHE_KEYS_TEST.threshold,
            role,
        );
        let dkg_params: DKGParams =
            DKGParams::WithSnS(THRESHOLD_FHE_KEYS_TEST.dkg_parameters_sns.into());

        let rt = Runtime::new().unwrap();
        let (fhe_pub_key_set, private_key_set) = rt.block_on(async {
            initialize_key_material(&mut base_session, dkg_params)
                .await
                .unwrap()
        });
        store_versioned_auxiliary!(
            &private_key_set,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.private_key_set_filename,
        );

        let (integer_server_key, _, _, _, sns_key, _) =
            fhe_pub_key_set.server_key.clone().into_raw_parts();
        store_versioned_auxiliary!(
            &sns_key,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.sns_key_filename,
        );
        store_versioned_auxiliary!(
            &integer_server_key,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.integer_server_key_filename,
        );

        let mut rng = AesRng::seed_from_u64(THRESHOLD_FHE_KEYS_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);

        // NOTE: this is not deterministic since the result is a HashMap
        let info =
            compute_all_info(&private_sig_key, &fhe_pub_key_set, Some(&dummy_domain())).unwrap();
        store_versioned_auxiliary!(
            &info,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.info_filename,
        );

        let decompression_key = fhe_pub_key_set.server_key.to_owned().into_raw_parts().3;
        store_versioned_auxiliary!(
            &decompression_key,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.decompression_key_filename,
        );

        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: private_key_set,
            integer_server_key,
            sns_key,
            pk_meta_data: info,
            decompression_key,
        };

        store_versioned_test!(
            &threshold_fhe_keys,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename
        );

        TestMetadataKMS::ThresholdFheKeys(THRESHOLD_FHE_KEYS_TEST)
    }
}

struct DistributedDecryptionV0_11;

impl DistributedDecryptionV0_11 {
    fn gen_prss_setup_rpoly_64(dir: &PathBuf) -> TestMetadataDD {
        let role = Role::indexed_by_one(PRSS_SETUP_RPOLY_64_TEST.role_i);
        let base_session = get_networkless_base_session_for_parties(
            PRSS_SETUP_RPOLY_64_TEST.amount,
            PRSS_SETUP_RPOLY_64_TEST.threshold,
            role,
        );
        let prss_setup = get_dummy_prss_setup::<ResiduePolyF4Z64>(base_session);

        store_versioned_test!(&prss_setup, dir, &PRSS_SETUP_RPOLY_64_TEST.test_filename);

        TestMetadataDD::PRSSSetup(PRSS_SETUP_RPOLY_64_TEST)
    }

    fn gen_prss_setup_rpoly_128(dir: &PathBuf) -> TestMetadataDD {
        let role = Role::indexed_by_one(PRSS_SETUP_RPOLY_128_TEST.role_i);
        let base_session = get_networkless_base_session_for_parties(
            PRSS_SETUP_RPOLY_128_TEST.amount,
            PRSS_SETUP_RPOLY_128_TEST.threshold,
            role,
        );
        let prss_setup = get_dummy_prss_setup::<ResiduePolyF4Z128>(base_session);

        store_versioned_test!(&prss_setup, dir, &PRSS_SETUP_RPOLY_128_TEST.test_filename);

        TestMetadataDD::PRSSSetup(PRSS_SETUP_RPOLY_128_TEST)
    }

    fn gen_prf_key(dir: &PathBuf) -> TestMetadataDD {
        let mut buf = [0u8; 16];
        let mut rng = AesRng::from_seed(PRF_KEY_TEST.seed.to_le_bytes());
        rng.fill_bytes(&mut buf);

        let prf_key = PrfKey(buf);

        store_versioned_test!(&prf_key, dir, &PRF_KEY_TEST.test_filename);

        TestMetadataDD::PrfKey(PRF_KEY_TEST)
    }
}

struct KmsGrpcV0_11;

impl KmsGrpcV0_11 {
    fn gen_signed_pub_data_handle_internal(dir: &PathBuf) -> TestMetadataKmsGrpc {
        let signed_pub_data_handle_internal = SignedPubDataHandleInternal::new(
            SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST.key_handle.to_string(),
            SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST.signature.to_vec(),
            SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST
                .external_signature
                .to_vec(),
        );

        store_versioned_test!(
            &signed_pub_data_handle_internal,
            dir,
            &SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST.test_filename
        );

        TestMetadataKmsGrpc::SignedPubDataHandleInternal(SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST)
    }

    fn gen_public_key_type(dir: &PathBuf) -> TestMetadataKmsGrpc {
        let public_key_type = PublicKeyType::Compact;
        store_versioned_test!(&public_key_type, dir, &PUBLIC_KEY_TYPE.test_filename);

        TestMetadataKmsGrpc::PublicKeyType(PUBLIC_KEY_TYPE)
    }

    fn gen_pub_data_type(dir: &PathBuf) -> TestMetadataKmsGrpc {
        let pub_data_type = PubDataType::DecompressionKey;
        store_versioned_test!(&pub_data_type, dir, &PUB_DATA_TYPE.test_filename);

        TestMetadataKmsGrpc::PubDataType(PUB_DATA_TYPE)
    }
}

impl KMSCoreVersion for V0_11 {
    const VERSION_NUMBER: &'static str = "0.11";

    // Without this, some keys will be generated differently every time we run the script
    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });
    }

    fn gen_kms_data() -> Vec<TestMetadataKMS> {
        let dir = Self::data_dir().join(KMS_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            KmsV0_11::gen_private_sig_key(&dir),
            KmsV0_11::gen_public_sig_key(&dir),
            KmsV0_11::gen_kms_fhe_key_handles(&dir),
            KmsV0_11::gen_threshold_fhe_keys(&dir),
            KmsV0_11::gen_app_key_blob(&dir),
        ]
    }

    fn gen_threshold_fhe_data() -> Vec<TestMetadataDD> {
        let dir = Self::data_dir().join(DISTRIBUTED_DECRYPTION_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            DistributedDecryptionV0_11::gen_prss_setup_rpoly_64(&dir),
            DistributedDecryptionV0_11::gen_prss_setup_rpoly_128(&dir),
            DistributedDecryptionV0_11::gen_prf_key(&dir),
        ]
    }

    fn gen_kms_grpc_data() -> Vec<TestMetadataKmsGrpc> {
        let dir = Self::data_dir().join(KMS_GRPC_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            KmsGrpcV0_11::gen_signed_pub_data_handle_internal(&dir),
            KmsGrpcV0_11::gen_public_key_type(&dir),
            KmsGrpcV0_11::gen_pub_data_type(&dir),
        ]
    }
}
