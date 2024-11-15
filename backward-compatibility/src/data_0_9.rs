//! Data generation for kms-core v0.9
//! This file provides the code that is used to generate all the data to serialize and versionize
//! for kms-core v0.9.

use std::{borrow::Cow, fs::create_dir_all, path::PathBuf};

use aes_prng::AesRng;
use distributed_decryption_0_9::execution::endpoints::keygen::FhePubKeySet;
use distributed_decryption_0_9::{
    algebra::residue_poly::{ResiduePoly128, ResiduePoly64},
    execution::{
        runtime::party::Role,
        tfhe_internals::{
            parameters::{DKGParams, DKGParamsRegular, DKGParamsSnS, SwitchAndSquashParameters},
            test_feature::initialize_key_material,
        },
    },
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};

use kms_0_9::util::key_setup::FhePublicKey;
use kms_0_9::{
    cryptography::central_kms::{gen_sig_keys, generate_client_fhe_key, KmsFheKeyHandles},
    rpc::rpc_types::SignedPubDataHandleInternal,
    threshold::threshold_kms::{compute_all_info, ThresholdFheKeys},
};

use events_0_9::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, FheKeyUrlInfo,
    FheParameter, FheType, InsecureCrsGenValues, InsecureKeyGenValues, KeyGenPreprocResponseValues,
    KeyGenPreprocValues, KeyGenResponseValues, KeyGenValues, KeyUrlInfo, KeyUrlResponseValues,
    KeyUrlValues, KmsCoreConf, KmsCoreParty, OperationValue, ReencryptResponseValues,
    ReencryptValues, Transaction, VerfKeyUrlInfo, ZkpResponseValues, ZkpValues,
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
    ServerKey,
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
    CrsGenResponseValuesTest, CrsGenValuesTest, DecryptResponseValuesTest, DecryptValuesTest,
    InsecureCrsGenValuesTest, InsecureKeyGenValuesTest, KeyGenPreprocResponseValuesTest,
    KeyGenPreprocValuesTest, KeyGenResponseValuesTest, KeyGenValuesTest, KeyUrlResponseValuesTest,
    KeyUrlValuesTest, KmsCoreConfTest, KmsFheKeyHandlesTest, PRSSSetupTest, PrivateSigKeyTest,
    PublicSigKeyTest, ReencryptResponseValuesTest, ReencryptValuesTest,
    SignedPubDataHandleInternalTest, TestMetadataDD, TestMetadataEvents, TestMetadataKMS,
    ThresholdFheKeysTest, ZkpResponseValuesTest, ZkpValuesTest, DISTRIBUTED_DECRYPTION_MODULE_NAME,
    EVENTS_MODULE_NAME, KMS_MODULE_NAME,
};

// Macro to store a versioned test
macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_02($msg, $dir, $test_filename)
    };
}

// Macro to store a versioned auxiliary data associated to a test
macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_name:expr, $filename:expr $(,)? ) => {
        store_versioned_auxiliary_02($msg, $dir, $test_name, $filename)
    };
}

// Utility function to convert an array of arrays to a vector of vectors
fn array_array_to_vec_vec<T, A, const N: usize>(array: [A; N]) -> Vec<Vec<T>>
where
    A: IntoIterator<Item = T>,
    T: Clone,
{
    array.into_iter().map(|a| a.into_iter().collect()).collect()
}

// Utility function to convert an array of strings to a vector of strings
fn array_str_to_vec_string<const N: usize>(array: [Cow<'static, str>; N]) -> Vec<String> {
    array.into_iter().map(|s| s.into_owned()).collect()
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
        external_signature: [4, 5, 6],
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

// Constants for events tests
const DECRYPT_VALUES_TEST: DecryptValuesTest = DecryptValuesTest {
    test_filename: Cow::Borrowed("decrypt_values"),
    key_id: [1, 2, 3],
    ciphertext_handles: [[4, 5, 6], [7, 8, 9]],
    fhe_type_names: [Cow::Borrowed("Euint8"), Cow::Borrowed("Euint16")],
    external_handles: [[10, 11, 12], [13, 14, 15]],
    version: 16,
    acl_address: Cow::Borrowed("acl_address"),
    proof: Cow::Borrowed("proof"),
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const DECRYPT_RESPONSE_VALUES_TEST: DecryptResponseValuesTest = DecryptResponseValuesTest {
    test_filename: Cow::Borrowed("decrypt_response_values"),
    signature: [1, 2, 3],
    payload: [4, 5, 6],
    block_height: 1,
    transaction_index: 1,
};

const REENCRYPT_VALUES_TEST: ReencryptValuesTest = ReencryptValuesTest {
    test_filename: Cow::Borrowed("reencrypt_values"),
    signature: [1, 2, 3],
    version: 4,
    client_address: Cow::Borrowed("client_address"),
    enc_key: [5, 6, 7],
    fhe_type_name: Cow::Borrowed("fhe_type_name"),
    key_id: [8, 9, 10],
    ciphertext_handle: [11, 12, 13],
    ciphertext_digest: [14, 15, 16],
    acl_address: Cow::Borrowed("acl_address"),
    proof: Cow::Borrowed("proof"),
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const REENCRYPT_RESPONSE_VALUES_TEST: ReencryptResponseValuesTest = ReencryptResponseValuesTest {
    test_filename: Cow::Borrowed("reencrypt_response_values"),
    signature: [1, 2, 3],
    payload: [4, 5, 6],
    block_height: 1,
    transaction_index: 1,
};

const ZKP_VALUES_TEST: ZkpValuesTest = ZkpValuesTest {
    test_filename: Cow::Borrowed("zkp_values"),
    crs_id: [1, 2, 3],
    key_id: [4, 5, 6],
    contract_address: Cow::Borrowed("contract_address"),
    client_address: Cow::Borrowed("client_address"),
    ct_proof_handle: [7, 8, 9],
    acl_address: Cow::Borrowed("acl_address"),
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const ZKP_RESPONSE_VALUES_TEST: ZkpResponseValuesTest = ZkpResponseValuesTest {
    test_filename: Cow::Borrowed("zkp_response_values"),
    signature: [1, 2, 3],
    payload: [4, 5, 6],
    block_height: 1,
    transaction_index: 1,
};

const KEY_URL_VALUES_TEST: KeyUrlValuesTest = KeyUrlValuesTest {
    test_filename: Cow::Borrowed("key_url_values"),
    block_height: 1,
    transaction_index: 1,
    data_id: [1, 2, 3],
};

const KEY_URL_RESPONSE_VALUES_TEST: KeyUrlResponseValuesTest = KeyUrlResponseValuesTest {
    test_filename: Cow::Borrowed("key_url_response_values"),
    fhe_key_info_fhe_public_key_data_id: [1, 2, 3],
    fhe_key_info_fhe_public_key_param_choice: 4,
    fhe_key_info_fhe_public_key_urls: [Cow::Borrowed("fhe_key_info_fhe_public_key_url_1")],
    fhe_key_info_fhe_public_key_signatures: [[5, 6, 7]],
    fhe_key_info_fhe_server_key_data_id: [8, 9, 10],
    fhe_key_info_fhe_server_key_param_choice: 11,
    fhe_key_info_fhe_server_key_urls: [Cow::Borrowed("fhe_key_info_fhe_server_key_url_1")],
    fhe_key_info_fhe_server_key_signatures: [[12, 13, 14]],
    crs_ids: [15],
    crs_data_ids: [[16, 17, 18]],
    crs_param_choices: [19],
    crs_urls: [[Cow::Borrowed("crs_url_1")]],
    crs_signatures: [[[20, 21, 22]]],
    verf_public_key_key_id: [23, 24, 25],
    verf_public_key_server_id: 26,
    verf_public_key_url: Cow::Borrowed("verf_public_key_url"),
    verf_public_key_address: Cow::Borrowed("verf_public_key_address"),
    block_height: 1,
    transaction_index: 1,
};

const KEY_GEN_PREPROC_VALUES_TEST: KeyGenPreprocValuesTest = KeyGenPreprocValuesTest {
    test_filename: Cow::Borrowed("key_gen_preproc_values"),
    block_height: 1,
    transaction_index: 1,
};

const KEY_GEN_PREPROC_RESPONSE_VALUES_TEST: KeyGenPreprocResponseValuesTest =
    KeyGenPreprocResponseValuesTest {
        test_filename: Cow::Borrowed("key_gen_preproc_response_values"),
        block_height: 1,
        transaction_index: 1,
    };

const KEY_GEN_VALUES_TEST: KeyGenValuesTest = KeyGenValuesTest {
    test_filename: Cow::Borrowed("key_gen_values"),
    preproc_id: [1, 2, 3],
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const KEY_GEN_RESPONSE_VALUES_TEST: KeyGenResponseValuesTest = KeyGenResponseValuesTest {
    test_filename: Cow::Borrowed("key_gen_response_values"),
    request_id: [1, 2, 3],
    public_key_digest: Cow::Borrowed("public_key_digest"),
    public_key_signature: [4, 5, 6],
    server_key_digest: Cow::Borrowed("server_key_digest"),
    server_key_signature: [7, 8, 9],
    param: 1,
    block_height: 1,
    transaction_index: 1,
};

const INSECURE_KEY_GEN_VALUES_TEST: InsecureKeyGenValuesTest = InsecureKeyGenValuesTest {
    test_filename: Cow::Borrowed("insecure_key_gen_values"),
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const CRS_GEN_VALUES_TEST: CrsGenValuesTest = CrsGenValuesTest {
    test_filename: Cow::Borrowed("crs_gen_values"),
    max_num_bits: 256,
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const CRS_GEN_RESPONSE_VALUES_TEST: CrsGenResponseValuesTest = CrsGenResponseValuesTest {
    test_filename: Cow::Borrowed("crs_gen_response_values"),
    request_id: Cow::Borrowed("request_id"),
    digest: Cow::Borrowed("digest"),
    signature: [1, 2, 3],
    max_num_bits: 256,
    param: 1,
    block_height: 1,
    transaction_index: 1,
};

const INSECURE_CRS_GEN_VALUES_TEST: InsecureCrsGenValuesTest = InsecureCrsGenValuesTest {
    test_filename: Cow::Borrowed("insecure_crs_gen_values"),
    max_num_bits: 256,
    eip712_name: Cow::Borrowed("eip712_name"),
    eip712_version: Cow::Borrowed("eip712_version"),
    eip712_chain_id: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 42,
    ],
    eip712_verifying_contract: Cow::Borrowed("eip712_verifying_contract"),
    eip712_salt: Some([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]),
    block_height: 1,
    transaction_index: 1,
};

const KMS_CORE_CONF_TEST: KmsCoreConfTest = KmsCoreConfTest {
    test_filename: Cow::Borrowed("kms_core_conf"),
    parties_party_id: [1, 2, 3],
    parties_public_key: [4, 5, 6],
    parties_address: Cow::Borrowed("parties_address"),
    parties_tls_pub_key: [7, 8, 9],
    response_count_for_majority_vote: 10,
    response_count_for_reconstruction: 11,
    degree_for_reconstruction: 12,
    param_choice: Cow::Borrowed("test"),
};

pub struct V0_9;

struct KmsV0_9;

impl KmsV0_9 {
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

    fn gen_signed_pub_data_handle_internal(dir: &PathBuf) -> TestMetadataKMS {
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

        TestMetadataKMS::SignedPubDataHandleInternal(SIGNED_PUB_DATA_HANDLE_INTERNAL_TEST)
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

        let public_keys = FhePubKeySet {
            public_key,
            server_key,
            sns_key: None,
        };

        // TODO: include eip712_domain parameter
        let kms_fhe_key_handles = KmsFheKeyHandles::new(
            &private_sig_key,
            client_key,
            &public_keys,
            decompression_key,
            None,
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

        let sns_key = fhe_pub_key_set.sns_key.clone().unwrap();
        store_versioned_auxiliary!(
            &sns_key,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.sns_key_filename,
        );

        let mut rng = AesRng::seed_from_u64(THRESHOLD_FHE_KEYS_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);

        // TODO: include domain parameter
        let info = compute_all_info(&private_sig_key, &fhe_pub_key_set, None).unwrap();
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

struct DistributedDecryptionV0_9;

impl DistributedDecryptionV0_9 {
    fn gen_prss_setup_rpoly_64(dir: &PathBuf) -> TestMetadataDD {
        let role = Role::indexed_by_one(PRSS_SETUP_RPOLY_64_TEST.role_i);
        let base_session = get_networkless_base_session_for_parties(
            PRSS_SETUP_RPOLY_64_TEST.amount,
            PRSS_SETUP_RPOLY_64_TEST.threshold,
            role,
        );
        let prss_setup = get_dummy_prss_setup::<ResiduePoly64>(base_session);

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
        let prss_setup = get_dummy_prss_setup::<ResiduePoly128>(base_session);

        store_versioned_test!(&prss_setup, dir, &PRSS_SETUP_RPOLY_128_TEST.test_filename);

        TestMetadataDD::PRSSSetup(PRSS_SETUP_RPOLY_128_TEST)
    }
}

struct EventsV0_9;

impl EventsV0_9 {
    fn gen_decrypt_values(dir: &PathBuf) -> TestMetadataEvents {
        let fhe_types: Vec<FheType> = DECRYPT_VALUES_TEST
            .fhe_type_names
            .iter()
            .map(|type_name| FheType::from_str_name(type_name))
            .collect();

        let ciphertext_handles = array_array_to_vec_vec(DECRYPT_VALUES_TEST.ciphertext_handles);
        let external_handles = array_array_to_vec_vec(DECRYPT_VALUES_TEST.external_handles);

        let decrypt_values = DecryptValues::builder()
            .key_id(DECRYPT_VALUES_TEST.key_id.to_vec().into())
            .ciphertext_handles(ciphertext_handles.into())
            .fhe_types(fhe_types)
            .external_handles(Some(external_handles.into()))
            .version(DECRYPT_VALUES_TEST.version)
            .acl_address(DECRYPT_VALUES_TEST.acl_address.to_string())
            .proof(DECRYPT_VALUES_TEST.proof.to_string())
            .eip712_name(DECRYPT_VALUES_TEST.eip712_name.to_string())
            .eip712_version(DECRYPT_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(DECRYPT_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(DECRYPT_VALUES_TEST.eip712_verifying_contract.to_string())
            .eip712_salt(
                DECRYPT_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            DECRYPT_VALUES_TEST.block_height,
            DECRYPT_VALUES_TEST.transaction_index,
            vec![OperationValue::from(decrypt_values)],
        );

        store_versioned_test!(&transaction, dir, &DECRYPT_VALUES_TEST.test_filename);

        TestMetadataEvents::DecryptValues(DECRYPT_VALUES_TEST)
    }

    fn gen_decrypt_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let decrypt_response_values = DecryptResponseValues::builder()
            .signature(DECRYPT_RESPONSE_VALUES_TEST.signature.to_vec().into())
            .payload(DECRYPT_RESPONSE_VALUES_TEST.payload.to_vec().into())
            .build();

        let transaction = Transaction::new(
            DECRYPT_RESPONSE_VALUES_TEST.block_height,
            DECRYPT_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(decrypt_response_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &DECRYPT_RESPONSE_VALUES_TEST.test_filename
        );

        TestMetadataEvents::DecryptResponseValues(DECRYPT_RESPONSE_VALUES_TEST)
    }

    fn gen_reencrypt_values(dir: &PathBuf) -> TestMetadataEvents {
        let reencrypt_values = ReencryptValues::builder()
            .signature(REENCRYPT_VALUES_TEST.signature.to_vec().into())
            .version(REENCRYPT_VALUES_TEST.version)
            .client_address(REENCRYPT_VALUES_TEST.client_address.to_string())
            .enc_key(REENCRYPT_VALUES_TEST.enc_key.to_vec().into())
            .fhe_type(FheType::from_str_name(&REENCRYPT_VALUES_TEST.fhe_type_name))
            .key_id(REENCRYPT_VALUES_TEST.key_id.to_vec().into())
            .ciphertext_handle(REENCRYPT_VALUES_TEST.ciphertext_handle.to_vec().into())
            .ciphertext_digest(REENCRYPT_VALUES_TEST.ciphertext_digest.to_vec().into())
            .acl_address(REENCRYPT_VALUES_TEST.acl_address.to_string())
            .proof(REENCRYPT_VALUES_TEST.proof.to_string())
            .eip712_name(REENCRYPT_VALUES_TEST.eip712_name.to_string())
            .eip712_version(REENCRYPT_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(REENCRYPT_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(REENCRYPT_VALUES_TEST.eip712_verifying_contract.to_string())
            .eip712_salt(
                REENCRYPT_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            REENCRYPT_VALUES_TEST.block_height,
            REENCRYPT_VALUES_TEST.transaction_index,
            vec![OperationValue::from(reencrypt_values)],
        );

        store_versioned_test!(&transaction, dir, &REENCRYPT_VALUES_TEST.test_filename);

        TestMetadataEvents::ReencryptValues(REENCRYPT_VALUES_TEST)
    }

    fn gen_reencrypt_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let reencrypt_response_values = ReencryptResponseValues::builder()
            .signature(REENCRYPT_RESPONSE_VALUES_TEST.signature.to_vec().into())
            .payload(REENCRYPT_RESPONSE_VALUES_TEST.payload.to_vec().into())
            .build();

        let transaction = Transaction::new(
            REENCRYPT_RESPONSE_VALUES_TEST.block_height,
            REENCRYPT_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(reencrypt_response_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &REENCRYPT_RESPONSE_VALUES_TEST.test_filename
        );

        TestMetadataEvents::ReencryptResponseValues(REENCRYPT_RESPONSE_VALUES_TEST)
    }

    // TODO: rename `zkp` to `verify_proven_ct`
    fn gen_zkp_values(dir: &PathBuf) -> TestMetadataEvents {
        let zkp_values = ZkpValues::builder()
            .crs_id(ZKP_VALUES_TEST.crs_id.to_vec().into())
            .key_id(ZKP_VALUES_TEST.key_id.to_vec().into())
            .contract_address(ZKP_VALUES_TEST.contract_address.to_string())
            .client_address(ZKP_VALUES_TEST.client_address.to_string())
            .ct_proof_handle(ZKP_VALUES_TEST.ct_proof_handle.to_vec().into())
            .acl_address(ZKP_VALUES_TEST.acl_address.to_string())
            .eip712_name(ZKP_VALUES_TEST.eip712_name.to_string())
            .eip712_version(ZKP_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(ZKP_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(ZKP_VALUES_TEST.eip712_verifying_contract.to_string())
            .eip712_salt(
                ZKP_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            ZKP_VALUES_TEST.block_height,
            ZKP_VALUES_TEST.transaction_index,
            vec![OperationValue::from(zkp_values)],
        );

        store_versioned_test!(&transaction, dir, &ZKP_VALUES_TEST.test_filename);

        TestMetadataEvents::ZkpValues(ZKP_VALUES_TEST)
    }

    // TODO: rename `zkp_response_values` to `verify_proven_ct_response_values`
    fn gen_zkp_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let zkp_response_values = ZkpResponseValues::builder()
            .signature(ZKP_RESPONSE_VALUES_TEST.signature.to_vec().into())
            .payload(ZKP_RESPONSE_VALUES_TEST.payload.to_vec().into())
            .build();

        let transaction = Transaction::new(
            ZKP_RESPONSE_VALUES_TEST.block_height,
            ZKP_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(zkp_response_values)],
        );

        store_versioned_test!(&transaction, dir, &ZKP_RESPONSE_VALUES_TEST.test_filename);

        TestMetadataEvents::ZkpResponseValues(ZKP_RESPONSE_VALUES_TEST)
    }

    fn gen_key_url_values(dir: &PathBuf) -> TestMetadataEvents {
        let key_url_values = KeyUrlValues::builder()
            .data_id(KEY_URL_VALUES_TEST.data_id.to_vec().into())
            .build();

        let transaction = Transaction::new(
            KEY_URL_VALUES_TEST.block_height,
            KEY_URL_VALUES_TEST.transaction_index,
            vec![OperationValue::from(key_url_values)],
        );

        store_versioned_test!(&transaction, dir, &KEY_URL_VALUES_TEST.test_filename);

        TestMetadataEvents::KeyUrlValues(KEY_URL_VALUES_TEST)
    }

    fn gen_key_url_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let fhe_public_key = KeyUrlInfo::builder()
            .data_id(
                KEY_URL_RESPONSE_VALUES_TEST
                    .fhe_key_info_fhe_public_key_data_id
                    .to_vec()
                    .into(),
            )
            .param_choice(KEY_URL_RESPONSE_VALUES_TEST.fhe_key_info_fhe_public_key_param_choice)
            .urls(array_str_to_vec_string(
                KEY_URL_RESPONSE_VALUES_TEST.fhe_key_info_fhe_public_key_urls,
            ))
            .signatures(
                array_array_to_vec_vec(
                    KEY_URL_RESPONSE_VALUES_TEST.fhe_key_info_fhe_public_key_signatures,
                )
                .into(),
            )
            .build();

        let fhe_server_key = KeyUrlInfo::builder()
            .data_id(
                KEY_URL_RESPONSE_VALUES_TEST
                    .fhe_key_info_fhe_server_key_data_id
                    .to_vec()
                    .into(),
            )
            .param_choice(KEY_URL_RESPONSE_VALUES_TEST.fhe_key_info_fhe_server_key_param_choice)
            .urls(array_str_to_vec_string(
                KEY_URL_RESPONSE_VALUES_TEST.fhe_key_info_fhe_server_key_urls,
            ))
            .signatures(
                array_array_to_vec_vec(
                    KEY_URL_RESPONSE_VALUES_TEST.fhe_key_info_fhe_server_key_signatures,
                )
                .into(),
            )
            .build();

        let fhe_key_info = vec![FheKeyUrlInfo::builder()
            .fhe_public_key(fhe_public_key)
            .fhe_server_key(fhe_server_key)
            .build()];

        let crs = KEY_URL_RESPONSE_VALUES_TEST
            .crs_ids
            .iter()
            .zip(KEY_URL_RESPONSE_VALUES_TEST.crs_data_ids.iter())
            .zip(KEY_URL_RESPONSE_VALUES_TEST.crs_param_choices.iter())
            .zip(KEY_URL_RESPONSE_VALUES_TEST.crs_urls.iter())
            .zip(KEY_URL_RESPONSE_VALUES_TEST.crs_signatures.iter())
            .map(|((((id, data_id), param_choice), urls), signatures)| {
                (
                    *id,
                    KeyUrlInfo::builder()
                        .data_id(data_id.to_vec().into())
                        .param_choice(*param_choice)
                        .urls(array_str_to_vec_string(urls.clone()))
                        .signatures(array_array_to_vec_vec(*signatures).into())
                        .build(),
                )
            })
            .collect();

        let verf_public_key = vec![VerfKeyUrlInfo::builder()
            .key_id(
                KEY_URL_RESPONSE_VALUES_TEST
                    .verf_public_key_key_id
                    .to_vec()
                    .into(),
            )
            .server_id(KEY_URL_RESPONSE_VALUES_TEST.verf_public_key_server_id)
            .verf_public_key_url(KEY_URL_RESPONSE_VALUES_TEST.verf_public_key_url.to_string())
            .verf_public_key_address(
                KEY_URL_RESPONSE_VALUES_TEST
                    .verf_public_key_address
                    .to_string(),
            )
            .build()];

        let key_url_response_values = KeyUrlResponseValues::builder()
            .fhe_key_info(fhe_key_info)
            .crs(crs)
            .verf_public_key(verf_public_key)
            .build();

        let transaction = Transaction::new(
            KEY_URL_RESPONSE_VALUES_TEST.block_height,
            KEY_URL_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(key_url_response_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &KEY_URL_RESPONSE_VALUES_TEST.test_filename
        );

        TestMetadataEvents::KeyUrlResponseValues(KEY_URL_RESPONSE_VALUES_TEST)
    }

    fn gen_key_gen_preproc_values(dir: &PathBuf) -> TestMetadataEvents {
        let key_gen_preproc_values = KeyGenPreprocValues::builder().build();

        let transaction = Transaction::new(
            KEY_GEN_PREPROC_VALUES_TEST.block_height,
            KEY_GEN_PREPROC_VALUES_TEST.transaction_index,
            vec![OperationValue::from(key_gen_preproc_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &KEY_GEN_PREPROC_VALUES_TEST.test_filename
        );

        TestMetadataEvents::KeyGenPreprocValues(KEY_GEN_PREPROC_VALUES_TEST)
    }

    fn gen_key_gen_preproc_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let key_gen_preproc_response_values = KeyGenPreprocResponseValues::builder().build();

        let transaction = Transaction::new(
            KEY_GEN_PREPROC_RESPONSE_VALUES_TEST.block_height,
            KEY_GEN_PREPROC_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(key_gen_preproc_response_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &KEY_GEN_PREPROC_RESPONSE_VALUES_TEST.test_filename
        );

        TestMetadataEvents::KeyGenPreprocResponseValues(KEY_GEN_PREPROC_RESPONSE_VALUES_TEST)
    }

    fn gen_key_gen_values(dir: &PathBuf) -> TestMetadataEvents {
        let key_gen_values = KeyGenValues::builder()
            .preproc_id(KEY_GEN_VALUES_TEST.preproc_id.to_vec().into())
            .eip712_name(KEY_GEN_VALUES_TEST.eip712_name.to_string())
            .eip712_version(KEY_GEN_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(KEY_GEN_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(KEY_GEN_VALUES_TEST.eip712_verifying_contract.to_string())
            .eip712_salt(
                KEY_GEN_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            KEY_GEN_VALUES_TEST.block_height,
            KEY_GEN_VALUES_TEST.transaction_index,
            vec![OperationValue::from(key_gen_values)],
        );

        store_versioned_test!(&transaction, dir, &KEY_GEN_VALUES_TEST.test_filename);

        TestMetadataEvents::KeyGenValues(KEY_GEN_VALUES_TEST)
    }

    fn gen_key_gen_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let key_gen_response_values = KeyGenResponseValues::builder()
            .request_id(KEY_GEN_RESPONSE_VALUES_TEST.request_id.to_vec().into())
            .public_key_digest(KEY_GEN_RESPONSE_VALUES_TEST.public_key_digest.to_string())
            .public_key_signature(
                KEY_GEN_RESPONSE_VALUES_TEST
                    .public_key_signature
                    .to_vec()
                    .into(),
            )
            .server_key_digest(KEY_GEN_RESPONSE_VALUES_TEST.server_key_digest.to_string())
            .server_key_signature(
                KEY_GEN_RESPONSE_VALUES_TEST
                    .server_key_signature
                    .to_vec()
                    .into(),
            )
            .param(KEY_GEN_RESPONSE_VALUES_TEST.param)
            .build();

        let transaction = Transaction::new(
            KEY_GEN_RESPONSE_VALUES_TEST.block_height,
            KEY_GEN_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(key_gen_response_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &KEY_GEN_RESPONSE_VALUES_TEST.test_filename
        );

        TestMetadataEvents::KeyGenResponseValues(KEY_GEN_RESPONSE_VALUES_TEST)
    }

    fn gen_insecure_key_gen_values(dir: &PathBuf) -> TestMetadataEvents {
        let insecure_key_gen_values = InsecureKeyGenValues::builder()
            .eip712_name(INSECURE_KEY_GEN_VALUES_TEST.eip712_name.to_string())
            .eip712_version(INSECURE_KEY_GEN_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(INSECURE_KEY_GEN_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(
                INSECURE_KEY_GEN_VALUES_TEST
                    .eip712_verifying_contract
                    .to_string(),
            )
            .eip712_salt(
                INSECURE_KEY_GEN_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            INSECURE_KEY_GEN_VALUES_TEST.block_height,
            INSECURE_KEY_GEN_VALUES_TEST.transaction_index,
            vec![OperationValue::from(insecure_key_gen_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &INSECURE_KEY_GEN_VALUES_TEST.test_filename
        );

        TestMetadataEvents::InsecureKeyGenValues(INSECURE_KEY_GEN_VALUES_TEST)
    }

    fn gen_crs_gen_values(dir: &PathBuf) -> TestMetadataEvents {
        let crs_gen_values = CrsGenValues::builder()
            .max_num_bits(CRS_GEN_VALUES_TEST.max_num_bits)
            .eip712_name(CRS_GEN_VALUES_TEST.eip712_name.to_string())
            .eip712_version(CRS_GEN_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(CRS_GEN_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(CRS_GEN_VALUES_TEST.eip712_verifying_contract.to_string())
            .eip712_salt(
                CRS_GEN_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            CRS_GEN_VALUES_TEST.block_height,
            CRS_GEN_VALUES_TEST.transaction_index,
            vec![OperationValue::from(crs_gen_values)],
        );

        store_versioned_test!(&transaction, dir, &CRS_GEN_VALUES_TEST.test_filename);

        TestMetadataEvents::CrsGenValues(CRS_GEN_VALUES_TEST)
    }

    fn gen_crs_gen_response_values(dir: &PathBuf) -> TestMetadataEvents {
        let crs_gen_response_values = CrsGenResponseValues::builder()
            .request_id(CRS_GEN_RESPONSE_VALUES_TEST.request_id.to_string())
            .digest(CRS_GEN_RESPONSE_VALUES_TEST.digest.to_string())
            .signature(CRS_GEN_RESPONSE_VALUES_TEST.signature.to_vec().into())
            .max_num_bits(CRS_GEN_RESPONSE_VALUES_TEST.max_num_bits)
            .param(CRS_GEN_RESPONSE_VALUES_TEST.param)
            .build();

        let transaction = Transaction::new(
            CRS_GEN_RESPONSE_VALUES_TEST.block_height,
            CRS_GEN_RESPONSE_VALUES_TEST.transaction_index,
            vec![OperationValue::from(crs_gen_response_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &CRS_GEN_RESPONSE_VALUES_TEST.test_filename
        );

        TestMetadataEvents::CrsGenResponseValues(CRS_GEN_RESPONSE_VALUES_TEST)
    }

    fn gen_insecure_crs_gen_values(dir: &PathBuf) -> TestMetadataEvents {
        let insecure_crs_gen_values = InsecureCrsGenValues::builder()
            .max_num_bits(INSECURE_CRS_GEN_VALUES_TEST.max_num_bits)
            .eip712_name(INSECURE_CRS_GEN_VALUES_TEST.eip712_name.to_string())
            .eip712_version(INSECURE_CRS_GEN_VALUES_TEST.eip712_version.to_string())
            .eip712_chain_id(INSECURE_CRS_GEN_VALUES_TEST.eip712_chain_id.to_vec().into())
            .eip712_verifying_contract(
                INSECURE_CRS_GEN_VALUES_TEST
                    .eip712_verifying_contract
                    .to_string(),
            )
            .eip712_salt(
                INSECURE_CRS_GEN_VALUES_TEST
                    .eip712_salt
                    .map(|salt| salt.to_vec().into())
                    .expect("could not convert salt format"),
            )
            .build();

        let transaction = Transaction::new(
            INSECURE_CRS_GEN_VALUES_TEST.block_height,
            INSECURE_CRS_GEN_VALUES_TEST.transaction_index,
            vec![OperationValue::from(insecure_crs_gen_values)],
        );

        store_versioned_test!(
            &transaction,
            dir,
            &INSECURE_CRS_GEN_VALUES_TEST.test_filename
        );

        TestMetadataEvents::InsecureCrsGenValues(INSECURE_CRS_GEN_VALUES_TEST)
    }

    fn gen_kms_core_conf(dir: &PathBuf) -> TestMetadataEvents {
        let parties = vec![KmsCoreParty {
            party_id: KMS_CORE_CONF_TEST.parties_party_id.to_vec().into(),
            public_key: Some(KMS_CORE_CONF_TEST.parties_public_key.to_vec().into()),
            address: KMS_CORE_CONF_TEST.parties_address.to_string(),
            tls_pub_key: Some(KMS_CORE_CONF_TEST.parties_tls_pub_key.to_vec().into()),
        }];

        let param_choice = match KMS_CORE_CONF_TEST.param_choice.as_ref() {
            "test" => FheParameter::Test,
            "default" => FheParameter::Default,
            _ => panic!("Invalid parameter choice"),
        };

        let kms_core_conf_threshold = KmsCoreConf {
            parties,
            response_count_for_majority_vote: KMS_CORE_CONF_TEST.response_count_for_majority_vote,
            response_count_for_reconstruction: KMS_CORE_CONF_TEST.response_count_for_reconstruction,
            degree_for_reconstruction: KMS_CORE_CONF_TEST.degree_for_reconstruction,
            param_choice,
        };

        let kms_core_conf: KmsCoreConf = KmsCoreConf::Threshold(kms_core_conf_threshold);

        store_versioned_test!(&kms_core_conf, dir, &KMS_CORE_CONF_TEST.test_filename);

        TestMetadataEvents::KmsCoreConf(KMS_CORE_CONF_TEST)
    }
}

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

        vec![
            KmsV0_9::gen_private_sig_key(&dir),
            KmsV0_9::gen_public_sig_key(&dir),
            KmsV0_9::gen_signed_pub_data_handle_internal(&dir),
            KmsV0_9::gen_kms_fhe_key_handles(&dir),
            KmsV0_9::gen_threshold_fhe_keys(&dir),
        ]
    }

    fn gen_distributed_decryption_data() -> Vec<TestMetadataDD> {
        let dir = Self::data_dir().join(DISTRIBUTED_DECRYPTION_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            DistributedDecryptionV0_9::gen_prss_setup_rpoly_64(&dir),
            DistributedDecryptionV0_9::gen_prss_setup_rpoly_128(&dir),
        ]
    }

    fn gen_events_data() -> Vec<TestMetadataEvents> {
        let dir = Self::data_dir().join(EVENTS_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            EventsV0_9::gen_decrypt_values(&dir),
            EventsV0_9::gen_decrypt_response_values(&dir),
            EventsV0_9::gen_reencrypt_values(&dir),
            EventsV0_9::gen_reencrypt_response_values(&dir),
            EventsV0_9::gen_zkp_values(&dir),
            EventsV0_9::gen_zkp_response_values(&dir),
            EventsV0_9::gen_key_url_values(&dir),
            EventsV0_9::gen_key_url_response_values(&dir),
            EventsV0_9::gen_key_gen_preproc_values(&dir),
            EventsV0_9::gen_key_gen_preproc_response_values(&dir),
            EventsV0_9::gen_key_gen_values(&dir),
            EventsV0_9::gen_key_gen_response_values(&dir),
            EventsV0_9::gen_insecure_key_gen_values(&dir),
            EventsV0_9::gen_crs_gen_values(&dir),
            EventsV0_9::gen_crs_gen_response_values(&dir),
            EventsV0_9::gen_insecure_crs_gen_values(&dir),
            EventsV0_9::gen_kms_core_conf(&dir),
        ]
    }
}
