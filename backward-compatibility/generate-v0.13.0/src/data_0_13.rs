//! Data generation for kms-core v0.13.0
//! This file provides the code that is used to generate all the data to serialize and versionize
//! for kms-core v0.13.0

use aes_prng::AesRng;
use kms_0_13_0::backup::custodian::{
    Custodian, CustodianSetupMessagePayload, InternalCustodianContext,
};
use kms_0_13_0::backup::{
    custodian::{InternalCustodianRecoveryOutput, InternalCustodianSetupMessage},
    operator::{
        BackupMaterial, InnerOperatorBackupOutput, InternalRecoveryRequest, Operator,
        RecoveryValidationMaterial, DSEP_BACKUP_COMMITMENT,
    },
    BackupCiphertext,
};
use kms_0_13_0::consts::SAFE_SER_SIZE_LIMIT;
use kms_0_13_0::cryptography::{
    encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedCipher},
    hybrid_ml_kem::HybridKemCt,
    signatures::{compute_eip712_signature, gen_sig_keys, SigningSchemeType},
    signcryption::{
        Signcrypt, UnifiedSigncryption, UnifiedSigncryptionKeyOwned, UnifiedUnsigncryptionKeyOwned,
    },
};
use kms_0_13_0::engine::base::{
    safe_serialize_hash_element_versioned, CrsGenMetadata, KeyGenMetadataInner, KmsFheKeyHandles,
};
use kms_0_13_0::engine::centralized::central_kms::generate_client_fhe_key;
use kms_0_13_0::engine::context::{ContextInfo, NodeInfo, SoftwareVersion};
use kms_0_13_0::engine::threshold::service::session::PRSSSetupCombined;
use kms_0_13_0::engine::threshold::service::ThresholdFheKeys;
use kms_0_13_0::util::key_setup::FhePublicKey;
use kms_0_13_0::vault::keychain::AppKeyBlob;
use kms_grpc_0_13_0::{
    kms::v1::{CustodianContext, CustodianSetupMessage, TypedPlaintext},
    rpc_types::{PrivDataType, PubDataType, PublicKeyType, SignedPubDataHandleInternal},
    solidity_types::{CrsgenVerification, KeygenVerification},
    RequestId,
};
use rand::{RngCore, SeedableRng};
use std::collections::BTreeMap;
use std::num::Wrapping;
use std::{borrow::Cow, collections::HashMap, fs::create_dir_all, path::PathBuf};
use tfhe_1_4::safe_serialization::safe_serialize;
use tfhe_1_4::shortint::parameters::{
    LweCiphertextCount, NoiseSquashingClassicParameters, NoiseSquashingCompressionParameters,
};
use tfhe_1_4::{
    core_crypto::commons::{
        ciphertext_modulus::CiphertextModulus,
        generators::DeterministicSeeder,
        math::random::{DefaultRandomGenerator, Seed, TUniform},
    },
    shortint::parameters::NoiseSquashingParameters,
    shortint::{
        engine::ShortintEngine,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize,
        },
        CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
    },
    ServerKey, Tag,
};
use tfhe_versionable_0_6::Upgrade;
use threshold_fhe_0_13_0::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
use threshold_fhe_0_13_0::execution::small_execution::prf::PrfKey;
use threshold_fhe_0_13_0::execution::tfhe_internals::public_keysets::FhePubKeySet;
use threshold_fhe_0_13_0::{
    execution::{
        runtime::party::Role,
        sharing::share::Share,
        small_execution::prss::{PrssSet, PrssSetV0},
        tfhe_internals::{
            parameters::{DKGParams, DKGParamsRegular, DKGParamsSnS, DkgMode},
            test_feature::initialize_key_material,
        },
    },
    networking::tls::ReleasePCRValues,
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};
use tokio::runtime::Runtime;

use backward_compatibility::parameters::{
    ClassicPBSParametersTest, DKGParamsRegularTest, DKGParamsSnSTest,
    SwitchAndSquashCompressionParametersTest, SwitchAndSquashParametersTest,
};
use backward_compatibility::{
    AppKeyBlobTest, BackupCiphertextTest, ContextInfoTest, CrsGenMetadataTest, HybridKemCtTest,
    InternalCustodianContextTest, InternalCustodianRecoveryOutputTest,
    InternalCustodianSetupMessageTest, InternalRecoveryRequestTest, KeyGenMetadataTest,
    KmsFheKeyHandlesTest, NodeInfoTest, OperatorBackupOutputTest, PRSSSetupTest, PrfKeyTest,
    PrivDataTypeTest, PrivateSigKeyTest, PrssSetTest, PrssSetupCombinedTest, PubDataTypeTest,
    PublicKeyTypeTest, PublicSigKeyTest, RecoveryValidationMaterialTest, ReleasePCRValuesTest,
    ShareTest, SigncryptionPayloadTest, SignedPubDataHandleInternalTest, SoftwareVersionTest,
    TestMetadataDD, TestMetadataKMS, TestMetadataKmsGrpc, ThresholdFheKeysTest, TypedPlaintextTest,
    UnifiedCipherTest, UnifiedSigncryptionKeyTest, UnifiedSigncryptionTest,
    UnifiedUnsigncryptionKeyTest, DISTRIBUTED_DECRYPTION_MODULE_NAME, KMS_GRPC_MODULE_NAME,
    KMS_MODULE_NAME,
};

use kms_0_13_0::cryptography::signcryption::SigncryptionPayload;

use crate::generate::{
    store_versioned_auxiliary_05, store_versioned_test_05, KMSCoreVersion, TEST_DKG_PARAMS_SNS,
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

fn convert_dkg_params_sns(value: DKGParamsSnSTest) -> DKGParamsSnS {
    DKGParamsSnS {
        regular_params: convert_dkg_params_regular(value.regular_params),
        sns_params: convert_sns_parameters(value.sns_params),
        sns_compression_params: Some(convert_sns_compression_parameters(
            value.sns_compression_parameters,
        )),
    }
}

// Parameters `dedicated_compact_public_key_parameters` and `compression_decompression_parameters`
// are set to None because they are optional tfhe-rs types, which means their backward compatibility
// is already tested.
fn convert_dkg_params_regular(value: DKGParamsRegularTest) -> DKGParamsRegular {
    DKGParamsRegular {
        dkg_mode: DkgMode::Z128,
        sec: value.sec,
        ciphertext_parameters: convert_classic_pbs_parameters(value.ciphertext_parameters),
        dedicated_compact_public_key_parameters: None,
        compression_decompression_parameters: None,
        secret_key_deviations: None,
        cpk_re_randomization_ksk_params: None,
    }
}

fn convert_classic_pbs_parameters(value: ClassicPBSParametersTest) -> ClassicPBSParameters {
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
        modulus_switch_noise_reduction_params:
            tfhe_1_4::shortint::prelude::ModulusSwitchType::Standard,
    }
}

fn convert_sns_parameters(value: SwitchAndSquashParametersTest) -> NoiseSquashingParameters {
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(value.glwe_dimension),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(value.glwe_noise_distribution),
        polynomial_size: PolynomialSize(value.polynomial_size),
        decomp_base_log: DecompositionBaseLog(value.pbs_base_log),
        decomp_level_count: DecompositionLevelCount(value.pbs_level),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        modulus_switch_noise_reduction_params:
            tfhe_1_4::shortint::prelude::ModulusSwitchType::Standard,
        message_modulus: MessageModulus(value.message_modulus),
        carry_modulus: CarryModulus(value.carry_modulus),
    })
}

fn convert_sns_compression_parameters(
    value: SwitchAndSquashCompressionParametersTest,
) -> NoiseSquashingCompressionParameters {
    NoiseSquashingCompressionParameters {
        packing_ks_level: DecompositionLevelCount(value.packing_ks_level),
        packing_ks_base_log: DecompositionBaseLog(value.packing_ks_base_log),
        packing_ks_polynomial_size: PolynomialSize(value.packing_ks_polynomial_size),
        packing_ks_glwe_dimension: GlweDimension(value.packing_ks_glwe_dimension),
        lwe_per_glwe: LweCiphertextCount(value.lwe_per_glwe),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(
            value.packing_ks_key_noise_distribution,
        ),
        ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
        message_modulus: MessageModulus(value.message_modulus),
        carry_modulus: CarryModulus(value.carry_modulus),
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

// Distributed Decryption test
const PRF_KEY_TEST: PrfKeyTest = PrfKeyTest {
    test_filename: Cow::Borrowed("prf_key"),
    seed: 100,
};

// Distributed Decryption test
const PRSS_SET_64_TEST: PrssSetTest = PrssSetTest {
    test_filename: Cow::Borrowed("prss_set_64"),
    legacy_filename: Cow::Borrowed("legacy_prss_set_64"),
    amount_parties: 7,
    amount_points: 7,
    residue_poly_size: 64,
    state: 11111,
};

// Distributed Decryption test
const PRSS_SET_128_TEST: PrssSetTest = PrssSetTest {
    test_filename: Cow::Borrowed("prss_set_128"),
    legacy_filename: Cow::Borrowed("legacy_prss_set_128"),
    amount_parties: 13,
    amount_points: 3,
    residue_poly_size: 128,
    state: 2222,
};

// Distributed Decryption test
const SHARE_64_TEST: ShareTest = ShareTest {
    test_filename: Cow::Borrowed("share_64"),
    value: 34653246,
    owner: 1,
    residue_poly_size: 64,
};

// Distributed Decryption test
const SHARE_128_TEST: ShareTest = ShareTest {
    test_filename: Cow::Borrowed("share_128"),
    value: 934565743256423875434534434,
    owner: 1,
    residue_poly_size: 128,
};

// Distributed Decryption test
const RELEASE_PCR_VALUES_TEST: ReleasePCRValuesTest = ReleasePCRValuesTest {
    test_filename: Cow::Borrowed("release_pcr_values"),
    state: 64,
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

const PRIV_DATA_TYPE: PrivDataTypeTest = PrivDataTypeTest {
    test_filename: Cow::Borrowed("priv_data_type"),
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
const KEY_GEN_METADATA_TEST: KeyGenMetadataTest = KeyGenMetadataTest {
    test_filename: Cow::Borrowed("key_gen_metadata"),
    legacy_filename: Cow::Borrowed("legacy_key_gen_metadata"),
    state: 100,
};

// KMS test
const CRS_GEN_METADATA_TEST: CrsGenMetadataTest = CrsGenMetadataTest {
    test_filename: Cow::Borrowed("crs_gen_metadata"),
    legacy_filename: Cow::Borrowed("legacy_crs_gen_metadata"),
    state: 100,
    max_num_bits: 2048,
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

// KMS test
fn typed_plaintext_test() -> TypedPlaintextTest {
    TypedPlaintextTest {
        test_filename: Cow::Borrowed("typed_plaintext"),
        plaintext_bytes: vec![1, 2, 3, 4, 5],
        fhe_type: 8, // FheTypes::Uint8
    }
}

// KMS test
fn signcryption_payload_test() -> SigncryptionPayloadTest {
    SigncryptionPayloadTest {
        test_filename: Cow::Borrowed("signcryption_payload"),
        plaintext_bytes: vec![1, 2, 3, 4, 5],
        fhe_type: 8, // FheTypes::Uint8
        link: vec![222, 173, 190, 239],
    }
}

// KMS test
const SIGNCRYPTION_KEY_TEST: UnifiedSigncryptionKeyTest = UnifiedSigncryptionKeyTest {
    test_filename: Cow::Borrowed("signcryption_key"),
    state: 100,
};

// KMS test
const UNSIGNCRYPTION_KEY_TEST: UnifiedUnsigncryptionKeyTest = UnifiedUnsigncryptionKeyTest {
    test_filename: Cow::Borrowed("designcryption_key"),
    state: 200,
};

// KMS test
const UNIFIED_SIGNCRYPTION_TEST: UnifiedSigncryptionTest = UnifiedSigncryptionTest {
    test_filename: Cow::Borrowed("unified_signcryption"),
    state: 202,
};

// KMS test
const BACKUP_CIPHERTEXT_TEST: BackupCiphertextTest = BackupCiphertextTest {
    test_filename: Cow::Borrowed("backup_ciphertext"),
    unified_cipher_filename: Cow::Borrowed("unified_ciphertext_handle"),
    state: 200,
};

// KMS test
const UNIFIED_CIPHER_TEST: UnifiedCipherTest = UnifiedCipherTest {
    test_filename: Cow::Borrowed("unified_ciphertext"),
    hybrid_kem_filename: Cow::Borrowed("hybrid_kem_ct_handle"),
    state: 123,
};

// KMS test
const PRSS_SETUP_COMBINED_TEST: PrssSetupCombinedTest = PrssSetupCombinedTest {
    test_filename: Cow::Borrowed("prss_setup_combined"),
    prss_setup_64: Cow::Borrowed("prss_setup_64"),
    prss_setup_128: Cow::Borrowed("prss_setup_128"),
    role_i: 3,
    amount: 13,
    threshold: 4,
};

// KMS test
fn hybrid_kem_ct_test() -> HybridKemCtTest {
    HybridKemCtTest {
        test_filename: Cow::Borrowed("hybrid_kem_ct"),
        nonce: [2u8; 12],
        kem_ct: vec![1, 2, 3, 4, 5],
        payload_ct: vec![6, 7, 8, 9, 10],
    }
}

// KMS test
fn context_info_test() -> ContextInfoTest {
    ContextInfoTest {
        test_filename: Cow::Borrowed("context_info"),
        threshold: 3,
        state: 234,
    }
}

// KMS test
fn node_info_test() -> NodeInfoTest {
    NodeInfoTest {
        test_filename: Cow::Borrowed("node_info"),
        mpc_identity: Cow::Borrowed("node_mpc_identity"),
        party_id: 4,
        external_url: Cow::Borrowed("https://node4.example.com/mpc/something-something"),
        public_storage_url: Cow::Borrowed("https://storage.example.com/node4"),
        ca_cert: Some(vec![1, 2, 3, 4, 6, 7, 8, 9]),
        state: 500,
    }
}

// KMS test
const SOFTWARE_VERSION_TEST: SoftwareVersionTest = SoftwareVersionTest {
    test_filename: Cow::Borrowed("software_version"),
    major: 0,
    minor: 13,
    patch: 4,
    tag: Cow::Borrowed("super fun version"),
};

// KMS test
const RECOVERY_MATERIAL_TEST: RecoveryValidationMaterialTest = RecoveryValidationMaterialTest {
    test_filename: Cow::Borrowed("recovery_material"),
    internal_cus_context_filename: Cow::Borrowed("internal_cus_context_handle"),
    state: 300,
    custodian_count: 5,
};

// KMS test
const INTERNAL_RECOVERY_REQUEST_TEST: InternalRecoveryRequestTest = InternalRecoveryRequestTest {
    test_filename: Cow::Borrowed("internal_recovery_request"),
    amount: 10,
    state: 300,
};

// KMS test
const INTERNAL_CUS_CONTEXT_TEST: InternalCustodianContextTest = InternalCustodianContextTest {
    test_filename: Cow::Borrowed("internal_cus_context"),
    internal_cus_setup_filename: Cow::Borrowed("internal_cus_setup_handle"),
    unified_enc_key_filename: Cow::Borrowed("unified_enc_key_handle"),
    state: 300,
    custodian_count: 5,
};

// KMS test
const INTERNAL_CUS_SETUP_MSG_TEST: InternalCustodianSetupMessageTest =
    InternalCustodianSetupMessageTest {
        test_filename: Cow::Borrowed("internal_custodian_setup_message"),
        state: 42,
    };

// KMS test
const INTERNAL_CUS_REC_OUT_TEST: InternalCustodianRecoveryOutputTest =
    InternalCustodianRecoveryOutputTest {
        test_filename: Cow::Borrowed("internal_custodian_recovery_output"),
        state: 43,
    };

// KMS test
const OPERATOR_BACKUP_OUTPUT_TEST: OperatorBackupOutputTest = OperatorBackupOutputTest {
    test_filename: Cow::Borrowed("operator_backup_output"),
    custodian_count: 3,
    custodian_threshold: 1,
    plaintext: [0u8; 32],
    backup_id: [1u8; 32],
    seed: 42,
};

fn dummy_domain() -> alloy_sol_types_1_4_1::Eip712Domain {
    alloy_sol_types_1_4_1::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: alloy_primitives_1_4_1::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
    )
}

pub struct V0_13;

struct KmsV0_13;

impl KmsV0_13 {
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

    fn gen_typed_plaintext(dir: &PathBuf) -> TestMetadataKMS {
        let test = typed_plaintext_test();

        let plaintext = TypedPlaintext {
            bytes: test.plaintext_bytes.clone(),
            fhe_type: test.fhe_type,
        };

        // TypedPlaintext doesn't use tfhe-versionable, serialize directly with bincode
        let serialized = bc2wrap::serialize(&plaintext).unwrap();
        let filename = format!("{}.bincode", test.test_filename);
        std::fs::write(dir.join(&filename), serialized).unwrap();

        TestMetadataKMS::TypedPlaintext(test)
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

    fn gen_key_gen_metadata(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(KEY_GEN_METADATA_TEST.state);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        // We need to serialize something that is versioned, so let us just use signing keys for the test
        let (pretend_server_key, pretend_public_key) = gen_sig_keys(&mut rng);
        let preprocessing_id: RequestId = RequestId::new_random(&mut rng);
        let key_id: RequestId = RequestId::new_random(&mut rng);

        let mut key_digest_map: HashMap<PubDataType, Vec<u8>> = HashMap::new();
        let mut legacy: HashMap<PubDataType, SignedPubDataHandleInternal> = HashMap::new();
        let server_key_digest =
            safe_serialize_hash_element_versioned(b"TESTTEST", &pretend_server_key).unwrap();
        let pub_key_digest =
            safe_serialize_hash_element_versioned(b"TESTTEST", &pretend_public_key).unwrap();
        let sol_type = KeygenVerification::new(
            &preprocessing_id,
            &key_id,
            server_key_digest.clone(),
            pub_key_digest.clone(),
        );
        key_digest_map.insert(PubDataType::ServerKey, server_key_digest);
        key_digest_map.insert(PubDataType::PublicKey, pub_key_digest);
        let external_signature =
            compute_eip712_signature(&sig_key, &sol_type, &dummy_domain()).unwrap();

        legacy.insert(
            PubDataType::ServerKey,
            SignedPubDataHandleInternal {
                key_handle: key_id.to_string(),
                signature: vec![1_u8; 65],
                external_signature: external_signature.clone(),
            },
        );
        legacy.insert(
            PubDataType::PublicKey,
            SignedPubDataHandleInternal {
                key_handle: key_id.to_string(),
                signature: vec![2_u8; 65],
                external_signature: external_signature.clone(),
            },
        );

        let current = KeyGenMetadataInner {
            key_id,
            preprocessing_id,
            key_digest_map,
            external_signature,
        };
        store_versioned_auxiliary!(
            &legacy,
            dir,
            &KEY_GEN_METADATA_TEST.test_filename,
            &KEY_GEN_METADATA_TEST.legacy_filename,
        );
        store_versioned_test!(&current, dir, &KEY_GEN_METADATA_TEST.test_filename);

        TestMetadataKMS::KeyGenMetadata(KEY_GEN_METADATA_TEST)
    }

    fn gen_crs_metadata(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(CRS_GEN_METADATA_TEST.state);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let crs_id: RequestId = RequestId::new_random(&mut rng);
        let digest = [12u8; 32].to_vec();
        let max_num_bits = CRS_GEN_METADATA_TEST.max_num_bits;
        let sol_type = CrsgenVerification::new(&crs_id, max_num_bits as usize, digest.clone());
        let external_signature =
            compute_eip712_signature(&sig_key, &sol_type, &dummy_domain()).unwrap();
        let current_crs_meta_data =
            CrsGenMetadata::new(crs_id, digest, max_num_bits, external_signature.clone());

        let legacy_crs_meta_data = SignedPubDataHandleInternal::new(
            crs_id.to_string(),
            [3u8; 65].to_vec(),
            external_signature.clone(),
        );

        store_versioned_auxiliary!(
            &legacy_crs_meta_data,
            dir,
            &CRS_GEN_METADATA_TEST.test_filename,
            &CRS_GEN_METADATA_TEST.legacy_filename,
        );
        store_versioned_test!(
            &current_crs_meta_data,
            dir,
            &CRS_GEN_METADATA_TEST.test_filename
        );

        TestMetadataKMS::CrsGenMetadata(CRS_GEN_METADATA_TEST)
    }

    #[allow(clippy::ptr_arg)]
    fn gen_signcryption_payload(dir: &PathBuf) -> TestMetadataKMS {
        let test = signcryption_payload_test();

        let payload = SigncryptionPayload {
            plaintext: TypedPlaintext {
                bytes: test.plaintext_bytes.clone(),
                fhe_type: test.fhe_type,
            },
            link: test.link.clone(),
        };

        // SigncryptionPayload doesn't use tfhe-versionable, serialize with bc2wrap from v0.11.1
        // This uses the exact bc2wrap implementation and bincode version from v0.11.1
        let serialized = bc2wrap::serialize(&payload).unwrap();
        let filename = format!("{}.bincode", test.test_filename);
        std::fs::write(dir.join(&filename), serialized).unwrap();

        TestMetadataKMS::SigncryptionPayload(test)
    }

    fn gen_signcryption_key(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(SIGNCRYPTION_KEY_TEST.state);
        let (_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let (client_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let signcrypt_key = UnifiedSigncryptionKeyOwned::new(
            server_sig_key,
            enc_key,
            client_verf_key.verf_key_id(),
        );
        store_versioned_test!(&signcrypt_key, dir, &SIGNCRYPTION_KEY_TEST.test_filename);
        TestMetadataKMS::UnifiedSigncryptionKeyOwned(SIGNCRYPTION_KEY_TEST)
    }

    fn gen_designcryption_key(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(UNSIGNCRYPTION_KEY_TEST.state);
        let (sender_verf_key, _sender_sig_key) = gen_sig_keys(&mut rng);
        let (receiver_verf_key, _receiver_sig_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (dec_key, enc_key) = encryption.keygen().unwrap();
        let signcrypt_key = UnifiedUnsigncryptionKeyOwned::new(
            dec_key,
            enc_key,
            sender_verf_key,
            receiver_verf_key.verf_key_id().to_vec(),
        );
        store_versioned_test!(&signcrypt_key, dir, &UNSIGNCRYPTION_KEY_TEST.test_filename);
        TestMetadataKMS::UnifiedUnsigncryptionKeyOwned(UNSIGNCRYPTION_KEY_TEST)
    }

    fn gen_backup_ciphertext(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(BACKUP_CIPHERTEXT_TEST.state);
        let backup_id: RequestId = RequestId::new_random(&mut rng);
        // Generate the unified ciphertext after using the RNG for generating backup ID since backup ID
        // will also be generated as part of the test
        let mut kem_ct = [0_u8; 32];
        rng.fill_bytes(&mut kem_ct);
        let mut payload_ct = [0_u8; 32];
        rng.fill_bytes(&mut payload_ct);
        let ciphertext: UnifiedCipher = UnifiedCipher {
            cipher: HybridKemCt {
                nonce: [0_u8; 12],
                kem_ct: kem_ct.to_vec(),
                payload_ct: payload_ct.to_vec(),
            },
            pke_type: PkeSchemeType::MlKem512,
        };
        store_versioned_auxiliary!(
            &ciphertext,
            dir,
            &BACKUP_CIPHERTEXT_TEST.test_filename,
            &BACKUP_CIPHERTEXT_TEST.unified_cipher_filename,
        );

        let backup_ct = BackupCiphertext {
            ciphertext,
            priv_data_type: PrivDataType::SigningKey,
            backup_id,
        };

        store_versioned_test!(&backup_ct, dir, &BACKUP_CIPHERTEXT_TEST.test_filename);
        TestMetadataKMS::BackupCiphertext(BACKUP_CIPHERTEXT_TEST)
    }

    fn gen_unified_signcryption(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(UNIFIED_SIGNCRYPTION_TEST.state);
        let (verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let (client_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let signcrypt_key = UnifiedSigncryptionKeyOwned::new(
            server_sig_key,
            enc_key,
            client_verf_key.verf_key_id(),
        );
        let signcryption = signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &verf_key)
            .unwrap();

        store_versioned_test!(&signcryption, dir, &UNIFIED_SIGNCRYPTION_TEST.test_filename);
        TestMetadataKMS::UnifiedSigncryption(UNIFIED_SIGNCRYPTION_TEST)
    }

    fn gen_unified_cipher(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(UNIFIED_CIPHER_TEST.state);
        let mut kem_ct = [0_u8; 32];
        rng.fill_bytes(&mut kem_ct);
        let mut payload_ct = [0_u8; 32];
        rng.fill_bytes(&mut payload_ct);
        let kem = HybridKemCt {
            nonce: [0_u8; 12],
            kem_ct: kem_ct.to_vec(),
            payload_ct: payload_ct.to_vec(),
        };
        store_versioned_auxiliary!(
            &kem,
            dir,
            &UNIFIED_CIPHER_TEST.test_filename,
            &UNIFIED_CIPHER_TEST.hybrid_kem_filename,
        );
        let cipher = UnifiedCipher {
            cipher: kem,
            pke_type: PkeSchemeType::MlKem512,
        };

        store_versioned_test!(&cipher, dir, &UNIFIED_CIPHER_TEST.test_filename);

        TestMetadataKMS::UnifiedCipher(UNIFIED_CIPHER_TEST)
    }

    fn gen_hybrid_kem_ct(dir: &PathBuf) -> TestMetadataKMS {
        let test = hybrid_kem_ct_test();
        let cipher = HybridKemCt {
            nonce: test.nonce,
            kem_ct: test.kem_ct.clone(),
            payload_ct: test.payload_ct.clone(),
        };

        store_versioned_test!(&cipher, dir, &test.test_filename);

        TestMetadataKMS::HybridKemCt(test)
    }

    fn gen_prss_setup_combined(dir: &PathBuf) -> TestMetadataKMS {
        let role = Role::indexed_from_one(PRSS_SETUP_COMBINED_TEST.role_i);
        let base_session_64 = get_networkless_base_session_for_parties(
            PRSS_SETUP_COMBINED_TEST.amount as usize,
            PRSS_SETUP_COMBINED_TEST.threshold,
            role,
        );
        let base_session_128 = get_networkless_base_session_for_parties(
            PRSS_SETUP_COMBINED_TEST.amount as usize,
            PRSS_SETUP_COMBINED_TEST.threshold,
            role,
        );
        let prss_setup_z64 = get_dummy_prss_setup::<ResiduePolyF4Z64>(base_session_64);
        let prss_setup_z128 = get_dummy_prss_setup::<ResiduePolyF4Z128>(base_session_128);
        let prss = PRSSSetupCombined {
            prss_setup_z64: prss_setup_z64.clone(),
            prss_setup_z128: prss_setup_z128.clone(),
            num_parties: PRSS_SETUP_COMBINED_TEST.amount,
            threshold: PRSS_SETUP_COMBINED_TEST.threshold,
        };
        store_versioned_auxiliary!(
            &prss_setup_z64,
            dir,
            &PRSS_SETUP_COMBINED_TEST.test_filename,
            &PRSS_SETUP_COMBINED_TEST.prss_setup_64,
        );
        store_versioned_auxiliary!(
            &prss_setup_z128,
            dir,
            &PRSS_SETUP_COMBINED_TEST.test_filename,
            &PRSS_SETUP_COMBINED_TEST.prss_setup_128,
        );

        store_versioned_test!(&prss, dir, &PRSS_SETUP_COMBINED_TEST.test_filename);
        TestMetadataKMS::PrssSetupCombined(PRSS_SETUP_COMBINED_TEST)
    }

    fn gen_context_info(dir: &PathBuf) -> TestMetadataKMS {
        let test = context_info_test();
        let mut rng = AesRng::seed_from_u64(test.state);
        // Note that `NodeInfo`, `SoftwareVersion` and `ReleasePCRValues` are tested separately so we just do a simple static construction here
        let node_info = NodeInfo {
            mpc_identity: "Staoshi Nakamoto".to_string(),
            party_id: 42,
            verification_key: None,
            external_url: "https://node42.example.com".to_string(),
            ca_cert: None,
            public_storage_url: "https://storage.example.com/node42".to_string(),
            extra_verification_keys: vec![],
        };
        let software_version = SoftwareVersion {
            major: 2,
            minor: 11,
            patch: 12,
            tag: None,
        };
        let pcr_values = ReleasePCRValues {
            pcr0: vec![0_u8; 32],
            pcr1: vec![1_u8; 32],
            pcr2: vec![2_u8; 32],
        };
        let context_info = ContextInfo {
            mpc_nodes: vec![node_info.clone(), node_info.clone()],
            software_version,
            context_id: RequestId::new_random(&mut rng).into(),
            threshold: test.threshold,
            pcr_values: vec![pcr_values.clone(), pcr_values.clone()],
        };

        store_versioned_test!(&context_info, dir, &test.test_filename);

        TestMetadataKMS::ContextInfo(test)
    }

    fn gen_node_info(dir: &PathBuf) -> TestMetadataKMS {
        let node_info_test = node_info_test();
        let mut rng = AesRng::seed_from_u64(node_info_test.state);
        let (verf_key, _sig_key) = gen_sig_keys(&mut rng);
        let (verf_key2, _sig_key) = gen_sig_keys(&mut rng);
        let node_info = NodeInfo {
            mpc_identity: node_info_test.mpc_identity.to_string(),
            party_id: node_info_test.party_id,
            verification_key: Some(verf_key),
            external_url: node_info_test.external_url.to_string(),
            ca_cert: node_info_test.ca_cert.clone(), // We currently don't have simple code for generating certificates
            public_storage_url: node_info_test.public_storage_url.to_string(),
            extra_verification_keys: vec![verf_key2],
        };

        store_versioned_test!(&node_info, dir, &node_info_test.test_filename);

        TestMetadataKMS::NodeInfo(node_info_test)
    }

    fn gen_software_version(dir: &PathBuf) -> TestMetadataKMS {
        let software_version = SoftwareVersion {
            major: SOFTWARE_VERSION_TEST.major,
            minor: SOFTWARE_VERSION_TEST.minor,
            patch: SOFTWARE_VERSION_TEST.patch,
            tag: Some(SOFTWARE_VERSION_TEST.tag.to_string()),
        };

        store_versioned_test!(&software_version, dir, &SOFTWARE_VERSION_TEST.test_filename);

        TestMetadataKMS::SoftwareVersion(SOFTWARE_VERSION_TEST)
    }

    fn gen_recovery_material(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(RECOVERY_MATERIAL_TEST.state);
        let backup_id: RequestId = RequestId::new_random(&mut rng);
        let (operator_pk, operator_sk) = gen_sig_keys(&mut rng);
        let mut commitments = BTreeMap::new();
        let mut cts = BTreeMap::new();
        for role_j in 1..=RECOVERY_MATERIAL_TEST.custodian_count {
            let cus_role = Role::indexed_from_one(role_j);
            let (custodian_pk, _) = gen_sig_keys(&mut rng);
            let backup_material = BackupMaterial {
                backup_id,
                custodian_pk,
                custodian_role: cus_role,
                operator_pk: operator_pk.clone(),
                shares: Vec::new(),
            };
            let msg_digest =
                safe_serialize_hash_element_versioned(&DSEP_BACKUP_COMMITMENT, &backup_material)
                    .unwrap();
            commitments.insert(cus_role, msg_digest);
            let mut payload = [0_u8; 32];
            rng.fill_bytes(&mut payload);
            let cts_out = InnerOperatorBackupOutput {
                signcryption: UnifiedSigncryption {
                    payload: payload.to_vec(),
                    pke_type: PkeSchemeType::MlKem512,
                    signing_type: SigningSchemeType::Ecdsa256k1,
                },
            };
            cts.insert(cus_role, cts_out);
        }

        // Dummy payload; but needs to be a properly serialized payload
        // This must be generated after the commitment stuff, since the test will regenerate the commitment stuff,
        // but read the custodian context from disk
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (cus_pk, _) = gen_sig_keys(&mut rng);
        let payload = CustodianSetupMessagePayload {
            header: "header".to_string(),
            random_value: [4_u8; 32],
            timestamp: 0,
            public_enc_key: enc_key.clone(),
            verification_key: cus_pk.clone(),
        };
        let mut payload_serial = Vec::new();
        safe_serialize(&payload, &mut payload_serial, SAFE_SER_SIZE_LIMIT).unwrap();
        let mut custodian_nodes = Vec::new();
        for role_j in 1..=RECOVERY_MATERIAL_TEST.custodian_count {
            let setup_msg = CustodianSetupMessage {
                custodian_role: role_j as u64,
                name: format!("Custodian-{role_j}"),
                payload: payload_serial.clone(),
            };
            custodian_nodes.push(setup_msg);
        }
        let custodian_context = CustodianContext {
            custodian_nodes,
            context_id: Some(backup_id.into()),
            threshold: 1,
        };
        let internal_custodian_context =
            InternalCustodianContext::new(custodian_context, enc_key).unwrap();
        store_versioned_auxiliary!(
            &internal_custodian_context,
            dir,
            &RECOVERY_MATERIAL_TEST.test_filename,
            &RECOVERY_MATERIAL_TEST.internal_cus_context_filename,
        );
        let recovery_material = RecoveryValidationMaterial::new(
            cts,
            commitments,
            internal_custodian_context,
            &operator_sk,
        )
        .unwrap();
        store_versioned_test!(
            &recovery_material,
            dir,
            &RECOVERY_MATERIAL_TEST.test_filename
        );
        TestMetadataKMS::RecoveryValidationMaterial(RECOVERY_MATERIAL_TEST)
    }

    fn gen_internal_recovery_request(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(INTERNAL_RECOVERY_REQUEST_TEST.state);
        let backup_id: RequestId = RequestId::new_random(&mut rng);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let mut cts = BTreeMap::new();
        for role_j in 1..=INTERNAL_RECOVERY_REQUEST_TEST.amount {
            let cur_role = Role::indexed_from_one(role_j as usize);
            let mut payload = [0_u8; 32];
            rng.fill_bytes(&mut payload);
            let signcryption = UnifiedSigncryption {
                payload: payload.to_vec(),
                pke_type: PkeSchemeType::MlKem512,
                signing_type: SigningSchemeType::Ecdsa256k1,
            };
            cts.insert(cur_role, InnerOperatorBackupOutput { signcryption });
        }
        let recovery_material =
            InternalRecoveryRequest::new(enc_key, cts, backup_id, verf_key).unwrap();
        store_versioned_test!(
            &recovery_material,
            dir,
            &INTERNAL_RECOVERY_REQUEST_TEST.test_filename
        );
        TestMetadataKMS::InternalRecoveryRequest(INTERNAL_RECOVERY_REQUEST_TEST)
    }

    fn gen_internal_cus_context_handles(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(INTERNAL_CUS_CONTEXT_TEST.state);
        let context_id: RequestId = RequestId::new_random(&mut rng);
        let mut cus_nodes = BTreeMap::new();
        for role_j in 1..=INTERNAL_CUS_CONTEXT_TEST.custodian_count {
            let cus_role = Role::indexed_from_one(role_j);
            let (custodian_verf_key, _) = gen_sig_keys(&mut rng);
            let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
            let (_, cus_enc_key) = encryption.keygen().unwrap();
            let mut rnd = [0_u8; 32];
            rng.fill_bytes(&mut rnd);
            let setup_msg = InternalCustodianSetupMessage {
                header: "header".to_string(),
                custodian_role: cus_role,
                name: format!("role{role_j}"),
                random_value: rnd,
                timestamp: 42,
                public_enc_key: cus_enc_key,
                public_verf_key: custodian_verf_key,
            };
            cus_nodes.insert(cus_role, setup_msg);
        }
        // Generate the extra encryption key last since it will be loaded from file and
        // thus we should avoid using the RNG for the things that it will be used to generate in the test
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_, cus_enc_key) = encryption.keygen().unwrap();
        let internal_cus_context = InternalCustodianContext {
            threshold: 1,
            context_id,
            custodian_nodes: cus_nodes,
            backup_enc_key: cus_enc_key.clone(),
        };
        store_versioned_auxiliary!(
            &cus_enc_key,
            dir,
            &INTERNAL_CUS_CONTEXT_TEST.test_filename,
            &INTERNAL_CUS_CONTEXT_TEST.unified_enc_key_filename,
        );

        store_versioned_test!(
            &internal_cus_context,
            dir,
            &INTERNAL_CUS_CONTEXT_TEST.test_filename
        );

        TestMetadataKMS::InternalCustodianContext(INTERNAL_CUS_CONTEXT_TEST)
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

        let dkg_params: DKGParams = DKGParams::WithSnS(convert_dkg_params_sns(
            KMS_FHE_KEY_HANDLES_TEST.dkg_parameters_sns,
        ));
        let seed = Some(Seed(KMS_FHE_KEY_HANDLES_TEST.seed));

        let client_key = generate_client_fhe_key(dkg_params, Tag::default(), seed);
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
            server_key.6,
            Tag::default(),
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
        let key_id = kms_grpc_0_13_0::RequestId::zeros();
        let preproc_id = kms_grpc_0_13_0::RequestId::zeros();
        let kms_fhe_key_handles = KmsFheKeyHandles::new(
            &private_sig_key,
            client_key,
            &key_id,
            &preproc_id,
            &public_key_set,
            decompression_key,
            &dummy_domain(),
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
        let role = Role::indexed_from_one(THRESHOLD_FHE_KEYS_TEST.role_i);
        let mut base_session = get_networkless_base_session_for_parties(
            THRESHOLD_FHE_KEYS_TEST.amount,
            THRESHOLD_FHE_KEYS_TEST.threshold,
            role,
        );
        let dkg_params: DKGParams = DKGParams::WithSnS(convert_dkg_params_sns(
            THRESHOLD_FHE_KEYS_TEST.dkg_parameters_sns,
        ));

        let rt = Runtime::new().unwrap();
        let (fhe_pub_key_set, private_key_set) = rt.block_on(async {
            initialize_key_material(&mut base_session, dkg_params, Tag::default())
                .await
                .unwrap()
        });
        store_versioned_auxiliary!(
            &private_key_set,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename,
            &THRESHOLD_FHE_KEYS_TEST.private_key_set_filename,
        );

        let (integer_server_key, _, _, _, sns_key, _, _, _) =
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

        // NOTE: this is not deterministic since the result is a HashMap
        // compute_all_info doesn't exist in v0.11.1, so we create the metadata manually
        let info: HashMap<PubDataType, SignedPubDataHandleInternal> = HashMap::new();
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
            private_keys: std::sync::Arc::new(private_key_set),
            integer_server_key: std::sync::Arc::new(integer_server_key),
            sns_key: sns_key.map(std::sync::Arc::new),
            meta_data: kms_0_13_0::engine::base::KeyGenMetadata::LegacyV0(info),
            decompression_key: decompression_key.map(std::sync::Arc::new),
        };

        store_versioned_test!(
            &threshold_fhe_keys,
            dir,
            &THRESHOLD_FHE_KEYS_TEST.test_filename
        );

        TestMetadataKMS::ThresholdFheKeys(THRESHOLD_FHE_KEYS_TEST)
    }

    /// Generates the _internal_ custodian setup message
    fn gen_internal_cus_setup_msg(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(INTERNAL_CUS_SETUP_MSG_TEST.state);
        let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (private_key, public_key) = encryption.keygen().unwrap();
        let custodian = Custodian::new(
            Role::indexed_from_one(1),
            signing_key,
            public_key,
            private_key,
        )
        .unwrap();
        let custodian_setup_message = custodian
            .generate_setup_message(&mut rng, "custodian-1".to_string())
            .unwrap();
        store_versioned_test!(
            &custodian_setup_message,
            dir,
            &INTERNAL_CUS_SETUP_MSG_TEST.test_filename
        );
        TestMetadataKMS::InternalCustodianSetupMessage(INTERNAL_CUS_SETUP_MSG_TEST)
    }

    fn gen_internal_cus_rec_out(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(INTERNAL_CUS_REC_OUT_TEST.state);
        let (operator_verification_key, _) = gen_sig_keys(&mut rng);
        let mut buf = [0u8; 100];
        rng.fill_bytes(&mut buf);
        let signcryption = UnifiedSigncryption {
            payload: buf.to_vec(),
            pke_type: PkeSchemeType::MlKem512,
            signing_type: SigningSchemeType::Ecdsa256k1,
        };
        let icro = InternalCustodianRecoveryOutput {
            signcryption,
            custodian_role: Role::indexed_from_one(2),
            operator_verification_key,
        };
        store_versioned_test!(&icro, dir, &INTERNAL_CUS_REC_OUT_TEST.test_filename);
        TestMetadataKMS::InternalCustodianRecoveryOutput(INTERNAL_CUS_REC_OUT_TEST)
    }

    fn gen_operator_backup_output(dir: &PathBuf) -> TestMetadataKMS {
        let mut rng = AesRng::seed_from_u64(OPERATOR_BACKUP_OUTPUT_TEST.seed);

        let custodians: Vec<_> = (1..=OPERATOR_BACKUP_OUTPUT_TEST.custodian_count)
            .map(|i| {
                let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
                let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
                let (private_key, public_key) = encryption.keygen().unwrap();
                Custodian::new(
                    Role::indexed_from_one(i),
                    signing_key,
                    public_key,
                    private_key,
                )
                .unwrap()
            })
            .collect();
        let custodian_messages: Vec<_> = custodians
            .iter()
            .enumerate()
            .map(|(i, c)| {
                c.generate_setup_message(&mut rng, format!("Custodian-{i}"))
                    .unwrap()
            })
            .collect();

        let operator = {
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            Operator::new_for_sharing(
                custodian_messages,
                signing_key,
                OPERATOR_BACKUP_OUTPUT_TEST.custodian_threshold,
                custodians.len(),
            )
            .unwrap()
        };
        let operator_backup_output = &operator
            .secret_share_and_signcrypt(
                &mut rng,
                &OPERATOR_BACKUP_OUTPUT_TEST.plaintext,
                RequestId::from_bytes(OPERATOR_BACKUP_OUTPUT_TEST.backup_id),
            )
            .unwrap()
            .0[&Role::indexed_from_one(1)];

        store_versioned_test!(
            operator_backup_output,
            dir,
            &OPERATOR_BACKUP_OUTPUT_TEST.test_filename
        );
        TestMetadataKMS::OperatorBackupOutput(OPERATOR_BACKUP_OUTPUT_TEST)
    }
}

struct DistributedDecryptionV0_13;

impl DistributedDecryptionV0_13 {
    fn gen_prss_setup_rpoly_64(dir: &PathBuf) -> TestMetadataDD {
        let role = Role::indexed_from_one(PRSS_SETUP_RPOLY_64_TEST.role_i);
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
        let role = Role::indexed_from_one(PRSS_SETUP_RPOLY_128_TEST.role_i);
        let base_session = get_networkless_base_session_for_parties(
            PRSS_SETUP_RPOLY_128_TEST.amount,
            PRSS_SETUP_RPOLY_128_TEST.threshold,
            role,
        );
        let prss_setup = get_dummy_prss_setup::<ResiduePolyF4Z128>(base_session);

        store_versioned_test!(&prss_setup, dir, &PRSS_SETUP_RPOLY_128_TEST.test_filename);

        TestMetadataDD::PRSSSetup(PRSS_SETUP_RPOLY_128_TEST)
    }

    fn gen_prss_set_64(dir: &PathBuf) -> TestMetadataDD {
        let mut rng = AesRng::seed_from_u64(PRSS_SET_64_TEST.state);

        let mut party_set = Vec::new();
        for i in 1..=PRSS_SET_64_TEST.amount_parties {
            party_set.push(Role::indexed_from_one(i));
        }

        let mut set_key = [0u8; 16];
        rng.fill_bytes(&mut set_key);

        let mut f_a_points = Vec::new();
        for _ in 0..PRSS_SET_64_TEST.amount_points {
            f_a_points.push(ResiduePolyF4Z64::from_scalar(Wrapping(rng.next_u64())));
        }

        let current_set = PrssSet::<ResiduePolyF4Z64>::new(
            party_set.clone(),
            PrfKey(set_key.clone()),
            f_a_points.clone(),
        );
        let legacy_set = PrssSetV0::<ResiduePolyF4Z64>::new(
            party_set.iter().map(|r| r.one_based()).collect(),
            PrfKey(set_key.clone()),
            f_a_points.clone(),
        );
        store_versioned_auxiliary!(
            &legacy_set.upgrade().unwrap(),
            dir,
            &PRSS_SET_64_TEST.test_filename,
            &PRSS_SET_64_TEST.legacy_filename,
        );
        store_versioned_test!(&current_set, dir, &PRSS_SET_64_TEST.test_filename);

        TestMetadataDD::PrssSet(PRSS_SET_64_TEST)
    }

    fn gen_prss_set_128(dir: &PathBuf) -> TestMetadataDD {
        let mut rng = AesRng::seed_from_u64(PRSS_SET_128_TEST.state);

        let mut party_set = Vec::new();
        for i in 1..=PRSS_SET_128_TEST.amount_parties {
            party_set.push(Role::indexed_from_one(i));
        }

        let mut set_key = [0u8; 16];
        rng.fill_bytes(&mut set_key);

        let mut f_a_points = Vec::new();
        for _ in 0..PRSS_SET_128_TEST.amount_points {
            f_a_points.push(ResiduePolyF4Z128::from_scalar(Wrapping(
                rng.next_u64() as u128
            )));
        }

        let current_set = PrssSet::<ResiduePolyF4Z128>::new(
            party_set.clone(),
            PrfKey(set_key.clone()),
            f_a_points.clone(),
        );
        let legacy_set = PrssSetV0::<ResiduePolyF4Z128>::new(
            party_set.iter().map(|r| r.one_based()).collect(),
            PrfKey(set_key.clone()),
            f_a_points.clone(),
        );
        store_versioned_auxiliary!(
            &legacy_set.upgrade().unwrap(),
            dir,
            &PRSS_SET_128_TEST.test_filename,
            &PRSS_SET_128_TEST.legacy_filename,
        );
        store_versioned_test!(&current_set, dir, &PRSS_SET_128_TEST.test_filename);

        TestMetadataDD::PrssSet(PRSS_SET_128_TEST)
    }

    fn gen_share_64(dir: &PathBuf) -> TestMetadataDD {
        let role = Role::indexed_from_one(SHARE_64_TEST.owner);
        let val = ResiduePolyF4Z64::from_scalar(Wrapping(SHARE_64_TEST.value as u64));
        let share = Share::<ResiduePolyF4Z64>::new(role, val);

        store_versioned_test!(&share, dir, &SHARE_64_TEST.test_filename);

        TestMetadataDD::Share(SHARE_64_TEST)
    }

    fn gen_share_128(dir: &PathBuf) -> TestMetadataDD {
        let role = Role::indexed_from_one(SHARE_128_TEST.owner);
        let val = ResiduePolyF4Z128::from_scalar(Wrapping(SHARE_128_TEST.value));
        let share = Share::<ResiduePolyF4Z128>::new(role, val);

        store_versioned_test!(&share, dir, &SHARE_128_TEST.test_filename);

        TestMetadataDD::Share(SHARE_128_TEST)
    }

    fn gen_prf_key(dir: &PathBuf) -> TestMetadataDD {
        let mut buf = [0u8; 16];
        let mut rng = AesRng::from_seed(PRF_KEY_TEST.seed.to_le_bytes());
        rng.fill_bytes(&mut buf);

        let prf_key = PrfKey(buf);

        store_versioned_test!(&prf_key, dir, &PRF_KEY_TEST.test_filename);

        TestMetadataDD::PrfKey(PRF_KEY_TEST)
    }

    fn gen_release_pcr_values(dir: &PathBuf) -> TestMetadataDD {
        let mut rng = AesRng::seed_from_u64(RELEASE_PCR_VALUES_TEST.state);
        let mut pcr0 = [0u8; 64];
        rng.fill_bytes(&mut pcr0);
        let mut pcr1 = [0u8; 33];
        rng.fill_bytes(&mut pcr1);
        let mut pcr2 = [0u8; 73];
        rng.fill_bytes(&mut pcr2);

        let pcr_values = ReleasePCRValues {
            pcr0: pcr0.to_vec(),
            pcr1: pcr1.to_vec(),
            pcr2: pcr2.to_vec(),
        };

        store_versioned_test!(&pcr_values, dir, &RELEASE_PCR_VALUES_TEST.test_filename);

        TestMetadataDD::ReleasePCRValues(RELEASE_PCR_VALUES_TEST)
    }
}

struct KmsGrpcV0_13;

impl KmsGrpcV0_13 {
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

    fn gen_priv_data_type(dir: &PathBuf) -> TestMetadataKmsGrpc {
        let priv_data_type = PrivDataType::ContextInfo;
        store_versioned_test!(&priv_data_type, dir, &PRIV_DATA_TYPE.test_filename);

        TestMetadataKmsGrpc::PrivDataType(PRIV_DATA_TYPE)
    }
}

impl KMSCoreVersion for V0_13 {
    const VERSION_NUMBER: &'static str = "0.13.0";

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
            KmsV0_13::gen_private_sig_key(&dir),
            KmsV0_13::gen_public_sig_key(&dir),
            KmsV0_13::gen_app_key_blob(&dir),
            KmsV0_13::gen_key_gen_metadata(&dir),
            KmsV0_13::gen_crs_metadata(&dir),
            KmsV0_13::gen_typed_plaintext(&dir),
            KmsV0_13::gen_signcryption_payload(&dir),
            KmsV0_13::gen_signcryption_key(&dir),
            KmsV0_13::gen_designcryption_key(&dir),
            KmsV0_13::gen_unified_signcryption(&dir),
            KmsV0_13::gen_backup_ciphertext(&dir),
            KmsV0_13::gen_unified_cipher(&dir),
            KmsV0_13::gen_hybrid_kem_ct(&dir),
            KmsV0_13::gen_prss_setup_combined(&dir),
            KmsV0_13::gen_context_info(&dir),
            KmsV0_13::gen_node_info(&dir),
            KmsV0_13::gen_software_version(&dir),
            KmsV0_13::gen_recovery_material(&dir),
            KmsV0_13::gen_internal_recovery_request(&dir),
            KmsV0_13::gen_internal_cus_context_handles(&dir),
            KmsV0_13::gen_internal_cus_setup_msg(&dir),
            KmsV0_13::gen_kms_fhe_key_handles(&dir),
            KmsV0_13::gen_threshold_fhe_keys(&dir),
            KmsV0_13::gen_internal_cus_rec_out(&dir),
            KmsV0_13::gen_operator_backup_output(&dir),
        ]
    }

    fn gen_threshold_fhe_data() -> Vec<TestMetadataDD> {
        let dir = Self::data_dir().join(DISTRIBUTED_DECRYPTION_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            DistributedDecryptionV0_13::gen_prss_setup_rpoly_64(&dir),
            DistributedDecryptionV0_13::gen_prss_setup_rpoly_128(&dir),
            DistributedDecryptionV0_13::gen_prss_set_64(&dir),
            DistributedDecryptionV0_13::gen_prss_set_128(&dir),
            DistributedDecryptionV0_13::gen_share_64(&dir),
            DistributedDecryptionV0_13::gen_share_128(&dir),
            DistributedDecryptionV0_13::gen_prf_key(&dir),
            DistributedDecryptionV0_13::gen_release_pcr_values(&dir),
        ]
    }

    fn gen_kms_grpc_data() -> Vec<TestMetadataKmsGrpc> {
        let dir = Self::data_dir().join(KMS_GRPC_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        vec![
            KmsGrpcV0_13::gen_signed_pub_data_handle_internal(&dir),
            KmsGrpcV0_13::gen_public_key_type(&dir),
            KmsGrpcV0_13::gen_pub_data_type(&dir),
            KmsGrpcV0_13::gen_priv_data_type(&dir),
        ]
    }
}
