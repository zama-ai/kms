//! Tests breaking change in serialized data by trying to load historical data stored in `backward-compatibility/data`.
//! For each kms-core module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tells
//! what to test for each message.
//!

mod common;
use common::{load_and_unversionize, load_and_unversionize_auxiliary};

use aes_prng::AesRng;
use backward_compatibility::{
    data_dir,
    load::{DataFormat, TestFailure, TestResult, TestSuccess},
    tests::{run_all_tests, TestedModule},
    AppKeyBlobTest, BackupCiphertextTest, HybridKemCtTest, InternalCustodianContextTest,
    InternalCustodianSetupMessageTest, KmsFheKeyHandlesTest, OperatorBackupOutputTest,
    PrivateSigKeyTest, PublicSigKeyTest, RecoveryValidationMaterialTest, SigncryptionPayloadTest,
    TestMetadataKMS, TestType, Testcase, ThresholdFheKeysTest, TypedPlaintextTest,
    UnifiedCipherTest, UnifiedDesigncryptionKeyTest, UnifiedSigncryptionKeyTest,
};
use kms_grpc::{
    kms::v1::TypedPlaintext,
    rpc_types::{PrivDataType, PubDataType, SignedPubDataHandleInternal},
    RequestId,
};
use kms_lib::{
    backup::{
        custodian::{Custodian, InternalCustodianContext, InternalCustodianSetupMessage},
        operator::{
            BackupMaterial, InnerOperatorBackupOutput, Operator, RecoveryValidationMaterial,
            DSEP_BACKUP_COMMITMENT,
        },
        BackupCiphertext,
    },
    cryptography::{
        encryption::{
            Encryption, EncryptionScheme, EncryptionSchemeType, UnifiedCipher, UnifiedPublicEncKey,
        },
        hybrid_ml_kem::HybridKemCt,
        signatures::{gen_sig_keys, PrivateSigKey, PublicSigKey},
        signcryption::{
            SigncryptionPayload, UnifiedDesigncryptionKeyOwned, UnifiedSigncryptionKeyOwned,
        },
    },
    engine::{
        base::{safe_serialize_hash_element_versioned, KeyGenMetadata, KmsFheKeyHandles},
        threshold::service::ThresholdFheKeys,
    },
    util::key_setup::FhePublicKey,
    vault::keychain::AppKeyBlob,
};
use rand::RngCore;
use rand::SeedableRng;
use std::{
    collections::{BTreeMap, HashMap},
    env,
    path::Path,
    sync::Arc,
};
use tfhe::integer::compression_keys::DecompressionKey;
use threshold_fhe::execution::{
    runtime::party::Role, tfhe_internals::public_keysets::FhePubKeySet,
};

// This domain should match what is in the data_XX.rs file in backward compatibility.
fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "Authorization token",
        version: "1",
        chain_id: 8006,
        verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
    )
}

fn test_private_sig_key(
    dir: &Path,
    test: &PrivateSigKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PrivateSigKey = load_and_unversionize(dir, test, format)?;

    let mut rng = AesRng::seed_from_u64(test.state);
    let (_, new_versionized) = gen_sig_keys(&mut rng);

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid private sig key:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_typed_plaintext(
    dir: &Path,
    test: &TypedPlaintextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    // Load the serialized TypedPlaintext
    // Note: TypedPlaintext doesn't use tfhe-versionable, so we deserialize directly
    let original: TypedPlaintext = match format {
        DataFormat::Bincode => {
            let path = dir.join(format!("{}.bincode", test.test_filename()));
            let bytes = std::fs::read(&path).map_err(|e| {
                test.failure(
                    format!("Failed to read file {}: {}", path.display(), e),
                    format,
                )
            })?;
            bc2wrap::deserialize(&bytes).map_err(|e| {
                test.failure(
                    format!("Failed to deserialize TypedPlaintext: {}", e),
                    format,
                )
            })?
        }
    };

    // Create expected plaintext
    let expected = kms_grpc::kms::v1::TypedPlaintext {
        bytes: test.plaintext_bytes.clone(),
        fhe_type: test.fhe_type,
    };

    // Compare
    if original != expected {
        Err(test.failure(
            format!("Invalid TypedPlaintext:\n Expected :\n{expected:?}\nGot:\n{original:?}"),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_app_key_blob(
    dir: &Path,
    test: &AppKeyBlobTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: AppKeyBlob = load_and_unversionize(dir, test, format)?;

    let new_versionized = AppKeyBlob {
        root_key_id: test.root_key_id.to_string(),
        data_key_blob: test.data_key_blob.clone().into_owned().into(),
        ciphertext: test.ciphertext.clone().into_owned().into(),
        iv: test.iv.clone().into_owned().into(),
        auth_tag: test.auth_tag.clone().into_owned().into(),
    };

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid app key blob:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_signcryption_payload(
    dir: &Path,
    test: &SigncryptionPayloadTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    // Load the serialized SigncryptionPayload
    // Note: SigncryptionPayload doesn't use tfhe-versionable, so we deserialize directly
    let original: SigncryptionPayload = match format {
        DataFormat::Bincode => {
            let path = dir.join(format!("{}.bincode", test.test_filename()));
            let bytes = std::fs::read(&path).map_err(|e| {
                test.failure(
                    format!("Failed to read file {}: {}", path.display(), e),
                    format,
                )
            })?;
            bc2wrap::deserialize(&bytes).map_err(|e| {
                test.failure(
                    format!("Failed to deserialize SigncryptionPayload: {}", e),
                    format,
                )
            })?
        }
    };

    // Create expected payload from metadata
    let expected = SigncryptionPayload {
        plaintext: kms_grpc::kms::v1::TypedPlaintext {
            bytes: test.plaintext_bytes.clone(),
            fhe_type: test.fhe_type,
        },
        link: test.link.clone(),
    };

    // Compare
    if original != expected {
        Err(test.failure(
            format!("Invalid SigncryptionPayload:\n Expected :\n{expected:?}\nGot:\n{original:?}"),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_public_sig_key(
    dir: &Path,
    test: &PublicSigKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PublicSigKey = load_and_unversionize(dir, test, format)?;

    let mut rng = AesRng::seed_from_u64(test.state);
    let (new_versionized, _) = gen_sig_keys(&mut rng);

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid public sig key:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_signcryption_keys(
    dir: &Path,
    test: &UnifiedSigncryptionKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: UnifiedSigncryptionKeyOwned =
        load_and_unversionize(dir, test, format)?;
    let mut rng = AesRng::seed_from_u64(test.state);
    let (_, server_sig_key) = gen_sig_keys(&mut rng);
    let (client_verf_key, _) = gen_sig_keys(&mut rng);
    let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
    let (_, enc_key) = encryption.keygen().unwrap();
    let new_versionized = UnifiedSigncryptionKeyOwned::new(
        server_sig_key.clone(),
        enc_key,
        client_verf_key.verf_key_id().to_vec(),
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid UnifiedSigncryptionKeyOwned:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

/// Observe that this test also indirectly tests UnifiedPublicEncKey and UnifiedPrivateEncKey
/// Also note that while these keys are currently not stored on disc, they are generated from a seedphrase
/// for the custodians, so we still need to ensure that they do not change format unexpectedly!
/// Hence we keep them versioned
fn test_designcryption_keys(
    dir: &Path,
    test: &UnifiedDesigncryptionKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: UnifiedDesigncryptionKeyOwned =
        load_and_unversionize(dir, test, format)?;
    let mut rng = AesRng::seed_from_u64(test.state);
    let (server_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);
    let (client_verf_key, _client_sig_key) = gen_sig_keys(&mut rng);
    let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
    let (dec_key, enc_key) = encryption.keygen().unwrap();
    let new_versionized = UnifiedDesigncryptionKeyOwned::new(
        dec_key,
        enc_key,
        server_verf_key,
        client_verf_key.verf_key_id(),
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid UnifiedDesigncryptionKeyOwned:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_backup_ciphertext(
    dir: &Path,
    test: &BackupCiphertextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: BackupCiphertext = load_and_unversionize(dir, test, format)?;
    let mut rng = AesRng::seed_from_u64(test.state);
    let mut ct = [0_u8; 32];
    rng.fill_bytes(&mut ct);
    let ciphertext: UnifiedCipher = UnifiedCipher {
        cipher: ct.to_vec(),
        encryption_type: EncryptionSchemeType::MlKem512,
    };
    let backup_id: RequestId = RequestId::new_random(&mut rng);
    let new_versionized = BackupCiphertext {
        ciphertext,
        priv_data_type: PrivDataType::SigningKey,
        backup_id,
    };
    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid BackupCiphertext:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_unified_cipher(
    dir: &Path,
    test: &UnifiedCipherTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: UnifiedCipher = load_and_unversionize(dir, test, format)?;
    let new_versionized = UnifiedCipher {
        cipher: test.cipher.clone(),
        encryption_type: EncryptionSchemeType::MlKem512,
    };
    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid UnifiedCipher:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_hybrid_kem_ct(
    dir: &Path,
    test: &HybridKemCtTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    // Load the serialized HybridKemCt
    let original_versionized: HybridKemCt = load_and_unversionize(dir, test, format)?;
    // // Observe that what we want to test is that we can still correctly decrypt an old CT even if the encryption algorithm change
    // let mut ct_buf = Vec::new();
    // tfhe::safe_serialization::safe_serialize(&test.ciphertext, &mut ct_buf, SAFE_SER_SIZE_LIMIT)
    //     .unwrap();
    // let ct = UnifiedCipher {
    //     cipher: ct_buf,
    //     encryption_type: EncryptionSchemeType::MlKem512,
    // };
    // let mut rng = AesRng::seed_from_u64(test.state);
    // let dec_key: UnifiedPrivateEncKey =
    //     load_and_unversionize_auxiliary(dir, test, &test.dec_key_path, format)?;
    // let res: storage::TestType = dec_key.decrypt(&ct).unwrap();
    // if res.i != test.plaintext {
    //     return Err(test.failure(
    //         format!(
    //             "Invalid HybridKemCt:\n Expected :\n{:?}\nGot:\n{:?}",
    //             res.i, test.plaintext
    //         ),
    //         format,
    //     ));
    // }
    // For completeness also ensure that format is the same, although not strictly needed

    let new_versionized = HybridKemCt {
        nonce: test.nonce,
        kem_ct: test.kem_ct.clone(),
        payload_ct: test.payload_ct.clone(),
    };
    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid UnifiedCipher:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_recovery_material(
    dir: &Path,
    test: &RecoveryValidationMaterialTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: RecoveryValidationMaterial =
        load_and_unversionize(dir, test, format)?;
    let icc: InternalCustodianContext =
        load_and_unversionize_auxiliary(dir, test, &test.internal_cus_context_filename, format)?;
    let mut rng = AesRng::seed_from_u64(test.state);
    let backup_id: RequestId = RequestId::new_random(&mut rng);
    let (operator_pk, operator_sk) = gen_sig_keys(&mut rng);
    let mut commitments = BTreeMap::new();
    for role_j in 1..=test.custodian_count {
        let cus_role = Role::indexed_from_one(role_j);
        let (custodian_pk, _) = gen_sig_keys(&mut rng);
        let backup_material = BackupMaterial {
            backup_id,
            custodian_pk,
            custodian_role: cus_role,
            operator_pk: operator_pk.clone(),
            operator_role: Role::indexed_from_one(1),
            shares: Vec::new(),
        };
        let msg_digest =
            safe_serialize_hash_element_versioned(&DSEP_BACKUP_COMMITMENT, &backup_material)
                .unwrap();
        commitments.insert(cus_role, msg_digest);
    }
    let new_versionized = RecoveryValidationMaterial::new(commitments, icc, &operator_sk).unwrap();

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid RecoveryValidationMaterial:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_internal_custodian_context(
    dir: &Path,
    test: &InternalCustodianContextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: InternalCustodianContext = load_and_unversionize(dir, test, format)?;
    let enc_key: UnifiedPublicEncKey =
        load_and_unversionize_auxiliary(dir, test, &test.unified_enc_key_filename, format)?;
    let mut rng = AesRng::seed_from_u64(test.state);
    let context_id: RequestId = RequestId::new_random(&mut rng);
    let mut cus_nodes = BTreeMap::new();
    for role_j in 1..=test.custodian_count {
        let cus_role = Role::indexed_from_one(role_j);
        let (custodian_verf_key, _) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
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
    let new_versionized = InternalCustodianContext {
        threshold: 1,
        context_id,
        previous_context_id: None,
        custodian_nodes: cus_nodes,
        backup_enc_key: enc_key,
    };

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid InternalCustodianContext:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_kms_fhe_key_handles(
    dir: &Path,
    test: &KmsFheKeyHandlesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: KmsFheKeyHandles = load_and_unversionize(dir, test, format)?;

    // Retrieve the key parameters from the original KMS handle
    let (original_integer_key, _, _, _, _, _, _) =
        original_versionized.client_key.clone().into_raw_parts();
    let original_key_params = original_integer_key.parameters();

    let client_key: tfhe::ClientKey =
        load_and_unversionize_auxiliary(dir, test, &test.client_key_filename, format)?;

    let private_sig_key: PrivateSigKey =
        load_and_unversionize_auxiliary(dir, test, &test.sig_key_filename, format)?;

    let server_key: tfhe::ServerKey =
        load_and_unversionize_auxiliary(dir, test, &test.server_key_filename, format)?;

    let public_key: FhePublicKey =
        load_and_unversionize_auxiliary(dir, test, &test.public_key_filename, format)?;

    let fhe_pub_key_set = FhePubKeySet {
        public_key,
        server_key,
    };

    let decompression_key: Option<DecompressionKey> =
        load_and_unversionize_auxiliary(dir, test, &test.decompression_key_filename, format)?;

    let key_id = RequestId::zeros();
    let preproc_id = RequestId::zeros();
    let new_versionized = KmsFheKeyHandles::new(
        &private_sig_key,
        client_key,
        &key_id,
        &preproc_id,
        &fhe_pub_key_set,
        decompression_key,
        &dummy_domain(),
    )
    .unwrap();

    // Retrieve the key parameters from the new KMS handle
    let (new_integer_key, _, _, _, _, _, _) = new_versionized.client_key.clone().into_raw_parts();
    let new_key_params = new_integer_key.parameters();

    // Compare the key parameters and the public key info. We cannot directly compare KmsFheKeyHandles
    // by adding the `PartialEq` trait because TFHE-rs' ClientKey are not able to be directly
    // compared. Instead, we compare the parameters, as done in TFHE-rs' tests
    if new_key_params != original_key_params {
        Err(test.failure(
            format!(
                "Invalid KMS FHE key handles because of different parameters:\n Expected :\n{original_key_params:?}\nGot:\n{new_key_params:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_threshold_fhe_keys(
    dir: &Path,
    test: &ThresholdFheKeysTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let private_keys =
        load_and_unversionize_auxiliary(dir, test, &test.private_key_set_filename, format)?;

    let integer_server_key: tfhe::integer::ServerKey =
        load_and_unversionize_auxiliary(dir, test, &test.integer_server_key_filename, format)?;

    let sns_key: Option<tfhe::integer::noise_squashing::NoiseSquashingKey> =
        load_and_unversionize_auxiliary(dir, test, &test.sns_key_filename, format)?;

    // NOTE: we use the old HashMap type here, instead of KeyGenMetadata
    // this is ok because we never explicitly write pk_meta_data to dist so there's no need
    // to read the new type KeyGenMetadata.
    // But we still need to fetch the correct information so that we can do the comparison.
    let pk_meta_data: HashMap<PubDataType, SignedPubDataHandleInternal> =
        load_and_unversionize_auxiliary(dir, test, &test.info_filename, format)?;

    let decompression_key: Option<DecompressionKey> =
        load_and_unversionize_auxiliary(dir, test, &test.decompression_key_filename, format)?;

    let original_versionized: ThresholdFheKeys = load_and_unversionize(dir, test, format)?;

    let new_versionized = ThresholdFheKeys {
        private_keys: Arc::new(private_keys),
        integer_server_key: Arc::new(integer_server_key),
        sns_key: sns_key.map(Arc::new),
        decompression_key: decompression_key.map(Arc::new),
        meta_data: KeyGenMetadata::LegacyV0(pk_meta_data),
    };

    // Retrieve the key parameters from the new KMS handle
    let new_key_params = new_versionized.private_keys.parameters;
    let original_key_params = original_versionized.private_keys.parameters;

    // Compare the key parameters and the public key info. We cannot directly compare ThresholdFheKeys
    // by adding the `PartialEq` trait because TFHE-rs' Decompression keys are not able to be directly
    // compared. Instead, we compare the parameters, as done in TFHE-rs' tests
    if new_key_params != original_key_params {
        Err(test.failure(
            format!(
                "Invalid KMS FHE key handles because of different parameters:\n Expected :\n{original_key_params:?}\nGot:\n{new_key_params:?}"
            ),
            format,
        ))
    } else if original_versionized.meta_data != new_versionized.meta_data {
        Err(test.failure(
            format!(
                "Invalid KMS FHE key handles because of different public key info:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized.meta_data, new_versionized.meta_data
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_internal_custodian_message(
    dir: &Path,
    test: &InternalCustodianSetupMessageTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_custodian_setup_message: InternalCustodianSetupMessage =
        load_and_unversionize(dir, test, format)?;

    let mut rng = AesRng::seed_from_u64(test.seed);
    let name = "Testname".to_string();
    let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
    let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
    let (dec_key, enc_key) = enc.keygen().unwrap();
    let custodian =
        Custodian::new(Role::indexed_from_zero(0), signing_key, enc_key, dec_key).unwrap();
    let mut new_custodian_setup_message = custodian.generate_setup_message(&mut rng, name).unwrap();

    // the timestamp will never match, so we modify it manually
    // the timestamp also affects the signature, so modify it as well
    new_custodian_setup_message.timestamp = original_custodian_setup_message.timestamp;

    if original_custodian_setup_message != new_custodian_setup_message {
        Err(test.failure(
            format!(
                "Invalid custodian setup message:\n original:\n{original_custodian_setup_message:?},\nactual:\n{new_custodian_setup_message:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_operator_backup_output(
    dir: &Path,
    test: &OperatorBackupOutputTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_operator_backup_output: InnerOperatorBackupOutput =
        load_and_unversionize(dir, test, format)?;

    let mut rng = AesRng::seed_from_u64(test.seed);
    let custodians: Vec<_> = (0..test.custodian_count)
        .map(|i| {
            let custodian_role = Role::indexed_from_zero(i);
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
            let (dec_key, enc_key) = enc.keygen().unwrap();
            Custodian::new(custodian_role, signing_key, enc_key, dec_key).unwrap()
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
        Operator::new(
            Role::indexed_from_zero(0),
            custodian_messages.clone(),
            signing_key,
            test.custodian_threshold,
            custodian_messages.len(), // Testing a sunshine case where all custodians are present
        )
        .unwrap()
    };
    let (cts, _commitments) = &operator
        .secret_share_and_signcrypt(
            &mut rng,
            &test.plaintext,
            RequestId::from_bytes(test.backup_id),
        )
        .unwrap();
    let new_operator_backup_output = &cts[&operator.role()];
    if original_operator_backup_output != *new_operator_backup_output {
        Err(test.failure(
            format!(
                "Invalid operator backup output:\n original:\n{original_operator_backup_output:?},\nactual:\n{new_operator_backup_output:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

pub struct KMS;

impl TestedModule for KMS {
    type Metadata = TestMetadataKMS;
    const METADATA_FILE: &'static str = "kms.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            Self::Metadata::PublicSigKey(test) => {
                test_public_sig_key(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::PrivateSigKey(test) => {
                test_private_sig_key(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::TypedPlaintext(test) => {
                test_typed_plaintext(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KmsFheKeyHandles(test) => {
                test_kms_fhe_key_handles(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::ThresholdFheKeys(test) => {
                test_threshold_fhe_keys(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::AppKeyBlob(test) => {
                test_app_key_blob(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::SigncryptionPayload(test) => {
                test_signcryption_payload(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::UnifiedSigncryptionKeyOwned(test) => {
                test_signcryption_keys(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::UnifiedDesigncryptionKeyOwned(test) => {
                test_designcryption_keys(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::BackupCiphertext(test) => {
                test_backup_ciphertext(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::UnifiedCipher(test) => {
                test_unified_cipher(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::HybridKemCt(test) => {
                test_hybrid_kem_ct(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::RecoveryValidationMaterial(test) => {
                test_recovery_material(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::InternalCustodianContext(test) => {
                test_internal_custodian_context(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::InternalCustodianSetupMessage(test) => {
                test_internal_custodian_message(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::OperatorBackupOutput(test) => {
                test_operator_backup_output(test_dir.as_ref(), test, format).into()
            }
        }
    }
}

#[test]
fn test_backward_compatibility_kms() {
    let pkg_version = env!("CARGO_PKG_VERSION");

    let base_data_dir = data_dir();

    let results = run_all_tests::<KMS>(&base_data_dir, pkg_version);

    for r in results.iter() {
        if r.is_failure() {
            panic!("Backward compatibility tests for the KMS module failed: {r:?}")
        }
    }
}
