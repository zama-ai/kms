//! Tests breaking change in serialized data by trying to load historical data stored in `backward-compatibility/data`.
//! For each events module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tells
//! what to test for each message.

use backward_compatibility::{
    data_dir,
    load::{DataFormat, TestFailure, TestResult, TestSuccess},
    tests::{run_all_tests, TestedModule},
    CrsGenResponseValuesTest, CrsGenValuesTest, DecryptResponseValuesTest, DecryptValuesTest,
    InsecureKeyGenValuesTest, KeyGenPreprocResponseValuesTest, KeyGenPreprocValuesTest,
    KeyGenResponseValuesTest, KeyGenValuesTest, KmsCoreConfTest, ReencryptResponseValuesTest,
    ReencryptValuesTest, TestMetadataEvents, TestType, Testcase, ZkpResponseValuesTest,
    ZkpValuesTest,
};
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, FheParameter,
    FheType, InsecureKeyGenValues, KeyGenPreprocResponseValues, KeyGenPreprocValues,
    KeyGenResponseValues, KeyGenValues, KmsCoreConf, KmsCoreParty, OperationValue,
    ReencryptResponseValues, ReencryptValues, Transaction, VerifyProvenCtResponseValues,
    VerifyProvenCtValues,
};
use kms_common::load_and_unversionize;
use std::{env, path::Path};
use strum::IntoEnumIterator;

// Utility function to convert an array of arrays to a vector of vectors
fn array_array_to_vec_vec<T, A, const N: usize>(array: [A; N]) -> Vec<Vec<T>>
where
    A: IntoIterator<Item = T>,
    T: Clone,
{
    array.into_iter().map(|a| a.into_iter().collect()).collect()
}

fn test_decrypt_values(
    dir: &Path,
    test: &DecryptValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let fhe_types: Vec<FheType> = test
        .fhe_type_names
        .iter()
        .map(|type_name| FheType::from_str_name(type_name))
        .collect();

    let ciphertext_handles = array_array_to_vec_vec(test.ciphertext_handles);
    let external_handles = array_array_to_vec_vec(test.external_handles);

    let decrypt_values = DecryptValues::builder()
        .key_id(test.key_id.to_vec().into())
        .ciphertext_handles(ciphertext_handles.into())
        .fhe_types(fhe_types)
        .external_handles(Some(external_handles.into()))
        .version(test.version)
        .acl_address(test.acl_address.to_string())
        .proof(test.proof.to_string())
        .eip712_name(test.eip712_name.to_string())
        .eip712_version(test.eip712_version.to_string())
        .eip712_chain_id(test.eip712_chain_id.to_vec().into())
        .eip712_verifying_contract(test.eip712_verifying_contract.to_string())
        .eip712_salt(test.eip712_salt.map(|salt| salt.to_vec().into()))
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::Decrypt(decrypt_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid DecryptValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_decrypt_response_values(
    dir: &Path,
    test: &DecryptResponseValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let decrypt_response_values = DecryptResponseValues::builder()
        .signature(test.signature.to_vec().into())
        .payload(test.payload.to_vec().into())
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::DecryptResponse(decrypt_response_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid DecryptResponseValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_reencrypt_values(
    dir: &Path,
    test: &ReencryptValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let reencrypt_values = ReencryptValues::builder()
        .signature(test.signature.to_vec().into())
        .version(test.version)
        .client_address(test.client_address.to_string())
        .enc_key(test.enc_key.to_vec().into())
        .fhe_type(FheType::from_str_name(&test.fhe_type_name))
        .key_id(test.key_id.to_vec().into())
        .ciphertext_handle(test.ciphertext_handle.to_vec().into())
        .ciphertext_digest(test.ciphertext_digest.to_vec().into())
        .acl_address(test.acl_address.to_string())
        .proof(test.proof.to_string())
        .eip712_name(test.eip712_name.to_string())
        .eip712_version(test.eip712_version.to_string())
        .eip712_chain_id(test.eip712_chain_id.to_vec().into())
        .eip712_verifying_contract(test.eip712_verifying_contract.to_string())
        .eip712_salt(test.eip712_salt.map(|salt| salt.to_vec().into()))
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::Reencrypt(reencrypt_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid ReencryptValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_reencrypt_response_values(
    dir: &Path,
    test: &ReencryptResponseValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let reencrypt_response_values = ReencryptResponseValues::builder()
        .signature(test.signature.to_vec().into())
        .payload(test.payload.to_vec().into())
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::ReencryptResponse(reencrypt_response_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid ReencryptResponseValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_verify_proven_ct_values(
    dir: &Path,
    test: &ZkpValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let verify_proven_ct_values = VerifyProvenCtValues::builder()
        .crs_id(test.crs_id.to_vec().into())
        .key_id(test.key_id.to_vec().into())
        .contract_address(test.contract_address.to_string())
        .client_address(test.client_address.to_string())
        .ct_proof_handle(test.ct_proof_handle.to_vec().into())
        .acl_address(test.acl_address.to_string())
        .eip712_name(test.eip712_name.to_string())
        .eip712_version(test.eip712_version.to_string())
        .eip712_chain_id(test.eip712_chain_id.to_vec().into())
        .eip712_verifying_contract(test.eip712_verifying_contract.to_string())
        .eip712_salt(test.eip712_salt.map(|salt| salt.to_vec().into()))
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::VerifyProvenCt(verify_proven_ct_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid VerifyProvenCtValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_verify_proven_ct_response_values(
    dir: &Path,
    test: &ZkpResponseValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let verify_proven_ct_response_values = VerifyProvenCtResponseValues::builder()
        .signature(test.signature.to_vec().into())
        .payload(test.payload.to_vec().into())
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::VerifyProvenCtResponse(
            verify_proven_ct_response_values,
        )],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid VerifyProvenCtResponseValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_key_gen_values(
    dir: &Path,
    test: &KeyGenValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let key_gen_values = KeyGenValues::builder()
        .preproc_id(test.preproc_id.to_vec().into())
        .eip712_name(test.eip712_name.to_string())
        .eip712_version(test.eip712_version.to_string())
        .eip712_chain_id(test.eip712_chain_id.to_vec().into())
        .eip712_verifying_contract(test.eip712_verifying_contract.to_string())
        .eip712_salt(test.eip712_salt.map(|salt| salt.to_vec().into()))
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::KeyGen(key_gen_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid KeyGenValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_key_gen_response_values(
    dir: &Path,
    test: &KeyGenResponseValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let key_gen_response_values: KeyGenResponseValues = KeyGenResponseValues::builder()
        .request_id(test.request_id.to_vec().into())
        .public_key_digest(test.public_key_digest.to_string())
        .public_key_signature(test.public_key_signature.to_vec().into())
        .server_key_digest(test.server_key_digest.to_string())
        .server_key_signature(test.server_key_signature.to_vec().into())
        .param(test.param.try_into().unwrap())
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::KeyGenResponse(key_gen_response_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid KeyGenResponseValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_key_gen_preproc_values(
    dir: &Path,
    test: &KeyGenPreprocValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let key_gen_preproc_values = KeyGenPreprocValues::builder().build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::KeyGenPreproc(key_gen_preproc_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid KeyGenPreprocValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_key_gen_preproc_response_values(
    dir: &Path,
    test: &KeyGenPreprocResponseValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let key_gen_preproc_response_values = KeyGenPreprocResponseValues::builder().build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::KeyGenPreprocResponse(
            key_gen_preproc_response_values,
        )],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid KeyGenPreprocResponseValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_insecure_key_gen_values(
    dir: &Path,
    test: &InsecureKeyGenValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let insecure_key_gen_values = InsecureKeyGenValues::builder()
        .eip712_name(test.eip712_name.to_string())
        .eip712_version(test.eip712_version.to_string())
        .eip712_chain_id(test.eip712_chain_id.to_vec().into())
        .eip712_verifying_contract(test.eip712_verifying_contract.to_string())
        .eip712_salt(test.eip712_salt.map(|salt| salt.to_vec().into()))
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::InsecureKeyGen(insecure_key_gen_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid InsecureKeyGenValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_crs_gen_values(
    dir: &Path,
    test: &CrsGenValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let crs_gen_values = CrsGenValues::builder()
        .max_num_bits(256)
        .eip712_name(test.eip712_name.to_string())
        .eip712_version(test.eip712_version.to_string())
        .eip712_chain_id(test.eip712_chain_id.to_vec().into())
        .eip712_verifying_contract(test.eip712_verifying_contract.to_string())
        .eip712_salt(test.eip712_salt.map(|salt| salt.to_vec().into()))
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::CrsGen(crs_gen_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid CrsGenValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_crs_gen_response_values(
    dir: &Path,
    test: &CrsGenResponseValuesTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: Transaction = load_and_unversionize(dir, test, format)?;

    let crs_gen_response_values = CrsGenResponseValues::builder()
        .request_id(test.request_id.to_string())
        .digest(test.digest.to_string())
        .signature(test.signature.to_vec().into())
        .max_num_bits(256)
        .param(FheParameter::Test)
        .build();

    let new_versionized = Transaction::new(
        test.block_height,
        test.transaction_index,
        vec![OperationValue::CrsGenResponse(crs_gen_response_values)],
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid CrsGenResponseValues:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_kms_core_conf(
    dir: &Path,
    test: &KmsCoreConfTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: KmsCoreConf = load_and_unversionize(dir, test, format)?;

    let parties = vec![KmsCoreParty {
        party_id: test.parties_party_id.to_vec().into(),
        public_key: Some(test.parties_public_key.to_vec().into()),
        address: test.parties_address.to_string(),
        tls_pub_key: Some(test.parties_tls_pub_key.to_vec().into()),
    }];

    let param_choice = match test.param_choice.as_ref() {
        "test" => FheParameter::Test,
        "default" => FheParameter::Default,
        _ => panic!("Invalid FHE parameter"),
    };

    let new_versionized = KmsCoreConf {
        parties,
        response_count_for_majority_vote: test.response_count_for_majority_vote,
        response_count_for_reconstruction: test.response_count_for_reconstruction,
        degree_for_reconstruction: test.degree_for_reconstruction,
        param_choice,
    };

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid KmsCoreConf (threshold):\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

pub struct Events;

impl TestedModule for Events {
    type Metadata = TestMetadataEvents;
    const METADATA_FILE: &'static str = "events.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            Self::Metadata::DecryptValues(test) => {
                test_decrypt_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::DecryptResponseValues(test) => {
                test_decrypt_response_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::ReencryptValues(test) => {
                test_reencrypt_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::ReencryptResponseValues(test) => {
                test_reencrypt_response_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::ZkpValues(test) => {
                test_verify_proven_ct_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::ZkpResponseValues(test) => {
                test_verify_proven_ct_response_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KeyGenValues(test) => {
                test_key_gen_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KeyGenResponseValues(test) => {
                test_key_gen_response_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KeyGenPreprocValues(test) => {
                test_key_gen_preproc_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KeyGenPreprocResponseValues(test) => {
                test_key_gen_preproc_response_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::InsecureKeyGenValues(test) => {
                test_insecure_key_gen_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::CrsGenValues(test) => {
                test_crs_gen_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::CrsGenResponseValues(test) => {
                test_crs_gen_response_values(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KmsCoreConf(test) => {
                test_kms_core_conf(test_dir.as_ref(), test, format).into()
            }
        }
    }
}

// Get all operation value names that are not tested
// This is to make sure all new operation values are backward compatible
fn get_missing_tested_operation_value_names(results: &[TestResult]) -> Vec<&'static str> {
    let tested_values: Vec<&str> = results
        .iter()
        .filter_map(|result| match result {
            TestResult::Success(success) => Some(success.target_type()),
            _ => None,
        })
        .collect();

    OperationValue::iter()
        .map(|op| op.values_name())
        .filter(|&value| !tested_values.contains(&value))
        .collect()
}

// Backward compatibility tests are skipped until we have a proper stable version
#[test]
#[ignore]
fn test_backward_compatibility_events() {
    let pkg_version = env!("CARGO_PKG_VERSION");

    let base_data_dir = data_dir();

    let results = run_all_tests::<Events>(&base_data_dir, pkg_version);

    if results.iter().any(|r| r.is_failure()) {
        panic!("Backward compatibility tests for the Events module failed")
    }

    let missing_test_names = get_missing_tested_operation_value_names(&results);

    if !missing_test_names.is_empty() {
        println!("The following OperationValue values are not tested:");
        for test in missing_test_names {
            println!("- {}", test);
        }
        panic!("Not all OperationValue values are tested");
    }
}
