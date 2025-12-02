mod common;
use common::load_and_unversionize;

use backward_compatibility::{
    data_dir,
    load::{DataFormat, TestFailure, TestResult, TestSuccess},
    tests::{run_all_tests, TestedModule},
    PrivDataTypeTest, PubDataTypeTest, PublicKeyTypeTest, SignedPubDataHandleInternalTest,
    TestMetadataKmsGrpc, TestType, Testcase,
};
use kms_grpc::rpc_types::{PrivDataType, PubDataType, PublicKeyType, SignedPubDataHandleInternal};
use std::path::Path;

fn test_signed_pub_data_handle_internal(
    dir: &Path,
    test: &SignedPubDataHandleInternalTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: SignedPubDataHandleInternal =
        load_and_unversionize(dir, test, format)?;

    let new_versionized = SignedPubDataHandleInternal::new(
        test.key_handle.to_string(),
        test.signature.to_vec(),
        test.external_signature.to_vec(),
    );

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid signed pub data handle (internal):\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_public_key_type(
    dir: &Path,
    test: &PublicKeyTypeTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PublicKeyType = load_and_unversionize(dir, test, format)?;

    let new_versionized = PublicKeyType::Compact;

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid signed pub data handle (internal):\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_pub_data_type(
    dir: &Path,
    test: &PubDataTypeTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PubDataType = load_and_unversionize(dir, test, format)?;

    let new_versionized = PubDataType::DecompressionKey;

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid signed pub data handle (internal):\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_priv_data_type(
    dir: &Path,
    test: &PrivDataTypeTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PrivDataType = load_and_unversionize(dir, test, format)?;

    // Last element in the enum
    let new_versionized = PrivDataType::ContextInfo;

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid signed priv data handle (internal):\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

pub struct KmsGrpc;

impl TestedModule for KmsGrpc {
    type Metadata = TestMetadataKmsGrpc;
    const METADATA_FILE: &'static str = "kms-grpc.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            Self::Metadata::SignedPubDataHandleInternal(test) => {
                test_signed_pub_data_handle_internal(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::PublicKeyType(test) => {
                test_public_key_type(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::PubDataType(test) => {
                test_pub_data_type(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::PrivDataType(test) => {
                test_priv_data_type(test_dir.as_ref(), test, format).into()
            }
        }
    }
}

#[test]
fn test_backward_compatibility_kms_grpc() {
    let pkg_version = env!("CARGO_PKG_VERSION");

    let base_data_dir = data_dir();

    let results = run_all_tests::<KmsGrpc>(&base_data_dir, pkg_version);

    for r in results.iter() {
        if r.is_failure() {
            panic!("Backward compatibility tests for the KmsGrpc module failed: {r:?}")
        }
    }
}
