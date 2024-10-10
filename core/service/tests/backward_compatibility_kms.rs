//! Tests breaking change in serialized data by trying to load historical data stored in `backward-compatibility/data`.
//! For each kms-core module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tells
//! what to test for each message.

use aes_prng::AesRng;

use backward_compatibility::{
    data_dir,
    load::{DataFormat, TestFailure, TestResult, TestSuccess},
    tests::{run_all_tests, TestedModule},
    KmsFheKeyHandlesTest, PrivateSigKeyTest, PublicSigKeyTest, SignedPubDataHandleInternalTest,
    TestMetadataKMS, TestType, Testcase, ThresholdFheKeysTest,
};
use distributed_decryption::execution::{
    endpoints::keygen::{FhePubKeySet, PrivateKeySet},
    tfhe_internals::switch_and_squash::SwitchAndSquashKey,
};
use kms_common::{load_and_unversionize, load_and_unversionize_auxiliary};
use kms_lib::{
    cryptography::{
        central_kms::{gen_sig_keys, KmsFheKeyHandles},
        internal_crypto_types::{PrivateSigKey, PublicSigKey},
    },
    rpc::rpc_types::{PubDataType, SignedPubDataHandleInternal},
    threshold::threshold_kms::ThresholdFheKeys,
    util::key_setup::FhePublicKey,
};
use rand::SeedableRng;
use std::{collections::HashMap, env, path::Path};
use tfhe::integer::compression_keys::DecompressionKey;

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
                "Invalid private sig key:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
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
                "Invalid public sig key:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

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
                "Invalid signed pub data handle (internal):\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
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
    let (original_integer_key, _, _, _) = original_versionized.client_key.clone().into_raw_parts();
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
        sns_key: None,
    };

    let decompression_key: Option<DecompressionKey> =
        load_and_unversionize_auxiliary(dir, test, &test.decompression_key_filename, format)?;

    // TODO: include eip712_domain parameter when generating the versioned data
    let new_versionized = KmsFheKeyHandles::new(
        &private_sig_key,
        client_key,
        &fhe_pub_key_set,
        decompression_key,
        None,
    )
    .unwrap();

    // Retrieve the key parameters from the new KMS handle
    let (new_integer_key, _, _, _) = new_versionized.client_key.clone().into_raw_parts();
    let new_key_params = new_integer_key.parameters();

    // Compare the key parameters and the public key info. We cannot directly compare KmsFheKeyHandles
    // by adding the `PartialEq` trait because TFHE-rs' ClientKey are not able to be directly
    // compared. Instead, we compare the parameters, as done in TFHE-rs' tests
    if new_key_params != original_key_params {
        Err(test.failure(
            format!(
                "Invalid KMS FHE key handles because of different parameters:\n Expected :\n{:?}\nGot:\n{:?}",
                original_key_params, new_key_params
            ),
            format,
        ))
    } else if original_versionized.public_key_info != new_versionized.public_key_info {
        Err(test.failure(
            format!(
                "Invalid KMS FHE key handles because of different public key info:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized.public_key_info, new_versionized.public_key_info
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
    let private_key_set: PrivateKeySet =
        load_and_unversionize_auxiliary(dir, test, &test.private_key_set_filename, format)?;

    let sns_key: SwitchAndSquashKey =
        load_and_unversionize_auxiliary(dir, test, &test.sns_key_filename, format)?;

    let info: HashMap<PubDataType, SignedPubDataHandleInternal> =
        load_and_unversionize_auxiliary(dir, test, &test.info_filename, format)?;

    let decompression_key: Option<DecompressionKey> =
        load_and_unversionize_auxiliary(dir, test, &test.decompression_key_filename, format)?;

    let original_versionized: ThresholdFheKeys = load_and_unversionize(dir, test, format)?;
    let new_versionized = ThresholdFheKeys {
        private_keys: private_key_set,
        sns_key,
        decompression_key,
        pk_meta_data: info,
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
                "Invalid KMS FHE key handles because of different parameters:\n Expected :\n{:?}\nGot:\n{:?}",
                original_key_params, new_key_params
            ),
            format,
        ))
    } else if original_versionized.pk_meta_data != new_versionized.pk_meta_data {
        Err(test.failure(
            format!(
                "Invalid KMS FHE key handles because of different public key info:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized.pk_meta_data, new_versionized.pk_meta_data
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
            Self::Metadata::SignedPubDataHandleInternal(test) => {
                test_signed_pub_data_handle_internal(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::KmsFheKeyHandles(test) => {
                test_kms_fhe_key_handles(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::ThresholdFheKeys(test) => {
                test_threshold_fhe_keys(test_dir.as_ref(), test, format).into()
            }
        }
    }
}

// Backward compatibility tests are skipped until we have a proper stable version
#[test]
#[ignore]
fn test_backward_compatibility_kms() {
    let pkg_version = env!("CARGO_PKG_VERSION");

    let base_data_dir = data_dir();

    let results = run_all_tests::<KMS>(&base_data_dir, pkg_version);

    if results.iter().any(|r| r.is_failure()) {
        panic!("Backward compatibility tests for the KMS module failed")
    }
}
