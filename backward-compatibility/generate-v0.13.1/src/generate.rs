//! Utility functions, traits and macros to generate and store versioned data for any kms-core version.

use std::{
    borrow::Cow,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use tfhe_versionable_0_7::Versionize as Versionize_0_7;

use backward_compatibility::{
    data_dir, dir_for_version,
    parameters::{
        ClassicPBSParametersTest, DKGParamsRegularTest, DKGParamsSnSTest,
        SwitchAndSquashCompressionParametersTest, SwitchAndSquashParametersTest,
    },
    TestMetadataDD, TestMetadataKMS, TestMetadataKmsGrpc,
};

// Parameters set for tests in kms-core 0.9, found in `PARAMS_TEST_BK_SNS`. However, for stability
// reasons, these should never change.
// For `DKGParamsRegularTest`, parameters `dedicated_compact_public_key_parameters` and
// `compression_decompression_parameters` are not included because they are optional tfhe-rs types,
// which means their backward compatibility is already tested.
pub const TEST_DKG_PARAMS_SNS: DKGParamsSnSTest = DKGParamsSnSTest {
    regular_params: DKGParamsRegularTest {
        sec: 128,
        ciphertext_parameters: ClassicPBSParametersTest {
            lwe_dimension: 10,
            glwe_dimension: 1,
            polynomial_size: 256,
            lwe_noise_gaussian: 0,
            glwe_noise_gaussian: 0,
            pbs_base_log: 16,
            pbs_level: 1,
            ks_base_log: 14,
            ks_level: 1,
            message_modulus: 4,
            carry_modulus: 4,
            max_noise_level: 5,
            log2_p_fail: -49.5137, // dummy parameter
            encryption_key_choice: Cow::Borrowed("big"),
        },
        flag: true,
    },
    sns_params: SwitchAndSquashParametersTest {
        glwe_dimension: 1,
        glwe_noise_distribution: 0,
        polynomial_size: 256,
        pbs_base_log: 32,
        pbs_level: 2,
        message_modulus: 4,
        carry_modulus: 4,
    },
    sns_compression_parameters: SwitchAndSquashCompressionParametersTest {
        packing_ks_level: 1,
        packing_ks_base_log: 16,
        packing_ks_polynomial_size: 256,
        packing_ks_glwe_dimension: 1,
        lwe_per_glwe: 10,
        packing_ks_key_noise_distribution: 0,
        message_modulus: 4,
        carry_modulus: 4,
    },
};

pub fn save_bcode<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    // Use bincode 2.x API with legacy config to match bc2wrap behavior
    let config = bincode::config::legacy().with_fixed_int_encoding();
    let encoded = bincode::serde::encode_to_vec(msg, config).unwrap();
    fs::write(path, encoded).unwrap();
}

/// Stores the test data in `dir`, encoded in bincode, using the right tfhe-versionable version
macro_rules! define_store_versioned_test_fn {
    ($fn_name:ident, $versionize_trait:ident) => {
        pub fn $fn_name<Data: $versionize_trait, P: AsRef<Path>>(
            msg: &Data,
            dir: P,
            test_filename: &str,
        ) {
            let versioned = msg.versionize();

            // Store in bincode
            let filename_bincode = format!("{}.bcode", test_filename);
            save_bcode(&versioned, dir.as_ref().join(filename_bincode));
        }
    };
}
define_store_versioned_test_fn!(store_versioned_test_05, Versionize_0_7);

/// Stores the auxiliary data in `dir`, encoded in bincode, using the right tfhe-versionable version
macro_rules! define_store_versioned_auxiliary_fn {
    ($fn_name:ident, $versionize_trait:ident) => {
        pub fn $fn_name<Data: $versionize_trait, P: AsRef<Path>>(
            msg: &Data,
            dir: P,
            test_name: &str,
            filename: &str,
        ) {
            let versioned = msg.versionize();

            // Store in bincode
            let filename_bincode = format!("{}.bcode", filename);
            let sub_dir_name = format!("auxiliary_{}", test_name);
            let sub_dir = dir.as_ref().join(&sub_dir_name);
            fs::create_dir_all(&sub_dir).unwrap();
            save_bcode(
                &versioned,
                dir.as_ref().join(sub_dir_name).join(filename_bincode),
            );
        }
    };
}
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_05, Versionize_0_7);

pub fn store_metadata<Meta, P>(new_data: &Vec<Meta>, path: P)
where
    Meta: Serialize + serde::de::DeserializeOwned + Clone,
    P: AsRef<Path>,
{
    let path = path.as_ref();

    // If file doesn't exist, just write the new data
    if !path.exists() {
        let serialized =
            ron::ser::to_string_pretty(new_data, ron::ser::PrettyConfig::default()).unwrap();
        fs::write(path, serialized).unwrap();
        return;
    }

    // Load existing metadata
    let existing_content = fs::read_to_string(path).unwrap();
    let mut combined_data: Vec<Meta> =
        ron::from_str(&existing_content).expect("Failed to deserialize existing metadata");

    // Append new entries
    combined_data.extend_from_slice(new_data);

    // Write combined data
    let serialized =
        ron::ser::to_string_pretty(&combined_data, ron::ser::PrettyConfig::default()).unwrap();
    fs::write(path, serialized).unwrap();
}

pub trait KMSCoreVersion {
    const VERSION_NUMBER: &'static str;

    fn data_dir() -> PathBuf {
        let base_data_dir = data_dir();
        dir_for_version(base_data_dir, Self::VERSION_NUMBER)
    }

    /// How to fix the prng seed for this version to make sure the generated (public) keys do not change every time we run the script
    fn seed_prng(seed: u128);

    /// Generates data for the KMS module for this version.
    /// This should create KMS-core types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_kms_data() -> Vec<TestMetadataKMS>;

    /// Generates data for the KMG grpc module for this version.
    /// This should create types from kms-grpc,
    /// versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_kms_grpc_data() -> Vec<TestMetadataKmsGrpc>;

    /// Generates data for the distributed decryption module for this version.
    /// This should create types from distributed decryption,
    /// versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_threshold_fhe_data() -> Vec<TestMetadataDD>;
}
