//! Utility functions, traits and macros to generate and store versioned data for any kms-core version.

use std::{
    borrow::Cow,
    fs::{self, File},
    path::{Path, PathBuf},
};

use bincode::Options;
use serde::Serialize;
use tfhe_versionable_0_2::Versionize as Versionize02;

use crate::{
    data_dir, dir_for_version,
    parameters::{
        ClassicPBSParametersTest, DKGParamsRegularTest, DKGParamsSnSTest,
        SwitchAndSquashParametersTest,
    },
    TestMetadataDD, TestMetadataKMS,
};

// Parameters set for tests in kms-core 0.9, found in `PARAMS_TEST_BK_SNS`. However, for stability
// reasons, these should never change.
pub const TEST_DKG_PARAMS_SNS: DKGParamsSnSTest = DKGParamsSnSTest {
    regular_params: DKGParamsRegularTest {
        sec: 128,
        ciphertext_parameters: ClassicPBSParametersTest {
            lwe_dimension: 32,
            glwe_dimension: 1,
            polynomial_size: 64,
            lwe_noise_gaussian: 0,
            glwe_noise_gaussian: 0,
            pbs_base_log: 21,
            pbs_level: 1,
            ks_base_log: 8,
            ks_level: 4,
            message_modulus: 4,
            carry_modulus: 2,
            max_noise_level: 5,
            log2_p_fail: -80., // dummy parameter
            encryption_key_choice: Cow::Borrowed("big"),
        },
        flag: true,
    },
    sns_params: SwitchAndSquashParametersTest {
        glwe_dimension: 2,
        glwe_noise_distribution: 0,
        polynomial_size: 256,
        pbs_base_log: 33,
        pbs_level: 2,
    },
};

pub fn save_bcode<Data: Serialize, P: AsRef<Path>>(msg: &Data, path: P) {
    let mut file = File::create(path).unwrap();
    let options = bincode::DefaultOptions::new().with_fixint_encoding();
    options.serialize_into(&mut file, msg).unwrap();
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
define_store_versioned_test_fn!(store_versioned_test_02, Versionize02);

/// Stores the auxiliary data in `dir`, encoded in bincode, using the right tfhe-versionable version
macro_rules! define_store_versioned_auxiliary_fn {
    ($fn_name:ident, $versionize_trait:ident) => {
        pub fn $fn_name<Data: $versionize_trait, P: AsRef<Path>>(
            msg: &Data,
            dir: P,
            test_filename: &str,
        ) {
            let versioned = msg.versionize();

            // Store in bincode
            let filename_bincode = format!("auxiliary_{}.bcode", test_filename);
            save_bcode(&versioned, dir.as_ref().join(filename_bincode));
        }
    };
}
define_store_versioned_auxiliary_fn!(store_versioned_auxiliary_02, Versionize02);

pub fn store_metadata<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::ser::to_string_pretty(value, ron::ser::PrettyConfig::default()).unwrap();
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

    /// Generates data for the distributed decryption module for this version.
    /// This should create KMS-core types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_distributed_decryption_data() -> Vec<TestMetadataDD>;
}
