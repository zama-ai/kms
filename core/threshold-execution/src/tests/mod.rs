use crate::{
    constants::{REAL_KEY_PATH, SMALL_TEST_KEY_PATH},
    tests::helper::tests::generate_keys_deterministically,
    tfhe_internals::parameters::{DKGParams, BC_PARAMS_SNS, PARAMS_TEST_BK_SNS},
};
use std::{path::Path, sync::Once};
use test_utils::write_element;

pub mod helper;

/// Ensures the small test key material exists on disk.
/// Guaranteed to run at most once per process.
pub fn ensure_test_data_setup() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        generate_keys_if_missing(
            SMALL_TEST_KEY_PATH,
            PARAMS_TEST_BK_SNS,
            tfhe::Tag::default(),
        );
    });
}

/// Ensures the real (full-fat) key material exists on disk.
/// Also ensures the small keys and temp dirs are set up.
/// Guaranteed to run at most once per process.
pub fn ensure_real_keys_setup() {
    ensure_test_data_setup();
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        generate_keys_if_missing(REAL_KEY_PATH, BC_PARAMS_SNS, tfhe::Tag::default());
    });
}

/// Generate keys and write them to `path` if the file doesn't already exist.
fn generate_keys_if_missing(path: &str, params: DKGParams, tag: tfhe::Tag) {
    if !Path::new(path).exists() {
        let keys = generate_keys_deterministically(params, tag);
        write_element(path, &keys).expect("failed to write generated test keys");
    }
}
