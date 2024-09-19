//! Utility functions to run the actual backward compatibility tests for any given module.

use std::fmt::Display;
use std::path::Path;

use serde::de::DeserializeOwned;

use crate::load::{load_tests_metadata, DataFormat, TestResult};
use crate::{dir_for_version, Testcase};

pub trait TestedModule {
    // The metadata type to consider for this module
    type Metadata: Clone + Display + DeserializeOwned;

    /// The name of the `.ron` file where the metadata for this module are stored
    const METADATA_FILE: &'static str;

    /// Run a testcase for this module
    fn run_test<P: AsRef<Path>>(
        base_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult;
}

/// Run a specific testcase. The testcase should be valid for the current version.
fn run_test<M: TestedModule>(
    base_dir: &Path,
    testcase: &Testcase<M::Metadata>,
    format: DataFormat,
) -> TestResult {
    let version = &testcase.kms_core_version_min;
    let module = &testcase.kms_core_module;

    let mut test_dir = dir_for_version(base_dir, version);
    test_dir.push(module);

    let test_result = M::run_test(test_dir, testcase, format);

    match &test_result {
        TestResult::Success(r) => println!("{}", r),
        TestResult::Failure(r) => println!("{}", r),
        TestResult::Skipped(r) => println!("{}", r),
    }

    test_result
}

pub fn run_all_tests<M: TestedModule>(base_dir: &Path, pkg_version: &str) -> Vec<TestResult> {
    let meta_file_path = base_dir.join(M::METADATA_FILE);

    if !meta_file_path.exists() {
        panic!(
            "Missing backward compatibility metadata: `{:?}`.",
            meta_file_path
        )
    }

    let meta = load_tests_metadata(meta_file_path).unwrap();

    let mut results = Vec::new();

    for testcase in meta {
        if testcase.is_valid_for_version(pkg_version) {
            let test_result = run_test::<M>(base_dir, &testcase, DataFormat::Bincode);
            results.push(test_result)
        }
    }

    results
}
