//! Functions and enums to load versioned test and associated data.
//! These are used when actually testing the backward compatibility of a module.

use std::{
    fmt::Display,
    fs::{self, File},
    path::Path,
};

use bincode::{DefaultOptions, Options};
use serde::de::DeserializeOwned;

use crate::{TestType, Testcase};

/// Loads auxiliary data that might be needed for a test (eg: a key to test a ciphertext)
pub fn load_versioned_auxiliary<Data: DeserializeOwned, P: AsRef<Path>>(
    dir: P,
    test_name: &str,
    filename: &str,
) -> Result<Data, String> {
    let filename = format!("{}.bcode", filename);
    let path = dir
        .as_ref()
        .join(format!("auxiliary_{}", test_name))
        .join(filename);

    let file = File::open(&path)
        .map_err(|e| format!("Failed to read auxiliary file {}: {}", path.display(), e))?;
    let options = DefaultOptions::new().with_fixint_encoding();
    options
        .deserialize_from(file)
        .map_err(|e| format!("Failed to parse auxiliary file {}: {}", path.display(), e))
}

#[derive(Copy, Clone, Debug)]
pub enum DataFormat {
    Bincode,
}

impl Display for DataFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DataFormat {
    pub fn extension(&self) -> &'static str {
        "bcode"
    }

    /// Loads the file that should be tested
    pub fn load_versioned_test<Data: DeserializeOwned, P: AsRef<Path>, T: TestType>(
        self,
        dir: P,
        test: &T,
    ) -> Result<Data, TestFailure> {
        let filename = format!("{}.{}", test.test_filename(), self.extension());
        let file = File::open(dir.as_ref().join(filename))
            .map_err(|e| test.failure(format!("Failed to read testcase: {}", e), self))?;

        let options = DefaultOptions::new().with_fixint_encoding();
        options
            .deserialize_from(file)
            .map_err(|e| test.failure(e, self))
    }
}

pub enum TestResult {
    Success(TestSuccess),
    Failure(TestFailure),
    Skipped(TestSkipped),
}

impl From<Result<TestSuccess, TestFailure>> for TestResult {
    fn from(value: Result<TestSuccess, TestFailure>) -> Self {
        match value {
            Ok(success) => Self::Success(success),
            Err(failure) => Self::Failure(failure),
        }
    }
}

impl TestResult {
    pub fn is_failure(&self) -> bool {
        match self {
            TestResult::Failure(_) => true,
            TestResult::Success(_) | TestResult::Skipped(_) => false,
        }
    }
}

pub struct TestFailure {
    pub(crate) module: String,
    pub(crate) target_type: String,
    pub(crate) test_filename: String,
    pub(crate) source_error: String,
    pub(crate) format: DataFormat,
}

impl Display for TestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Test: {}::{} in file {}.{}: FAILED: {}",
            self.module,
            self.target_type,
            self.test_filename,
            self.format.extension(),
            self.source_error
        )
    }
}

pub struct TestSuccess {
    pub(crate) module: String,
    pub(crate) target_type: String,
    pub(crate) test_filename: String,
    pub(crate) format: DataFormat,
}

// This is needed in some tests to verify some information after all tests have been ran
impl TestSuccess {
    pub fn target_type(&self) -> &str {
        self.target_type.as_str()
    }
}

impl Display for TestSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Test: {}::{} using file {}.{}: SUCCESS",
            self.module,
            self.target_type,
            self.test_filename,
            self.format.extension(),
        )
    }
}

pub struct TestSkipped {
    pub(crate) module: String,
    pub(crate) test_name: String,
}

impl Display for TestSkipped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test: {}::{}: SKIPPED", self.module, self.test_name)
    }
}

pub fn load_tests_metadata<P: AsRef<Path>, T: DeserializeOwned>(
    path: P,
) -> Result<Vec<Testcase<T>>, String> {
    let serialized =
        fs::read_to_string(path).map_err(|e| format!("Failed to load test metadata: {}", e))?;
    ron::from_str(&serialized).map_err(|e| format!("Invalid test metadata: {}", e))
}
