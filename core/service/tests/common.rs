#![allow(
    dead_code,
    reason = "shared by several backward-compatibility test binaries, not all of which use every helper"
)]

use {
    backward_compatibility::TestType,
    backward_compatibility::load::{DataFormat, TestFailure, load_versioned_auxiliary},
    std::path::Path,
    tfhe_versionable::Unversionize,
};

pub(crate) fn load_and_unversionize<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = format.load_versioned_test(dir, test)?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}

pub(crate) fn load_and_unversionize_auxiliary<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    auxiliary_filename: &str,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = load_versioned_auxiliary(dir, &test.test_filename(), auxiliary_filename)
        .map_err(|e| test.failure(e, format))?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}
