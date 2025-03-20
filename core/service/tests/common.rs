use {
    backward_compatibility::load::{load_versioned_auxiliary, DataFormat, TestFailure},
    backward_compatibility::TestType,
    std::path::Path,
    tfhe_versionable::Unversionize,
};

// Not sure why this is considered as deadcode when it's used in the backward compatibility tests.
#[allow(dead_code)]
pub(crate) fn load_and_unversionize<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = format.load_versioned_test(dir, test)?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}

// Not sure why this is considered as deadcode when it's used in the backward compatibility tests.
#[allow(dead_code)]
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
