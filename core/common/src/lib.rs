#[cfg(feature = "testing")]
use {
    kms_core_backward_compatibility::load::{DataFormat, TestFailure},
    kms_core_backward_compatibility::TestType,
    std::path::Path,
    tfhe_versionable::Unversionize,
};

#[macro_export]
macro_rules! impl_generic_versionize {
    ($t:ty) => {
        impl tfhe_versionable::Versionize for $t {
            type Versioned<'vers> = &'vers $t;

            fn versionize(&self) -> Self::Versioned<'_> {
                self
            }
        }

        impl tfhe_versionable::VersionizeOwned for $t {
            type VersionedOwned = $t;
            fn versionize_owned(self) -> Self::VersionedOwned {
                self
            }
        }

        impl tfhe_versionable::Unversionize for $t {
            fn unversionize(
                versioned: Self::VersionedOwned,
            ) -> Result<Self, tfhe_versionable::UnversionizeError> {
                Ok(versioned)
            }
        }

        impl tfhe_versionable::NotVersioned for $t {}
    };
}

#[cfg(feature = "testing")]
pub fn load_and_unversionize<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = format.load_versioned_test(dir, test)?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}
