pub mod retry;

use clap::ValueEnum;
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
#[cfg(feature = "testing")]
use {
    backward_compatibility::load::{load_versioned_auxiliary, DataFormat, TestFailure},
    backward_compatibility::TestType,
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

#[derive(Copy, Clone, Default, Serialize, Deserialize, Display, Debug, ValueEnum)]
pub enum DecryptionMode {
    /// nSmall Noise Flooding, this is the default
    #[default]
    NoiseFloodSmall,
    /// nLarge Noise Flooding
    NoiseFloodLarge,
    /// nSmall Bit Decomposition
    BitDecSmall,
    /// nLarge Bit Decomposition
    BitDecLarge,
}

impl DecryptionMode {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            DecryptionMode::NoiseFloodSmall => "NoiseFloodSmall",
            DecryptionMode::NoiseFloodLarge => "NoiseFloodLarge",
            DecryptionMode::BitDecSmall => "BitDecSmall",
            DecryptionMode::BitDecLarge => "BitDecLarge",
        }
    }
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

#[cfg(feature = "testing")]
pub fn load_and_unversionize_auxiliary<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    auxiliary_filename: &str,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = load_versioned_auxiliary(dir, &test.test_filename(), auxiliary_filename)
        .map_err(|e| test.failure(e, format))?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}
