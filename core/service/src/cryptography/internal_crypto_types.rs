use crate::consts::{DEFAULT_PARAM, TEST_PARAM};
use crate::cryptography::error::CryptographyError;
use kms_grpc::kms::v1::FheParameter;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;

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

/// Trait to help handling difficult cases of legacy serialization and deserialization
/// where versioning was not originally in play on the underlying type.
pub trait LegacySerialization {
    /// Serializes data of old types using bincode, and data of new types using safe serialization
    /// Be careful if you start using old types with safe serialization as this will break compatibility
    fn to_legacy_bytes(&self) -> Result<Vec<u8>, CryptographyError>;
    /// Deserializes data of old types using bincode, and data of new types using safe deserialization
    fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, CryptographyError>
    where
        Self: Sized;
}

/// This is a wrapper around [DKGParams] so that we can
/// implement [From<FheParameter>]. It has a [std::ops::Deref] implementation
/// which can be used for for converting from [FheParameter] to [DKGParams]
pub(crate) struct WrappedDKGParams(DKGParams);
impl From<FheParameter> for WrappedDKGParams {
    fn from(value: FheParameter) -> WrappedDKGParams {
        match value {
            FheParameter::Test => WrappedDKGParams(TEST_PARAM),
            FheParameter::Default => WrappedDKGParams(DEFAULT_PARAM),
        }
    }
}

impl std::ops::Deref for WrappedDKGParams {
    type Target = DKGParams;
    fn deref(&self) -> &DKGParams {
        &self.0
    }
}
