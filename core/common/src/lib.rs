// TODO @reviewer is this the right place for this?
use serde::Serialize;

/// This trait means that the type can be converted into a versioned equivalent
/// type.
pub trait Versionize {
    /// The equivalent versioned type. It should have a variant for each version.
    /// It may own the underlying data or only hold a read-only reference to it.
    /// The current implementation should always versionize to the most recent version.
    /// Also observe that the versioned type is the one that should be serialized.
    type Versioned<'vers>: Serialize
    where
        Self: 'vers;

    /// Wraps the object into a versioned enum with a variant for each version. This will
    /// use references on the underlying types if possible.
    fn versionize(&self) -> Self::Versioned<'_>;
}

/// This trait means that we can convert from a versioned enum into the target type.
pub trait Unversionize: Versionize + Sized {
    /// Creates an object from a versioned enum, and eventually upgrades from previous
    /// variants.
    /// This will be done with a `match` pattern matching all possible versions,
    /// with each branch carrying out the necessary conversions.
    fn unversionize(versioned: Self::Versioned<'_>) -> anyhow::Result<Self>;
}

/// This trait means that the type can be converted into a versioned equivalent used for serialization.
pub trait Versioned: Serialize {}

// Count tfhe-rs types, which implemnt their own versioning, as versioned
// TODO Change this to the versioned versions once tfhe-rs gets upgraded
impl Versioned for tfhe::CompactPublicKey {}
impl Versioned for tfhe::ServerKey {}
impl Versioned for tfhe::ClientKey {}
