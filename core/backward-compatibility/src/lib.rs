//! All tests struct are defined here, for all modules and versions of kms-core.

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

#[cfg(feature = "load")]
use semver::{Prerelease, Version, VersionReq};
#[cfg(feature = "load")]
use std::fmt::Display;
use strum::Display;

use serde::{Deserialize, Serialize};

pub mod parameters;

#[cfg(feature = "generate")]
pub mod data_0_9;
#[cfg(feature = "generate")]
pub mod generate;
#[cfg(feature = "load")]
pub mod load;
#[cfg(feature = "tests")]
pub mod tests;

pub const PRNG_SEED: u128 = 0xdeadbeef;

const DATA_DIR: &str = "data";

pub const KMS_MODULE_NAME: &str = "kms";
pub const DISTRIBUTED_DECRYPTION_MODULE_NAME: &str = "distributed_decryption";

pub fn dir_for_version<P: AsRef<Path>>(data_dir: P, version: &str) -> PathBuf {
    let mut path = data_dir.as_ref().to_path_buf();
    path.push(version.replace('.', "_"));

    path
}

pub fn data_dir() -> PathBuf {
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let mut path = PathBuf::from(root_dir);
    path.push(DATA_DIR);

    path
}

pub trait TestType {
    /// The KMS-core module where this type reside
    fn module(&self) -> String;

    /// The type that is tested
    fn target_type(&self) -> String;

    /// The name of the file to be tested, without path or extension
    /// (they will be inferred)
    fn test_filename(&self) -> String;

    #[cfg(feature = "load")]
    fn success(&self, format: load::DataFormat) -> load::TestSuccess {
        load::TestSuccess {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            format,
        }
    }

    #[cfg(feature = "load")]
    fn failure<E: Display>(&self, error: E, format: load::DataFormat) -> load::TestFailure {
        load::TestFailure {
            module: self.module(),
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            source_error: format!("{}", error),
            format,
        }
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivateSigKeyTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for PrivateSigKeyTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PrivateSigKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicSigKeyTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for PublicSigKeyTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PublicSigKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedPubDataHandleInternalTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
    pub key_handle: Cow<'static, str>,
    pub signature: [u8; 3],
}

impl TestType for SignedPubDataHandleInternalTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SignedPubDataHandleInternal".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KmsFheKeyHandlesTest {
    pub test_filename: Cow<'static, str>,
    pub client_key_filename: Cow<'static, str>,
    pub public_key_filename: Cow<'static, str>,
    pub server_key_filename: Cow<'static, str>,
    pub sig_key_filename: Cow<'static, str>,
    pub state: u64,
    pub seed: u128,
    pub element: Cow<'static, str>,
    pub dkg_parameters_sns: parameters::DKGParamsSnSTest,
}

impl TestType for KmsFheKeyHandlesTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KmsFheKeyHandles".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// Distributed Decryption test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicParameterTest {
    pub test_filename: Cow<'static, str>,
    pub witness_dim: usize,
    pub max_num_bits: Option<u32>,
}

impl TestType for PublicParameterTest {
    fn module(&self) -> String {
        DISTRIBUTED_DECRYPTION_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PublicParameter".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// Distributed Decryption test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PRSSSetupTest {
    pub test_filename: Cow<'static, str>,
    pub amount: usize,
    pub threshold: u8,
    pub role_i: usize,
    pub residue_poly_size: u16,
}

impl TestType for PRSSSetupTest {
    fn module(&self) -> String {
        DISTRIBUTED_DECRYPTION_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PRSSSetup".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}
// Distributed Decryption test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThresholdFheKeysTest {
    pub test_filename: Cow<'static, str>,
    pub private_key_set_filename: Cow<'static, str>,
    pub sns_key_filename: Cow<'static, str>,
    pub info_filename: Cow<'static, str>,
    pub state: u64,
    pub amount: usize,
    pub threshold: u8,
    pub role_i: usize,
    pub element: Cow<'static, str>,
    pub dkg_parameters_sns: parameters::DKGParamsSnSTest,
}

impl TestType for ThresholdFheKeysTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ThresholdFheKeys".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS metadata
#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataKMS {
    PrivateSigKey(PrivateSigKeyTest),
    PublicSigKey(PublicSigKeyTest),
    SignedPubDataHandleInternal(SignedPubDataHandleInternalTest),
    KmsFheKeyHandles(KmsFheKeyHandlesTest),
    ThresholdFheKeys(ThresholdFheKeysTest),
}

// Distributed Decryption metadata
#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataDD {
    PublicParameter(PublicParameterTest),
    PRSSSetup(PRSSSetupTest),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Testcase<T> {
    pub kms_core_version_min: String,
    pub kms_core_module: String,
    pub metadata: T,
}

#[cfg(feature = "load")]
impl<T: Display> Testcase<T> {
    pub fn is_valid_for_version(&self, version: &str) -> bool {
        let mut kms_core_version = Version::parse(version).unwrap();

        // Removes the pre-release tag because matches will always return
        kms_core_version.pre = Prerelease::EMPTY;

        let req = format!(">={}", self.kms_core_version_min);
        let min_version = VersionReq::parse(&req).unwrap();

        min_version.matches(&kms_core_version)
    }

    pub fn skip(&self) -> load::TestSkipped {
        load::TestSkipped {
            module: self.kms_core_module.to_string(),
            test_name: self.metadata.to_string(),
        }
    }
}
