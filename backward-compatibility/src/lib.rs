//! All tests struct are defined here, for all modules and versions of kms-core.

#[cfg(feature = "load")]
use semver::{Prerelease, Version, VersionReq};
use serde::{Deserialize, Serialize};
#[cfg(feature = "load")]
use std::fmt::Display;
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};
use strum::Display;

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
pub const EVENTS_MODULE_NAME: &str = "events";

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
    pub external_signature: [u8; 3],
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
    pub decompression_key_filename: Cow<'static, str>,
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
    pub decompression_key_filename: Cow<'static, str>,
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptValuesTest {
    pub test_filename: Cow<'static, str>,
    pub key_id: [u8; 3],
    pub ciphertext_handles: [[u8; 3]; 2],
    pub fhe_type_names: [Cow<'static, str>; 2],
    pub external_handles: [[u8; 3]; 2],
    pub version: u32,
    pub acl_address: Cow<'static, str>,
    pub proof: Cow<'static, str>,
    pub eip712_name: Cow<'static, str>,
    pub eip712_version: Cow<'static, str>,
    pub eip712_chain_id: [u8; 3],
    pub eip712_verifying_contract: Cow<'static, str>,
    pub eip712_salt: Option<[u8; 3]>,
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for DecryptValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "DecryptValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub signature: [u8; 3],
    pub payload: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for DecryptResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "DecryptResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReencryptValuesTest {
    pub test_filename: Cow<'static, str>,
    pub signature: [u8; 3],
    pub version: u32,
    pub client_address: Cow<'static, str>,
    pub enc_key: [u8; 3],
    pub fhe_type_name: Cow<'static, str>,
    pub key_id: [u8; 3],
    pub ciphertext_handle: [u8; 3],
    pub ciphertext_digest: [u8; 3],
    pub acl_address: Cow<'static, str>,
    pub proof: Cow<'static, str>,
    pub eip712_name: Cow<'static, str>,
    pub eip712_version: Cow<'static, str>,
    pub eip712_chain_id: [u8; 3],
    pub eip712_verifying_contract: Cow<'static, str>,
    pub eip712_salt: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for ReencryptValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ReencryptValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReencryptResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub signature: [u8; 3],
    pub payload: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for ReencryptResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "ReencryptResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkpValuesTest {
    pub test_filename: Cow<'static, str>,
    pub crs_id: [u8; 3],
    pub key_id: [u8; 3],
    pub contract_address: Cow<'static, str>,
    pub client_address: Cow<'static, str>,
    pub ct_proof_handle: [u8; 3],
    pub acl_address: Cow<'static, str>,
    pub eip712_name: Cow<'static, str>,
    pub eip712_version: Cow<'static, str>,
    pub eip712_chain_id: [u8; 3],
    pub eip712_verifying_contract: Cow<'static, str>,
    pub eip712_salt: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for ZkpValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "VerifyProvenCtValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkpResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub signature: [u8; 3],
    pub payload: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for ZkpResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "VerifyProvenCtResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyUrlValuesTest {
    pub test_filename: Cow<'static, str>,
    pub data_id: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for KeyUrlValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KeyUrlValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyUrlResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub fhe_key_info_fhe_public_key_data_id: [u8; 3],
    pub fhe_key_info_fhe_public_key_param_choice: i32,
    pub fhe_key_info_fhe_public_key_urls: [Cow<'static, str>; 1],
    pub fhe_key_info_fhe_public_key_signatures: [[u8; 3]; 1],
    pub fhe_key_info_fhe_server_key_data_id: [u8; 3],
    pub fhe_key_info_fhe_server_key_param_choice: i32,
    pub fhe_key_info_fhe_server_key_urls: [Cow<'static, str>; 1],
    pub fhe_key_info_fhe_server_key_signatures: [[u8; 3]; 1],
    pub crs_ids: [u32; 1],
    pub crs_data_ids: [[u8; 3]; 1],
    pub crs_param_choices: [i32; 1],
    pub crs_urls: [[Cow<'static, str>; 1]; 1],
    pub crs_signatures: [[[u8; 3]; 1]; 1],
    pub verf_public_key_key_id: [u8; 3],
    pub verf_public_key_server_id: u32,
    pub verf_public_key_url: Cow<'static, str>,
    pub verf_public_key_address: Cow<'static, str>,
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for KeyUrlResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KeyUrlResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenValuesTest {
    pub test_filename: Cow<'static, str>,
    pub preproc_id: [u8; 3],
    pub eip712_name: Cow<'static, str>,
    pub eip712_version: Cow<'static, str>,
    pub eip712_chain_id: [u8; 3],
    pub eip712_verifying_contract: Cow<'static, str>,
    pub eip712_salt: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for KeyGenValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KeyGenValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub request_id: [u8; 3],
    pub public_key_digest: Cow<'static, str>,
    pub public_key_signature: [u8; 3],
    pub server_key_digest: Cow<'static, str>,
    pub server_key_signature: [u8; 3],
    pub param: i32,
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for KeyGenResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KeyGenResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenPreprocValuesTest {
    pub test_filename: Cow<'static, str>,
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for KeyGenPreprocValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KeyGenPreprocValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenPreprocResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for KeyGenPreprocResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KeyGenPreprocResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InsecureKeyGenValuesTest {
    pub test_filename: Cow<'static, str>,
    pub eip712_name: Cow<'static, str>,
    pub eip712_version: Cow<'static, str>,
    pub eip712_chain_id: [u8; 3],
    pub eip712_verifying_contract: Cow<'static, str>,
    pub eip712_salt: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for InsecureKeyGenValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "InsecureKeyGenValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrsGenValuesTest {
    pub test_filename: Cow<'static, str>,
    pub max_num_bits: u32,
    pub eip712_name: Cow<'static, str>,
    pub eip712_version: Cow<'static, str>,
    pub eip712_chain_id: [u8; 3],
    pub eip712_verifying_contract: Cow<'static, str>,
    pub eip712_salt: [u8; 3],
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for CrsGenValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CrsGenValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrsGenResponseValuesTest {
    pub test_filename: Cow<'static, str>,
    pub request_id: Cow<'static, str>,
    pub digest: Cow<'static, str>,
    pub signature: [u8; 3],
    pub max_num_bits: u32,
    pub param: i32,
    pub block_height: u64,
    pub transaction_index: u32,
}

impl TestType for CrsGenResponseValuesTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "CrsGenResponseValues".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KmsCoreConfCentralizedTest {
    pub test_filename: Cow<'static, str>,
    pub fhe_parameter: Cow<'static, str>,
}

impl TestType for KmsCoreConfCentralizedTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KmsCoreConfCentralized".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KmsCoreConfThresholdTest {
    pub test_filename: Cow<'static, str>,
    pub parties_party_id: [u8; 3],
    pub parties_public_key: [u8; 3],
    pub parties_address: Cow<'static, str>,
    pub parties_tls_pub_key: [u8; 3],
    pub response_count_for_majority_vote: usize,
    pub response_count_for_reconstruction: usize,
    pub degree_for_reconstruction: usize,
    pub param_choice: Cow<'static, str>,
}

impl TestType for KmsCoreConfThresholdTest {
    fn module(&self) -> String {
        EVENTS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "KmsCoreConfThreshold".to_string()
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
    PRSSSetup(PRSSSetupTest),
}

// Events blockchain metadata
// All these tests first build a operation value, and then uses it to build a transaction object
// before versionizing and serializing it
#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataEvents {
    DecryptValues(DecryptValuesTest),
    DecryptResponseValues(DecryptResponseValuesTest),
    ReencryptValues(ReencryptValuesTest),
    ReencryptResponseValues(ReencryptResponseValuesTest),
    ZkpValues(ZkpValuesTest),
    ZkpResponseValues(ZkpResponseValuesTest),
    KeyUrlValues(KeyUrlValuesTest),
    KeyUrlResponseValues(KeyUrlResponseValuesTest),
    KeyGenValues(KeyGenValuesTest),
    KeyGenResponseValues(KeyGenResponseValuesTest),
    KeyGenPreprocValues(KeyGenPreprocValuesTest),
    KeyGenPreprocResponseValues(KeyGenPreprocResponseValuesTest),
    InsecureKeyGenValues(InsecureKeyGenValuesTest),
    CrsGenValues(CrsGenValuesTest),
    CrsGenResponseValues(CrsGenResponseValuesTest),
    KmsCoreConfCentralized(KmsCoreConfCentralizedTest),
    KmsCoreConfThreshold(KmsCoreConfThresholdTest),
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
