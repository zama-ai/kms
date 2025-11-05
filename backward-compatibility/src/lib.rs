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

#[cfg(feature = "load")]
pub mod load;
#[cfg(feature = "tests")]
pub mod tests;

pub const PRNG_SEED: u128 = 0xdeadbeef;

const DATA_DIR: &str = "data";

pub const KMS_MODULE_NAME: &str = "kms";
pub const DISTRIBUTED_DECRYPTION_MODULE_NAME: &str = "threshold-fhe";
pub const KMS_GRPC_MODULE_NAME: &str = "kms-grpc";

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

/// Test metadata for TypedPlaintext backward compatibility.
///
/// TypedPlaintext is serialized with bc2wrap and embedded in user decryption responses.
/// This test ensures that data serialized with older versions (v0.11.x) can still be
/// deserialized by the current version, preventing breaking changes to the binary format.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TypedPlaintextTest {
    pub test_filename: Cow<'static, str>,
    pub plaintext_bytes: Vec<u8>,
    pub fhe_type: i32,
}

impl TestType for TypedPlaintextTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "TypedPlaintext".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS-grpc test
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
        KMS_GRPC_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SignedPubDataHandleInternal".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyTypeTest {
    pub test_filename: Cow<'static, str>,
}

impl TestType for PublicKeyTypeTest {
    fn module(&self) -> String {
        KMS_GRPC_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PublicKeyType".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubDataTypeTest {
    pub test_filename: Cow<'static, str>,
}

impl TestType for PubDataTypeTest {
    fn module(&self) -> String {
        KMS_GRPC_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PubDataType".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivDataTypeTest {
    pub test_filename: Cow<'static, str>,
}

impl TestType for PrivDataTypeTest {
    fn module(&self) -> String {
        KMS_GRPC_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PrivDataType".to_string()
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppKeyBlobTest {
    pub test_filename: Cow<'static, str>,
    pub root_key_id: Cow<'static, str>,
    pub data_key_blob: Cow<'static, str>,
    pub ciphertext: Cow<'static, str>,
    pub iv: Cow<'static, str>,
    pub auth_tag: Cow<'static, str>,
}

impl TestType for AppKeyBlobTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "AppKeyBlob".to_string()
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrfKeyTest {
    pub test_filename: Cow<'static, str>,
    pub seed: u128,
}

impl TestType for PrfKeyTest {
    fn module(&self) -> String {
        DISTRIBUTED_DECRYPTION_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PrfKey".to_string()
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
    pub integer_server_key_filename: Cow<'static, str>,
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
pub struct OperatorBackupOutputTest {
    pub test_filename: Cow<'static, str>,
    pub custodian_count: usize,
    pub custodian_threshold: usize,
    pub plaintext: [u8; 32],
    pub backup_id: [u8; 32],
    pub seed: u64,
}

impl TestType for OperatorBackupOutputTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "OperatorBackupOutput".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
/// Test metadata for SigncryptionPayload backward compatibility.
///
/// SigncryptionPayload is serialized with bc2wrap and embedded in user decryption responses.
/// This test ensures that data serialized with older versions (v0.11.x) can still be
/// deserialized by the current version, preventing breaking changes to the binary format.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SigncryptionPayloadTest {
    pub test_filename: Cow<'static, str>,
    pub plaintext_bytes: Vec<u8>,
    pub fhe_type: i32,
    pub link: Vec<u8>,
}

impl TestType for SigncryptionPayloadTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "SigncryptionPayload".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnifiedSigncryptionKeyTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for UnifiedSigncryptionKeyTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "UnifiedSigncryptionKeyOwned".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnifiedUnsigncryptionKeyTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for UnifiedUnsigncryptionKeyTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "UnifiedUnsigncryptionKeyOwned".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub unified_cipher_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for BackupCiphertextTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "BackupCiphertext".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnifiedCipherTest {
    pub test_filename: Cow<'static, str>,
    pub hybrid_kem_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for UnifiedCipherTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "UnifiedCipher".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HybridKemCtTest {
    pub test_filename: Cow<'static, str>,
    pub nonce: [u8; 12],
    pub kem_ct: Vec<u8>,
    pub payload_ct: Vec<u8>,
}

impl TestType for HybridKemCtTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "HybridKemCt".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoveryValidationMaterialTest {
    pub test_filename: Cow<'static, str>,
    pub internal_cus_context_filename: Cow<'static, str>,
    pub state: u64,
    pub custodian_count: usize,
}

impl TestType for RecoveryValidationMaterialTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "RecoveryValidationMaterial".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InternalCustodianContextTest {
    pub test_filename: Cow<'static, str>,
    pub internal_cus_setup_filename: Cow<'static, str>,
    pub unified_enc_key_filename: Cow<'static, str>,
    pub state: u64,
    pub custodian_count: usize,
}

impl TestType for InternalCustodianContextTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "InternalCustodianContext".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InternalCustodianRecoveryOutputTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for InternalCustodianRecoveryOutputTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "InternalCustodianRecoveryOutput".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

// KMS test
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InternalCustodianSetupMessageTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for InternalCustodianSetupMessageTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "InternalCustodianSetupMessage".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

/// KMS metadata
#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataKMS {
    PrivateSigKey(PrivateSigKeyTest),
    PublicSigKey(PublicSigKeyTest),
    TypedPlaintext(TypedPlaintextTest),
    KmsFheKeyHandles(KmsFheKeyHandlesTest),
    ThresholdFheKeys(ThresholdFheKeysTest),
    AppKeyBlob(AppKeyBlobTest),
    SigncryptionPayload(SigncryptionPayloadTest),
    UnifiedSigncryptionKeyOwned(UnifiedSigncryptionKeyTest),
    UnifiedUnsigncryptionKeyOwned(UnifiedUnsigncryptionKeyTest),
    BackupCiphertext(BackupCiphertextTest),
    UnifiedCipher(UnifiedCipherTest),
    HybridKemCt(HybridKemCtTest),
    RecoveryValidationMaterial(RecoveryValidationMaterialTest),
    InternalCustodianContext(InternalCustodianContextTest),
    InternalCustodianSetupMessage(InternalCustodianSetupMessageTest),
    InternalCustodianRecoveryOutput(InternalCustodianRecoveryOutputTest),
    OperatorBackupOutput(OperatorBackupOutputTest),
}

/// KMS-grpc metadata
#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataKmsGrpc {
    SignedPubDataHandleInternal(SignedPubDataHandleInternalTest),
    PublicKeyType(PublicKeyTypeTest),
    PubDataType(PubDataTypeTest),
    PrivDataType(PrivDataTypeTest),
}

/// Distributed Decryption metadata
#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataDD {
    PRSSSetup(PRSSSetupTest),
    PrfKey(PrfKeyTest),
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
