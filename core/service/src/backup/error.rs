use rsa::pkcs1;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error(transparent)]
    RsaError(#[from] rsa::Error),
    #[error(transparent)]
    AesGcmError(#[from] aes_gcm::Error),
    #[error("ml-kem error")]
    MlKemError,
    #[error(transparent)]
    InternalSignatureError(#[from] k256::ecdsa::signature::Error),
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Pkcs1Error(#[from] pkcs1::Error),
    #[error("padding error")]
    PaddingError,
    #[error("sharing error: {0}")]
    SharingError(String),
    #[error("reconstruct error: {0}")]
    ReconstructError(String),
    #[error("bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("add share error: {0}")]
    AddShareError(String),
    #[error("setup error: {0}")]
    SetupError(String),
    #[error("no blocks error")]
    NoBlocksError,
    #[error("length error: {0}")]
    LengthError(String),
    #[error("signature verification error: {0}")]
    SignatureVerificationError(String),
    #[error("custodian setup error")]
    CustodianSetupError,
    #[error("custodian recovery error")]
    CustodianRecoveryError,
    #[error("signing error")]
    SigningError,
    #[error("safe deserialization error: {0}")]
    SafeDeserializationError(String),
    #[error("operator error: {0}")]
    OperatorError(String),
}
