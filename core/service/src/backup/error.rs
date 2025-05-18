use thiserror::Error;

use crate::cryptography::error::CryptographyError;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error(transparent)]
    InternalCryptographyError(#[from] CryptographyError),
    #[error(transparent)]
    InternalSignatureError(#[from] k256::ecdsa::signature::Error),
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
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
    #[error("signature verification error: {0}")]
    SignatureVerificationError(String),
    #[error("custodian setup error")]
    CustodianSetupError,
    #[error("custodian recovery error")]
    CustodianRecoveryError,
    #[error("signing error: {0}")]
    SigningError(String),
    #[error("safe deserialization error: {0}")]
    SafeDeserializationError(String),
    #[error("operator error: {0}")]
    OperatorError(String),
}
