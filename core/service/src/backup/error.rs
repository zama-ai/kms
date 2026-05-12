use thiserror::Error;

use crate::cryptography::error::CryptographyError;

/// Why a single custodian setup message was skipped during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupSkipReason {
    InvalidTimestamp,
    InvalidHeader,
    InvalidRole,
    DuplicateRole,
}

/// Why a single custodian recovery output was skipped during filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySkipReason {
    InvalidRole,
    MissingVerificationKey,
    MissingSigncryption,
    InvalidSigncryption,
    ParseError,
    DuplicateRole,
}

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
    #[error("bincode encode error: {0}")]
    BincodeEncodeError(#[from] bincode::error::EncodeError),
    #[error("bincode error: {0}")]
    BincodeError(String),
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
    #[error(
        "not enough valid custodian setup messages: expected at least {expected_min}, got {received}, skipped: {skipped:?}"
    )]
    SetupValidationFailed {
        expected_min: usize,
        received: usize,
        skipped: Vec<SetupSkipReason>,
    },
    #[error(
        "not enough valid recovery outputs: expected at least {required_min}, got {received} (threshold parameter: {threshold}), skipped: {skipped:?}"
    )]
    RecoveryThresholdNotMet {
        required_min: usize,
        received: usize,
        threshold: usize,
        skipped: Vec<RecoverySkipReason>,
    },
}
