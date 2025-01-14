use aws_lc_rs::error::Unspecified;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error(transparent)]
    UnspecifiedError(#[from] Unspecified),
    #[error("padding error")]
    PaddingError,
    #[error("sharing error {0}")]
    SharingError(String),
    #[error("reconstruct error {0}")]
    ReconstructError(String),
    #[error("bincode error {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("add share error {0}")]
    AddShareError(String),
    #[error("setup error {0}")]
    SetupError(String),
    #[error("share validation error")]
    ShareValidationError,
    #[error("key validation error")]
    KeyValidationError,
    #[error("no blocks error")]
    NoBlocksError,
}
