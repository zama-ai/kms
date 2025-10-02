use rsa::pkcs1;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptographyError {
    #[error("length error: {0}")]
    LengthError(String),
    #[error(transparent)]
    AesGcmError(#[from] aes_gcm::Error),
    #[error("ml-kem error")]
    MlKemError,
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("deserialization error: {0}")]
    DeserializationError(String),
    #[error(transparent)]
    RsaError(#[from] rsa::Error),
    #[error(transparent)]
    Pkcs1Error(#[from] pkcs1::Error),
    #[error("bincode encode error: {0}")]
    BincodeEncodeError(#[from] bincode::error::EncodeError),
    #[error("bincode error: {0}")]
    BincodeError(String),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Verification error: {0}")]
    VerificationError(String),
}
