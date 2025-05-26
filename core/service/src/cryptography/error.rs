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
    #[error("safe deserialization error: {0}")]
    SafeDeserializationError(String),
    #[error(transparent)]
    RsaError(#[from] rsa::Error),
    #[error(transparent)]
    Pkcs1Error(#[from] pkcs1::Error),
    #[error("bincode encode error: {0}")]
    BincodeEncodeError(#[from] bincode::error::EncodeError),
    #[error("bincode error: {0}")]
    BincodeError(String),
}
