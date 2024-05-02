use deep_space::error::PrivateKeyError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cannot create gRPC Client with: {0}")]
    GrpcClientCreateError(String),

    #[error("Failed to broadcast transaction: {0}")]
    BroadcastTxError(#[from] tonic::Status),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid decode from bytes to proto message: {0}")]
    DecodeError(#[from] prost::DecodeError),

    #[error("Invalid encode to bytes from proto message: {0}")]
    EncodeError(#[from] prost::EncodeError),

    #[error("PublicKey Error: {0}")]
    InvalidPublicKey(String),

    #[error("AccountId Error: {0}")]
    InvalidAccount(String),

    #[error("AccountId Error: Invalid bech32 converting from str {0}")]
    InvalidBech32Account(#[from] subtle_encoding::Error),

    #[error("Error deriving private key from mnemonic: {0}")]
    DerivePrivateKeyError(#[from] PrivateKeyError),

    #[error("Signature Error: {0}")]
    SignatureError(#[from] k256::ecdsa::Error),
}
