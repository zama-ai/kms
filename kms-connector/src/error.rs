use crate::core::wallet::WalletError;
use alloy_transport::RpcError;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

/// Error type for the KMS connector
#[derive(Debug, Error)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid handle: {0}")]
    InvalidHandle(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid request ID: {0}")]
    InvalidRequestId(String),

    #[error("Invalid request type: {0}")]
    InvalidRequestType(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Contract error: {0}")]
    Contract(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Event subscription error: {0}")]
    EventSubscription(String),

    #[error("Channel error: {0}")]
    Channel(String),

    #[error("Wallet error: {0}")]
    Wallet(#[from] WalletError),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl<T> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Self {
        Error::Channel(e.to_string())
    }
}

impl<T> From<RpcError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: RpcError<T>) -> Self {
        Error::Rpc(err.to_string())
    }
}

/// Result type for the KMS connector
pub type Result<T> = std::result::Result<T, Error>;
