use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to parse account ID: {0}")]
    AccountIdParseError(String),

    #[error("Failed to construct execute message: {0}")]
    MsgExecuteError(String),

    #[error("Failed to sign the document: {0}")]
    SignDocError(String),

    #[error("Blockchain transaction error: {0}")]
    BlockchainTransactionError(String),

    #[error("Check transaction failed: {0}")]
    CheckTxError(String),

    #[error("Transaction result error: {0}")]
    TxResultError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}
