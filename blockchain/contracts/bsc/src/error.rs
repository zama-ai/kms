use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum BackendError {
    #[error("[BackendContractError] {0}")]
    StdError(#[from] StdError),
}

impl From<String> for BackendError {
    fn from(error: String) -> Self {
        BackendError::StdError(StdError::generic_err(error))
    }
}
