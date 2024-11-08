use aipsc::contract::InclusionProofContract;
use cosmwasm_std::{Response, StdError, StdResult};
use sylvia::contract;
use sylvia::types::ExecCtx;

pub struct NoopInclusionProofContract;

#[contract]
#[sv::messages(aipsc::contract as InclusionProofContract)]
impl NoopInclusionProofContract {
    pub fn new() -> Self {
        Self {}
    }
    #[sv::msg(instantiate)]
    pub fn instantiate(&self, _ctx: ExecCtx) -> StdResult<Response> {
        Ok(Response::default())
    }
}

impl Default for NoopInclusionProofContract {
    fn default() -> Self {
        Self::new()
    }
}

impl InclusionProofContract for NoopInclusionProofContract {
    fn verify_proof(&self, _ctx: ExecCtx, _proof: String, _handles: String) -> StdResult<Response> {
        Ok(Response::default())
    }

    type Error = StdError;
}
