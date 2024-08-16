use aipsc::contract::InclusionProofContract;
use cosmwasm_std::{from_json, Response, StdError, StdResult};
use sylvia::contract;
use sylvia::types::ExecCtx;

use crate::contract::{ProofTendermint, TendermintUpdateHeader};

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
    fn verify_proof(&self, _ctx: ExecCtx, proof: Vec<u8>, _value: Vec<u8>) -> StdResult<Response> {
        let _pr: ProofTendermint =
            from_json(&proof).map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
        Ok(Response::default())
    }

    type Error = StdError;
    type UpdateHeader = TendermintUpdateHeader;

    fn update_header(
        &self,
        _ctx: ExecCtx,
        _update_header: Self::UpdateHeader,
    ) -> StdResult<Response> {
        Ok(Response::default())
    }
}
