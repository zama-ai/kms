use cosmwasm_std::{Response, StdError};
use sylvia::interface;
use sylvia::types::{CustomMsg, ExecCtx};

pub struct DebugProof;

#[interface]
pub trait InclusionProofContract {
    type Error: From<StdError>;

    type UpdateHeader: CustomMsg;

    #[sv::msg(exec)]
    fn update_header(
        &self,
        ctx: ExecCtx,
        update_header: Self::UpdateHeader,
    ) -> Result<Response, Self::Error>;

    #[sv::msg(exec)]
    fn verify_proof(
        &self,
        ctx: ExecCtx,
        proof: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Response, Self::Error>;
}
