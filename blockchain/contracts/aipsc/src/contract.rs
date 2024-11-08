use cosmwasm_std::{Response, StdError};
use sylvia::interface;
use sylvia::types::ExecCtx;

pub struct DebugProof;

#[interface]
pub trait InclusionProofContract {
    type Error: From<StdError>;

    #[sv::msg(exec)]
    fn verify_proof(
        &self,
        ctx: ExecCtx,
        proof: String,
        ciphertext_handles: String,
    ) -> Result<Response, Self::Error>;
}
