use cosmwasm_std::{Response, StdError};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sylvia::interface;
use sylvia::types::ExecCtx;

pub struct DebugProof;

#[interface]
#[sv::custom(msg=cosmwasm_std::Empty, query=cosmwasm_std::Empty)]
pub trait InclusionProofContract {
    type Error: From<StdError>;

    type UpdateHeader: Serialize + DeserializeOwned + JsonSchema + Clone + std::fmt::Debug;

    type ProofData: Serialize + DeserializeOwned + JsonSchema + Clone + std::fmt::Debug;

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
        proof: Self::ProofData,
        value: Vec<u8>,
    ) -> Result<Response, Self::Error>;
}
