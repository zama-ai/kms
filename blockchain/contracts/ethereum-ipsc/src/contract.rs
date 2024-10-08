use ethereum_inclusion_proofs::cosmwasm_proof_handler::EthereumProofHandler;
use ethereum_inclusion_proofs::types::EvmPermissionProof;

// use crate::ethereum_proof_handler::{EthereumProofHandler, EvmPermissionProof};
use aipsc::contract::InclusionProofContract;
use cosmwasm_std::{Response, StdError, StdResult};
use sylvia::{contract, entry_points, types::ExecCtx, types::InstantiateCtx};

use prost::Message;

#[derive(Default)]
pub struct ProofContract {}

#[entry_points]
#[contract]
#[sv::messages(aipsc::contract as InclusionProofContract)]
impl ProofContract {
    pub fn new() -> Self {
        Self {}
    }
    #[sv::msg(instantiate)]
    pub fn instantiate(&self, _ctx: InstantiateCtx) -> StdResult<Response> {
        Ok(Response::default())
    }
}

impl InclusionProofContract for ProofContract {
    type Error = StdError;

    fn verify_proof(&self, _ctx: ExecCtx, proof: String) -> StdResult<Response> {
        let proof = hex::decode(proof).unwrap();
        let proof = EvmPermissionProof::decode(&*proof).unwrap();

        let result = EthereumProofHandler::verify_proof(proof).unwrap();
        Ok(Response::new()
            .add_attribute("method", "verify ethereum proof")
            .add_attribute("result", result.to_string()))
    }
}
