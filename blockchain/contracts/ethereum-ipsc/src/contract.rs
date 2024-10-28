use ethereum_inclusion_proofs::cosmwasm_proof_handler::EthereumProofHandler;
use ethereum_inclusion_proofs::types::EvmPermissionProof;

use aipsc::contract::InclusionProofContract;
use cosmwasm_std::{Response, StdError, StdResult};
use cw2::{ensure_from_older_version, set_contract_version};
use sylvia::{
    contract, entry_points,
    types::{ExecCtx, InstantiateCtx, MigrateCtx},
};

use prost::Message;

// Info for migration
const CONTRACT_NAME: &str = "kms-ethereum-ipsc";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    pub fn instantiate(&self, ctx: InstantiateCtx) -> StdResult<Response> {
        // Set contract name and version in the storage
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        Ok(Response::default())
    }

    // Migrate function to migrate from old version to new version
    // As there is only one version of the ethereum-ipsc for now, this function has no real use. Future
    // versions of the ethereum-ipsc will be required to provide this function, with additional migration
    // logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> StdResult<Response> {
        // Check that the given storage (representing the old contract's storage) is compatible with
        // the new version of the ethereum-ipsc by :
        // - checking that the new contract name is the same
        // - checking that the new contract version is more recent than the current version
        // If both conditions are met, the storage is updated with the new contract version
        let _original_version =
            ensure_from_older_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

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
