use ethereum_inclusion_proofs::cosmwasm_proof_handler::EthereumProofHandler;
use ethereum_inclusion_proofs::types::EvmPermissionProof;

use aipsc::contract::InclusionProofContract;
use contracts_common::migrations::Migration;
use cosmwasm_std::{Response, StdError, StdResult};
use cw2::set_contract_version;
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

/// Implement the `Migration` trait
///
/// This allows to migrate the contract's state from an old version to a new version, without
/// changing its address. This will automatically use versioning to ensure compatibility between
/// versions
impl Migration for ProofContract {}

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

    /// Function to migrate from old version to new version
    ///
    /// As there is only one version of the contract for now, this function has no real use. Future
    /// versions of the contract will be required to provide this function, with additional migration
    /// logic if needed. This might include changing the function's signature.
    #[sv::msg(migrate)]
    fn migrate(&self, ctx: MigrateCtx) -> StdResult<Response> {
        self.apply_migration(ctx.deps.storage)
    }
}

impl InclusionProofContract for ProofContract {
    type Error = StdError;

    fn verify_proof(
        &self,
        _ctx: ExecCtx,
        proof: String,
        ciphertext_handles: String,
    ) -> StdResult<Response> {
        let proof = hex::decode(proof).unwrap();
        let proof = EvmPermissionProof::decode(&*proof).unwrap();
        let ciphertext_handles: Vec<Vec<u8>> = serde_json::from_str(&ciphertext_handles).unwrap();

        let result = EthereumProofHandler::verify_proof(proof, ciphertext_handles)
            .map_err(|e| StdError::generic_err(format!("Proof verification failed: {}", e)))?;

        Ok(Response::new()
            .add_attribute("method", "verify ethereum proof")
            .add_attribute("result", result.to_string()))
    }
}
