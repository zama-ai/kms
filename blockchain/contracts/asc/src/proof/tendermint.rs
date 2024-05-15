use crate::proof::InstantiateMsg;
use crate::proof::Proof;
use crate::proof::ProofStrategy;
use cosmwasm_std::StdResult;
use ibc_client_cw::api::ClientType;
use ibc_clients::tendermint::types::{ClientState, ConsensusState};
use tendermint::block::Height;

use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response};

#[derive(Clone, Debug)]
pub struct TendermintClient;

impl<'a> ClientType<'a> for TendermintClient {
    type ClientState = ClientState;
    type ConsensusState = ConsensusState;
}

pub type TendermintContext<'a> = Context<'a, TendermintClient>;

pub(crate) struct TendermintProofStrategy {
    pub(crate) chain_id: String,
    pub(crate) height: u64,
    pub(crate) header: Vec<u8>,
}

impl ProofStrategy for TendermintProofStrategy {
    fn instantiate(
        deps: DepsMut<'_>,
        env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> StdResult<Response> {
        let mut ctx = TendermintContext::new_mut(deps, env)?;
        let data = ctx.instantiate(msg)?;
        Ok(Response::default().set_data(data))
    }

    fn verify(&self, proof: Proof) -> Result<bool, ContractError> {
        // verify the proof against the tendermint chain
        let ctx = TendermintContext::new_ref(deps, env)?;
        ctx.query(msg);

        self.validate_proof(&proof).unwrap_or(false)
    }
}

pub struct TendermintStorageProof {
    pub proof: Vec<u8>,
    pub app_hash: Vec<u8>,
    pub contract_address: Vec<u8>,
    pub storage_key: Vec<u8>,
    pub expected_storage_value: Vec<u8>,
}

pub struct TendermintProof {
    pub height: u32,
    pub storage_proof: Option<TendermintStorageProof>,
}

impl TendermintProofStrategy {
    /// Validates a cryptographic proof against known application hash and expected storage values.
    ///
    /// This method ensures the integrity and authenticity of data within blockchain applications
    /// by validating cryptographic proofs against application-specific hashes and expected data values.
    ///
    /// Proofs are verified against a trusted `appHash`. An `appHash` in an Ethermint
    /// blockchain is a commitment to the whole blockchain state at a particular block
    /// height (i.e. block number). An Ethermint `appHash` after
    /// executing block N is added in the header of block N + 1.
    ///
    /// # Arguments
    ///
    /// * `proof` - The cryptographic proof to validate.
    ///
    /// # Returns
    ///
    /// * A result indicating the success of the validation.
    fn validate_proof(&self, proof: &Proof) -> anyhow::Result<bool, Status> {
        let proof: TendermintProof = bincode::deserialize(&proof)
            .map_err(|e| Status::internal(format!("Failed to deserialize proof: {}", e)))?;

        let app_hash = self
            .tendermint_client
            .get_app_hash(Height::from(proof.height + 1))
            .await
            .map_err(|e| Status::internal(format!("Failed to get app hash: {}", e)))?;

        let storage_proof = proof
            .storage_proof
            .as_ref()
            .ok_or_else(|| Status::new(Code::InvalidArgument, "Storage proof is missing"))?;

        if app_hash.as_bytes() != storage_proof.app_hash {
            return Err(Status::new(
                Code::InvalidArgument,
                "App hash does not match",
            ));
        }

        TendermintClient::verify_storage_proof(
            &storage_proof.proof,
            &storage_proof.contract_address,
            app_hash.as_bytes(),
            &storage_proof.storage_key,
            &storage_proof.expected_storage_value,
        )
        .map_err(|e| Status::internal(format!("Failed to verify storage proof: {}", e)))?;

        Ok(true)
    }
}
