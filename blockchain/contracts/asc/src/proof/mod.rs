use cosmwasm_schema::cw_serde;
use std::str::FromStr;

pub type Proof = Vec<u8>;

pub(crate) trait ProofStrategy {
    fn verify_request_proof(&self, proof: Proof) -> bool;
    fn verify_response_proof(&self, proof: Proof) -> bool;
}

pub enum ProofType {
    Debug,
    Tendermint,
}

#[cw_serde]
pub enum ContractProofType {
    Debug,
    Tendermint,
}

impl FromStr for ContractProofType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Debug" => Ok(ContractProofType::Debug),
            "Tendermint" => Ok(ContractProofType::Tendermint),
            _ => Err(()),
        }
    }
}

pub(crate) struct DebugProofStrategy {}

impl ProofStrategy for DebugProofStrategy {
    fn verify_request_proof(&self, _proof: Proof) -> bool {
        true
    }

    fn verify_response_proof(&self, _proof: Proof) -> bool {
        true
    }
}
