use super::operator::default_proof_runtime;
use cosmwasm_std::{StdError, StdResult};
use events::HexVector;
use tendermint::crypto::default::signature::Verifier;
use tendermint::crypto::signature::Verifier as _;
use tendermint::{PublicKey, Signature};

use crate::contract::ProofTendermint;

pub(crate) struct TendermintProofStrategy {}

impl TendermintProofStrategy {
    pub fn verify(
        proof: ProofTendermint,
        root_hash: Option<HexVector>,
        value: &[u8],
    ) -> StdResult<()> {
        let root_hash_value = if let Some(root_hash) = root_hash {
            if root_hash.is_empty() {
                return Err(StdError::generic_err("Root hash is empty"));
            }
            root_hash
        } else {
            return Err(StdError::generic_err("Root hash is missing"));
        };
        let runtime = default_proof_runtime();
        runtime
            .verify_value(proof.proof(), &root_hash_value, proof.keypath(), value)
            .map_err(|e| StdError::generic_err(format!("Verification proof failed: {}", e)))
    }

    pub fn verify_signatures(
        signatures: Vec<HexVector>,
        pubkeys: Vec<HexVector>,
        msg: &[u8],
    ) -> StdResult<()> {
        if signatures.len() != pubkeys.len() {
            return Err(StdError::generic_err("Invalid number of signatures"));
        }
        for (signature_raw, pubkey) in signatures.iter().zip(pubkeys.iter()) {
            let signature = Signature::new(signature_raw.to_vec().as_slice()).map_err(|e| {
                StdError::generic_err(format!(
                    "Error converting signature to Tendermint Signature {}",
                    e
                ))
            })?;
            let signature = signature
                .ok_or_else(|| StdError::generic_err("Invalid signature. Signature is empty."))?;
            let mut publickey = PublicKey::from_raw_ed25519(pubkey.to_vec().clone().as_slice());
            if publickey.is_none() {
                publickey = PublicKey::from_raw_secp256k1(pubkey.to_vec().as_slice());
            }
            let publickey = publickey
                .ok_or_else(|| StdError::generic_err("Invalid public key. Public key is empty."))?;
            Verifier::verify(publickey, msg, &signature).map_err(|e| {
                StdError::generic_err(format!("Signature verification failed: {}", e))
            })?;
        }
        Ok(())
    }
}
