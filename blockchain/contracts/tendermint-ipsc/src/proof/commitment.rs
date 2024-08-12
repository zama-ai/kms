//! # Commitment Proof Operations
//!
//! This module provides functionalities for decoding and operating on commitment proofs,
//! specifically focusing on ICS23 proofs.

use super::operator::ProofOperator;
use ics23::{
    calculate_existence_root, iavl_spec, smt_spec, tendermint_spec, verify_membership,
    verify_non_membership, CommitmentProof, HostFunctionsManager, ProofSpec,
};
use prost::Message;
use std::error::Error;
use tendermint::merkle::proof::ProofOp;

/// Constant for IAVL commitment proof operations.
pub const PROOF_OP_IAVL_COMMITMENT: &str = "ics23:iavl";
/// Constant for Simple Merkle commitment proof operations.
pub const PROOF_OP_SIMPLE_MERKLE_COMMITMENT: &str = "ics23:simple";
/// Constant for Sparse Merkle Tree commitment proof operations.
pub const PROOF_OP_SMT_COMMITMENT: &str = "ics23:smt";

/// Represents a commitment operation with its type, spec, key, and proof.
pub struct CommitmentOp {
    #[allow(dead_code)]
    op_type: String,
    spec: ProofSpec,
    key: Vec<u8>,
    proof: CommitmentProof,
}

/// Decodes a `ProofOp` into a `CommitmentOp` capable of proof operations.
///
/// # Arguments
///
/// * `pop` - A `ProofOp` instance to be decoded.
///
/// # Returns
///
/// Returns a `Result` which is either a Boxed `CommitmentOp` on success, or a Boxed error on failure.
pub fn commitment_op_decoder(
    pop: ProofOp,
) -> Result<Box<dyn ProofOperator>, Box<dyn std::error::Error>> {
    let spec = match pop.field_type.as_str() {
        PROOF_OP_IAVL_COMMITMENT => iavl_spec(),
        PROOF_OP_SIMPLE_MERKLE_COMMITMENT => tendermint_spec(),
        PROOF_OP_SMT_COMMITMENT => smt_spec(),
        _ => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unexpected ProofOp.Type",
            )))
        }
    };

    let mut proof = ics23::CommitmentProof { proof: None };
    proof.merge(pop.data.as_slice())?;

    Ok(Box::new(CommitmentOp {
        op_type: pop.field_type,
        spec,
        key: pop.key,
        proof,
    }))
}

impl ProofOperator for CommitmentOp {
    /// Returns the key associated with the proof operation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the operation key as a vector of bytes, or an error if any occurs.
    fn get_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.key.clone())
    }

    /// Attempts to verify the proof operation against provided arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - Arguments for the proof verification, where the length dictates the type of verification:
    ///   - Length 0 for non-membership proof verification.
    ///   - Length 1 for membership proof verification.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either a vector of root hashes on success, or an error on failure.
    fn run(&self, args: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let ex = to_exist_proof(&self.proof, &self.key).unwrap_or_else(|| {
            panic!(
                "missing existence proof for storage key: {}",
                hex::encode(self.key.clone())
            )
        });
        let root = calculate_existence_root::<HostFunctionsManager>(ex)?;
        match args.len() {
            0 => {
                let absent = verify_non_membership::<HostFunctionsManager>(
                    &self.proof,
                    &self.spec,
                    &root,
                    &self.key,
                );
                if !absent {
                    return Err("expected non-membership proof".into());
                }
            }
            1 => {
                let exists = verify_membership::<HostFunctionsManager>(
                    &self.proof,
                    &self.spec,
                    &root,
                    &self.key,
                    &args[0],
                );
                if !exists {
                    return Err("expected membership proof".into());
                }
            }
            _ => return Err("args must be length 0 or 1".into()),
        }
        Ok(vec![root.to_vec()])
    }
}

/// Extracts an `ExistenceProof` from a `CommitmentProof` if available.
///
/// # Arguments
///
/// * `proof` - The `CommitmentProof` containing the proof to extract.
/// * `key` - The key associated with the existence proof to find.
///
/// # Returns
///
/// An `Option` containing the `ExistenceProof` if found, or `None` if not.
fn to_exist_proof<'a>(
    proof: &'a ics23::CommitmentProof,
    key: &[u8],
) -> Option<&'a ics23::ExistenceProof> {
    match &proof.proof {
        Some(ics23::commitment_proof::Proof::Exist(ex)) => Some(ex),
        Some(ics23::commitment_proof::Proof::Batch(batch)) => {
            for entry in &batch.entries {
                if let Some(ics23::batch_entry::Proof::Exist(ex)) = &entry.proof {
                    if ex.key == key {
                        return Some(ex);
                    }
                }
            }
            None
        }
        _ => None,
    }
}
