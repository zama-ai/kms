#![allow(clippy::unit_arg)]
//! Size benchmarks for ZK proof-of-knowledge proofs.
//!
//! Measures sizes of the proofs generated for:
//!  - Prover load
//!  - Verifier load
//!
//! Run with:
//!   cargo bench --bench non-threshold_tfhe-zk-pok_size

#[path = "../utilities.rs"]
mod utilities;

use experiments::zk_utils::{nist_gen_crs, nist_gen_proof, nist_gen_proof_inputs};
use utilities::ALL_PARAMS;

fn main() {
    for (params_name, params) in ALL_PARAMS {
        let bench_name = format!("non-threshold_zk-pok_{params_name}");
        let crs = nist_gen_crs(params);
        let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, params);
        let proof_prover_load = nist_gen_proof(
            &crs,
            &public_commit,
            &private_commit,
            &metadata,
            tfhe::zk::ZkComputeLoad::Proof,
        );

        let serialized = bc2wrap::serialize(&proof_prover_load).unwrap();
        println!(
            "proof size (B, serialized): {bench_name}_proof_load={}",
            serialized.len()
        );

        let proof_verifier_load = nist_gen_proof(
            &crs,
            &public_commit,
            &private_commit,
            &metadata,
            tfhe::zk::ZkComputeLoad::Verify,
        );
        let serialized = bc2wrap::serialize(&proof_verifier_load).unwrap();
        println!(
            "proof size (B, serialized): {bench_name}_verify_load={}",
            serialized.len()
        );
    }
}
