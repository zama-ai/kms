//! Memory benchmarks for ZK proof-of-knowledge operations.
//!
//! Measures peak heap allocation for:
//!   - CRS generation
//!   - Proof generation  (CRS pre-computed)
//!   - Proof verification in TwoSteps mode (proof pre-computed)
//!   - Proof verification in Batched mode  (proof pre-computed)
//!
//! The reported figure is the peak heap level observed from the moment the
//! measurement begins, which includes all required inputs already in memory
//! (CRS, commits, proof).  This reflects the total RAM a deployment must have
//! available to execute the operation.
//!
//! Requires the `measure_memory` feature:
//!   cargo bench --bench non-threshold_tfhe-zk-pok_memory --features measure_memory

#[path = "../utilities.rs"]
mod utilities;

use utilities::{ALL_PARAMS, bench_memory};

use tfhe_zk_pok::curve_api::Bls12_446;
use tfhe_zk_pok::proofs::pke_v2::{PrivateCommit, Proof as ProofV2, PublicCommit, PublicParams};
use threshold_experiments::zk_utils::{
    METADATA_LEN, PkeZkParams, nist_gen_crs, nist_gen_crs_from_params, nist_gen_proof,
    nist_gen_proof_inputs, nist_pke_params_from_dkg, nist_seeded_rng, nist_verify_batched,
    nist_verify_two_steps,
};

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

fn main() {
    threshold_experiments::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    for (params_name, dkg_params) in ALL_PARAMS {
        let pke_params: PkeZkParams = nist_pke_params_from_dkg(dkg_params);

        // CRS generation
        {
            let bench_name = format!("non-threshold_zk-pok_{params_name}_crs_gen_memory");
            // Input: PkeZkParams (Copy).  A fresh deterministic RNG is created
            // inside the closure so that each of the 10 runs performs identical
            // work without sharing any state.
            bench_memory(
                |p: &mut PkeZkParams| {
                    let mut rng = nist_seeded_rng(*b"BENCHCRS");
                    nist_gen_crs_from_params(p, &mut rng)
                },
                &mut pke_params.clone(),
                bench_name,
            );
        }

        // Proof generation - Compute load: Proof
        {
            let bench_name =
                format!("non-threshold_zk-pok_{params_name}_proof_gen_load_proof_memory");
            let crs: PublicParams<Bls12_446> = nist_gen_crs(dkg_params);
            let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, dkg_params);

            let mut proof_inputs: (
                PublicParams<Bls12_446>,
                PublicCommit<Bls12_446>,
                PrivateCommit<Bls12_446>,
                [u8; METADATA_LEN],
            ) = (crs, public_commit, private_commit, metadata);

            bench_memory(
                |(crs, pub_c, priv_c, meta): &mut (
                    PublicParams<Bls12_446>,
                    PublicCommit<Bls12_446>,
                    PrivateCommit<Bls12_446>,
                    [u8; METADATA_LEN],
                )| {
                    nist_gen_proof(crs, pub_c, priv_c, meta, tfhe::zk::ZkComputeLoad::Proof)
                },
                &mut proof_inputs,
                bench_name,
            );
        }

        // Proof generation - Compute load: Verify
        {
            let bench_name =
                format!("non-threshold_zk-pok_{params_name}_proof_gen_load_verify_memory");
            let crs: PublicParams<Bls12_446> = nist_gen_crs(dkg_params);
            let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, dkg_params);

            let mut proof_inputs: (
                PublicParams<Bls12_446>,
                PublicCommit<Bls12_446>,
                PrivateCommit<Bls12_446>,
                [u8; METADATA_LEN],
            ) = (crs, public_commit, private_commit, metadata);

            bench_memory(
                |(crs, pub_c, priv_c, meta): &mut (
                    PublicParams<Bls12_446>,
                    PublicCommit<Bls12_446>,
                    PrivateCommit<Bls12_446>,
                    [u8; METADATA_LEN],
                )| {
                    nist_gen_proof(crs, pub_c, priv_c, meta, tfhe::zk::ZkComputeLoad::Verify)
                },
                &mut proof_inputs,
                bench_name,
            );
        }

        // Verification – TwoSteps mode - Compute load: Proof
        {
            let bench_name =
                format!("non-threshold_zk-pok_{params_name}_verify_two_steps_load_proof_memory");
            let crs: PublicParams<Bls12_446> = nist_gen_crs(dkg_params);
            let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, dkg_params);
            let proof: ProofV2<Bls12_446> = nist_gen_proof(
                &crs,
                &public_commit,
                &private_commit,
                &metadata,
                tfhe::zk::ZkComputeLoad::Proof,
            );

            let mut verify_inputs: (
                ProofV2<Bls12_446>,
                PublicParams<Bls12_446>,
                PublicCommit<Bls12_446>,
                [u8; METADATA_LEN],
            ) = (proof, crs, public_commit, metadata);

            bench_memory(
                |(proof, crs, pub_c, meta): &mut (
                    ProofV2<Bls12_446>,
                    PublicParams<Bls12_446>,
                    PublicCommit<Bls12_446>,
                    [u8; METADATA_LEN],
                )| nist_verify_two_steps(proof, crs, pub_c, meta).unwrap(),
                &mut verify_inputs,
                bench_name,
            );
        }

        // Verification – TwoSteps mode - Compute load: Verify
        {
            let bench_name =
                format!("non-threshold_zk-pok_{params_name}_verify_two_steps_load_verify_memory");
            let crs: PublicParams<Bls12_446> = nist_gen_crs(dkg_params);
            let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, dkg_params);
            let proof: ProofV2<Bls12_446> = nist_gen_proof(
                &crs,
                &public_commit,
                &private_commit,
                &metadata,
                tfhe::zk::ZkComputeLoad::Verify,
            );

            let mut verify_inputs: (
                ProofV2<Bls12_446>,
                PublicParams<Bls12_446>,
                PublicCommit<Bls12_446>,
                [u8; METADATA_LEN],
            ) = (proof, crs, public_commit, metadata);

            bench_memory(
                |(proof, crs, pub_c, meta): &mut (
                    ProofV2<Bls12_446>,
                    PublicParams<Bls12_446>,
                    PublicCommit<Bls12_446>,
                    [u8; METADATA_LEN],
                )| nist_verify_two_steps(proof, crs, pub_c, meta).unwrap(),
                &mut verify_inputs,
                bench_name,
            );
        }

        // Verification – Batched mode - Compute load: Proof
        {
            let bench_name =
                format!("non-threshold_zk-pok_{params_name}_verify_batched_load_proof_memory");
            let crs: PublicParams<Bls12_446> = nist_gen_crs(dkg_params);
            let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, dkg_params);
            let proof: ProofV2<Bls12_446> = nist_gen_proof(
                &crs,
                &public_commit,
                &private_commit,
                &metadata,
                tfhe::zk::ZkComputeLoad::Proof,
            );

            let mut verify_inputs: (
                ProofV2<Bls12_446>,
                PublicParams<Bls12_446>,
                PublicCommit<Bls12_446>,
                [u8; METADATA_LEN],
            ) = (proof, crs, public_commit, metadata);

            bench_memory(
                |(proof, crs, pub_c, meta): &mut (
                    ProofV2<Bls12_446>,
                    PublicParams<Bls12_446>,
                    PublicCommit<Bls12_446>,
                    [u8; METADATA_LEN],
                )| nist_verify_batched(proof, crs, pub_c, meta).unwrap(),
                &mut verify_inputs,
                bench_name,
            );
        }

        // Verification – Batched mode - Compute load: Verify
        {
            let bench_name =
                format!("non-threshold_zk-pok_{params_name}_verify_batched_load_verify_memory");
            let crs: PublicParams<Bls12_446> = nist_gen_crs(dkg_params);
            let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, dkg_params);
            let proof: ProofV2<Bls12_446> = nist_gen_proof(
                &crs,
                &public_commit,
                &private_commit,
                &metadata,
                tfhe::zk::ZkComputeLoad::Verify,
            );

            let mut verify_inputs: (
                ProofV2<Bls12_446>,
                PublicParams<Bls12_446>,
                PublicCommit<Bls12_446>,
                [u8; METADATA_LEN],
            ) = (proof, crs, public_commit, metadata);

            bench_memory(
                |(proof, crs, pub_c, meta): &mut (
                    ProofV2<Bls12_446>,
                    PublicParams<Bls12_446>,
                    PublicCommit<Bls12_446>,
                    [u8; METADATA_LEN],
                )| nist_verify_batched(proof, crs, pub_c, meta).unwrap(),
                &mut verify_inputs,
                bench_name,
            );
        }
    }
}
