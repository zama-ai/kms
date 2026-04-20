use tfhe_zk_pok::curve_api::Bls12_446;
use tfhe_zk_pok::proofs::pke_v2::{Proof as ProofV2, PublicParams};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_experiments::{
    utils::check_hash,
    zk_utils::{nist_gen_crs, nist_gen_proof, nist_gen_proof_inputs, nist_run_verify},
};

const CRS_LABEL: &str = "CRS";
const PROOF_LABEL: &str = "PROOF";
const EXPECTED_HASH_CRS: &str = "e7133c99195bdd0d8d00800b86e54f5d11d348da8954604d02cacb424d011e78";
const EXPECTED_HASH_PROOF: &str =
    "05491c9c547814cb7b2ad15f8218915e11d1639015c25bdec00702d19a0fa990";

fn generate_crs(params: DKGParams) -> PublicParams<Bls12_446> {
    let crs = nist_gen_crs(params);

    let bytes = bc2wrap::serialize(&crs).unwrap();
    check_hash(CRS_LABEL, &bytes, EXPECTED_HASH_CRS, false);

    crs
}

fn generate_proof(crs: &PublicParams<Bls12_446>, params: DKGParams) -> ProofV2<Bls12_446> {
    let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(crs, params);
    let proof = nist_gen_proof(
        crs,
        &public_commit,
        &private_commit,
        &metadata,
        tfhe::zk::ZkComputeLoad::Proof,
    );

    let bytes = bc2wrap::serialize(&proof).unwrap();
    check_hash(PROOF_LABEL, &bytes, EXPECTED_HASH_PROOF, false);

    proof
}

fn verify_proof(proof: &ProofV2<Bls12_446>, crs: &PublicParams<Bls12_446>, params: DKGParams) {
    let (public_commit, _private_commit, metadata) = nist_gen_proof_inputs(crs, params);
    nist_run_verify(proof, crs, &public_commit, &metadata);
}

fn main() {
    println!("STARTING TFHE ZK POK KAT");

    let params = threshold_execution::tfhe_internals::parameters::NIST_PARAMS_P32_SNS_FGLWE;

    let crs = generate_crs(params);
    let proof = generate_proof(&crs, params);

    verify_proof(&proof, &crs, params);

    println!("✅ All tfhe-zk-pok KAT artifacts matched and verified successfully");
}
