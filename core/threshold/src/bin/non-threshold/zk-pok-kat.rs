use clap::Parser;
use std::path::Path;
use tfhe_zk_pok::curve_api::Bls12_446;
use tfhe_zk_pok::proofs::pke_v2::{Proof as ProofV2, PublicParams};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::zk_utils::{gen_crs, gen_proof, gen_proof_inputs, run_verify};

#[derive(Parser, Debug)]
#[clap(name = "non-threshold-zk-pok-kat")]
#[clap(about = "Known Answer Tests for tfhe-zk-pok")]
struct KatCli {
    #[clap(short, long, default_value_t = false)]
    generate_kat: bool,

    #[clap(short, long, default_value = "./tfhe_zk_pok_kat")]
    path_to_kat_folder: String,
}

// KAT file I/O helpers
fn write_or_assert(path: &Path, bytes: &[u8], generate_kat: bool, label: &str) {
    if generate_kat {
        std::fs::write(path, bytes).unwrap();
        println!("saved {label} to {}", path.display());
    } else {
        let expected = std::fs::read(path).unwrap_or_else(|e| {
            panic!("missing KAT artifact at {}: {e}", path.display());
        });
        assert_eq!(
            expected,
            bytes,
            "❌ artifact mismatch for {label} at {}",
            path.display()
        );
    }
}

fn write_or_assert_value<T: serde::Serialize>(
    dir: &Path,
    name: &str,
    value: &T,
    generate_kat: bool,
) {
    let path = dir.join(name);
    let bytes = bc2wrap::serialize(value).unwrap();
    write_or_assert(&path, &bytes, generate_kat, name);
}

fn read_value<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> T {
    let path = dir.join(name);
    bc2wrap::deserialize_unsafe(&std::fs::read(&path).unwrap_or_else(|e| {
        panic!("missing KAT artifact at {}: {e}", path.display());
    }))
    .unwrap()
}

fn generate_and_save_crs(
    params: DKGParams,
    storage_path: &Path,
    save: bool,
) -> PublicParams<Bls12_446> {
    let crs = gen_crs(params);

    if save {
        println!("Saving CRS...");
        let bytes = bc2wrap::serialize(&crs).unwrap();
        std::fs::write(storage_path.join("crs.bin"), bytes).unwrap();
    }
    crs
}

fn generate_proof(
    crs: &PublicParams<Bls12_446>,
    params: DKGParams,
    storage_path: &Path,
    save: bool,
) -> ProofV2<Bls12_446> {
    let (public_commit, private_commit, metadata) = gen_proof_inputs(crs, params);
    let proof = gen_proof(
        crs,
        &public_commit,
        &private_commit,
        &metadata,
        tfhe::zk::ZkComputeLoad::Proof,
    );

    if save {
        println!("Saving proof...");
        write_or_assert_value(storage_path, "proof.bin", &proof, true);
    }

    proof
}

fn verify_proof(proof: &ProofV2<Bls12_446>, crs: &PublicParams<Bls12_446>, params: DKGParams) {
    let (public_commit, _private_commit, metadata) = gen_proof_inputs(crs, params);
    run_verify(proof, crs, &public_commit, &metadata);
}

fn main() {
    let args = KatCli::parse();
    println!("STARTING TFHE ZK POK KAT WITH {:?}", args);

    let base = Path::new(&args.path_to_kat_folder);
    if args.generate_kat {
        std::fs::create_dir_all(base).unwrap();
    } else if !base.exists() {
        panic!(
            "KAT folder {} does not exist. Cannot verify KAT files.",
            base.display()
        );
    }

    let params = threshold_execution::tfhe_internals::parameters::NIST_PARAMS_P32_SNS_FGLWE;

    let crs = generate_and_save_crs(params, base, args.generate_kat);

    if !args.generate_kat {
        let stored_crs =
            read_value::<tfhe_zk_pok::proofs::pke_v2::PublicParams<Bls12_446>>(base, "crs.bin");
        assert_eq!(
            bc2wrap::serialize(&crs).unwrap(),
            bc2wrap::serialize(&stored_crs).unwrap(),
            "❌ artifact mismatch for CRS at {}",
            base.join("crs.bin").display()
        );
    }

    let proof = generate_proof(&crs, params, base, args.generate_kat);

    if !args.generate_kat {
        let stored_proof = read_value::<ProofV2<Bls12_446>>(base, "proof.bin");
        assert_eq!(
            bc2wrap::serialize(&proof).unwrap(),
            bc2wrap::serialize(&stored_proof).unwrap(),
            "❌ artifact mismatch for proof at {}",
            base.join("proof.bin").display()
        );
    }

    verify_proof(&proof, &crs, params);

    if !args.generate_kat {
        println!("✅ All tfhe-zk-pok KAT artifacts matched and verified successfully");
    }
}
