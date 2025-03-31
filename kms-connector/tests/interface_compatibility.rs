use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

// EXPECTED_HASH values are computed from the interface files
const IDECRYPTION_MANAGER_HASH: &str =
    "f52f00aa3cc838695900d96063e2a8252fcc7fdd331ecd09c29b2b653be64846";
const IHTTPZ_HASH: &str = "ab256d548b04b6adfb7c1c7c344339d591d59ae121cbe833ed6234e173e0e331";

/// Interface file definition with its path and expected hash
struct InterfaceFile {
    path: &'static str,
    expected_hash: &'static str,
    rust_binding_path: &'static str,
}

const INTERFACE_FILES: &[InterfaceFile] = &[
    InterfaceFile {
        path: "gateway-l2/contracts/interfaces/IDecryptionManager.sol",
        expected_hash: IDECRYPTION_MANAGER_HASH,
        rust_binding_path: "gwl2_contracts/decryption.rs",
    },
    InterfaceFile {
        path: "gateway-l2/contracts/interfaces/IHTTPZ.sol",
        expected_hash: IHTTPZ_HASH,
        rust_binding_path: "gwl2_contracts/httpz.rs",
    },
];

/// Compute SHA256 hash of the file's content
fn compute_sol_file_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

#[test]
fn test_solidity_interfaces() {
    for interface in INTERFACE_FILES {
        let sol_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(interface.path);
        let content = fs::read_to_string(&sol_path)
            .unwrap_or_else(|_| panic!("Failed to read {}", interface.path));

        let current_hash = compute_sol_file_hash(&content);

        assert_eq!(
            current_hash,
            interface.expected_hash,
            "{} interface has changed!\n\
             \n\
             Steps to resolve:\n\
             1. Review the changes in {}\n\
             2. Update the Rust interface in {} if needed\n\
             3. Run this test again to get the new hash\n\
             4. Update EXPECTED_HASH in this test with the new hash: {}\n\
             \n\
             Note: This check ensures that any changes to the Solidity interface\n\
             are intentional and the Rust bindings are updated accordingly.",
            sol_path.file_name().unwrap().to_string_lossy(),
            sol_path.display(),
            interface.rust_binding_path,
            current_hash
        );
    }
}
