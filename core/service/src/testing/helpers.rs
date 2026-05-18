//! Common test helper functions
//!
//! This module provides reusable helper functions for test setup and utilities.
use super::material::TestMaterialManager;

/// Create test material manager with workspace test-material path
///
/// This helper automatically locates the workspace root and configures
/// the manager to use the `test-material/` directory.
pub fn create_test_material_manager() -> TestMaterialManager {
    // Try to find workspace root by looking for Cargo.toml and test-material/
    // Start from CARGO_MANIFEST_DIR if available (more reliable in cargo test/nextest)
    // Fall back to current_dir() if not available
    let start_path = std::env::var("CARGO_MANIFEST_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok());

    let workspace_root = start_path.and_then(|mut path| {
        // Walk up the directory tree looking for workspace root
        loop {
            if path.join("Cargo.toml").exists() && path.join("test-material").exists() {
                return Some(path);
            }
            if !path.pop() {
                break;
            }
        }
        None
    });

    match &workspace_root {
        Some(root) => tracing::info!(
            "Test material source path resolved: {}",
            root.join("test-material").display()
        ),
        None => tracing::warn!(
            "Could not find test-material directory (searched from: {}). \
             Tests requiring pre-generated material may fail. \
             Run 'cargo run -p generate-test-material -- --output ./test-material --profile insecure --parties 4' from workspace root.",
            std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| "<unknown>".to_string())
        ),
    }

    TestMaterialManager::new(workspace_root.map(|p| p.join("test-material")))
}

/// Convert Eip712Domain to Eip712DomainMsg for gRPC requests
///
/// This is a common conversion needed in many tests that work with EIP-712 signatures.
#[cfg(any(test, feature = "testing"))]
pub fn domain_to_msg(domain: &alloy_dyn_abi::Eip712Domain) -> kms_grpc::kms::v1::Eip712DomainMsg {
    kms_grpc::kms::v1::Eip712DomainMsg {
        name: domain
            .name
            .as_ref()
            .map(|n| n.to_string())
            .unwrap_or_default(),
        version: domain
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        chain_id: domain
            .chain_id
            .map(|id| id.to_be_bytes_vec())
            .unwrap_or_default(),
        verifying_contract: domain
            .verifying_contract
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        salt: domain.salt.map(|s| s.to_vec()),
    }
}
