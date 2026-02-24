//! Common test helper functions
//!
//! This module provides reusable helper functions for test setup and utilities.
use super::material::TestMaterialManager;
use crate::consts::{
    DEFAULT_EPOCH_ID, OTHER_CENTRAL_TEST_ID, SIGNING_KEY_ID, TEST_CENTRAL_KEY_ID, TEST_PARAM,
};
use crate::util::key_setup::{ensure_central_keys_exist, ensure_central_server_signing_keys_exist};
use crate::vault::storage::{file::FileStorage, Storage};
use anyhow::Result;
use kms_grpc::rpc_types::PubDataType;

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

    if workspace_root.is_none() {
        tracing::warn!(
            "Could not find test-material directory. Tests requiring pre-generated material may fail. \
             Run 'cargo run -p generate-test-material -- --output ./test-material testing' from workspace root."
        );
    }

    TestMaterialManager::new(workspace_root.map(|p| p.join("test-material")))
}

/// Regenerate central server keys for tests
///
/// Deletes existing keys and regenerates all central server keys
/// (both private and public) with correct, matching RequestIds.
/// This ensures test material has consistent key pairs including:
/// - Server signing keys (VerfKey, VerfAddress, SigningKey)
/// - FHE keys (PublicKey, ServerKey, FhePrivateKey)
///
/// # Arguments
/// * `pub_storage` - Public storage for regenerated keys
/// * `priv_storage` - Private storage for regenerated keys
pub async fn regenerate_central_keys(
    pub_storage: &mut FileStorage,
    priv_storage: &mut FileStorage,
) -> Result<()> {
    tracing::info!(
        "regenerate_central_keys: Ensuring signing keys exist in {} and {}",
        pub_storage.root_dir().display(),
        priv_storage.root_dir().display()
    );

    // Delete all signing-related directories to force complete regeneration
    remove_dir_if_exists(priv_storage.root_dir().join("SigningKey")).await;
    remove_dir_if_exists(pub_storage.root_dir().join("VerfKey")).await;
    remove_dir_if_exists(pub_storage.root_dir().join("VerfAddress")).await;

    // Regenerate signing keys (VerfKey, VerfAddress, SigningKey)
    let generated = ensure_central_server_signing_keys_exist(
        pub_storage,
        priv_storage,
        &SIGNING_KEY_ID,
        true, // deterministic
    )
    .await;

    if !generated {
        return Err(anyhow::anyhow!(
            "Failed to generate central server signing keys"
        ));
    }

    // Delete all FHE key artifacts to force clean regeneration.
    // ensure_central_keys_exist short-circuits on existing PublicKey, but we also
    // remove ServerKey and FhePrivateKey to avoid stale data from a previous run.
    for key_id in [&*TEST_CENTRAL_KEY_ID, &*OTHER_CENTRAL_TEST_ID] {
        let _ = pub_storage
            .delete_data(key_id, &PubDataType::PublicKey.to_string())
            .await;
        let _ = pub_storage
            .delete_data(key_id, &PubDataType::ServerKey.to_string())
            .await;
    }

    // Regenerate FHE keys
    if !ensure_central_keys_exist(
        pub_storage,
        priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        &DEFAULT_EPOCH_ID,
        true, // deterministic
        true, // write_privkey
    )
    .await
    {
        return Err(anyhow::anyhow!("Failed to generate central FHE keys"));
    }

    Ok(())
}

/// Remove a directory if it exists, logging the outcome.
async fn remove_dir_if_exists(path: std::path::PathBuf) {
    match tokio::fs::remove_dir_all(&path).await {
        Ok(()) => tracing::info!("Removed directory: {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // nothing to remove
        Err(e) => tracing::warn!("Failed to remove {}: {}", path.display(), e),
    }
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
            .map(|id| id.to_string().into_bytes())
            .unwrap_or_default(),
        verifying_contract: domain
            .verifying_contract
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        salt: domain.salt.map(|s| s.to_vec()),
    }
}
