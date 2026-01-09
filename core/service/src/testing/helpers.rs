//! Common test helper functions
//!
//! This module provides reusable helper functions for test setup and utilities.

use super::material::TestMaterialManager;
use crate::consts::{DEFAULT_EPOCH_ID, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID, TEST_PARAM};
use crate::util::key_setup::ensure_central_keys_exist;
use crate::vault::storage::{file::FileStorage, Storage};
use anyhow::Result;
use kms_grpc::rpc_types::PubDataType;

/// Create test material manager with workspace test-material path
///
/// This helper automatically locates the workspace root and configures
/// the manager to use the `test-material/` directory.
pub fn create_test_material_manager() -> TestMaterialManager {
    // Try to find workspace root by looking for Cargo.toml
    let workspace_root = std::env::current_dir().ok().and_then(|mut path| {
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

    TestMaterialManager::new(workspace_root.map(|p| p.join("test-material")))
}

/// Fix public key RequestIds for centralized tests
///
/// Ensures public keys are stored with correct RequestIds that match private keys.
/// This is necessary because pre-generated material may have mismatched RequestIds.
///
/// # Arguments
/// * `pub_storage` - Public storage to update
/// * `priv_storage` - Private storage (used to regenerate keys)
pub async fn fix_centralized_public_keys(
    pub_storage: &mut FileStorage,
    priv_storage: &mut FileStorage,
) -> Result<()> {
    // Clear existing public keys to force regeneration with correct RequestIds
    let _ = pub_storage
        .delete_data(&TEST_CENTRAL_KEY_ID, &PubDataType::PublicKey.to_string())
        .await;
    let _ = pub_storage
        .delete_data(&OTHER_CENTRAL_TEST_ID, &PubDataType::PublicKey.to_string())
        .await;

    ensure_central_keys_exist(
        pub_storage,
        priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        &DEFAULT_EPOCH_ID,
        true, // deterministic
        true, // write_privkey
    )
    .await;

    Ok(())
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
