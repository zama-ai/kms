//! Sanity test demonstrating the new isolated test material approach
//!
//! This test shows how to use the new test infrastructure that eliminates
//! Docker dependency and shared test material issues.

use crate::client::test_tools::{
    setup_centralized_isolated, setup_threshold_isolated, ThresholdTestConfig,
};
use crate::util::key_setup::test_material_manager::TestMaterialManager;
use crate::util::key_setup::test_material_spec::{MaterialType, TestMaterialSpec};
use crate::vault::storage::{file::FileStorage, StorageType};
use anyhow::Result;
use tempfile::TempDir;

/// Test using isolated centralized setup
#[tokio::test]
async fn test_centralized_isolated_example() -> Result<()> {
    use crate::consts::{OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID, TEST_PARAM};
    use crate::util::key_setup::ensure_central_keys_exist;
    use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
    use crate::vault::storage::Storage;
    use kms_grpc::rpc_types::PubDataType;

    let manager = TestMaterialManager::new(None);
    let spec = TestMaterialSpec::centralized_basic();
    let material_dir = manager
        .setup_test_material(&spec, "centralized_example")
        .await?;

    ensure_testing_material_exists(Some(material_dir.path())).await;

    let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
    let mut priv_storage = FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;

    // Fix public key RequestIds
    let _ = pub_storage
        .delete_data(&TEST_CENTRAL_KEY_ID, &PubDataType::PublicKey.to_string())
        .await;
    let _ = pub_storage
        .delete_data(&OTHER_CENTRAL_TEST_ID, &PubDataType::PublicKey.to_string())
        .await;

    ensure_central_keys_exist(
        &mut pub_storage,
        &mut priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        true, // deterministic
        true, // write_privkey
    )
    .await;

    // Setup centralized KMS with isolated material
    let (_server_handle, _client) = setup_centralized_isolated(
        pub_storage,
        priv_storage,
        None, // No backup vault
        None, // No rate limiter
        Some(material_dir.path()),
    )
    .await;

    // TODO: add test operations

    tracing::info!("✅ Centralized isolated test completed successfully");
    Ok(())
}

/// Test using isolated threshold setup
#[tokio::test]
async fn test_threshold_isolated_example() -> Result<()> {
    const NUM_PARTIES: usize = 4;

    // Setup isolated test material
    let manager = TestMaterialManager::new(None);
    let spec = TestMaterialSpec::threshold_basic(NUM_PARTIES);
    let material_dir = manager
        .setup_test_material(&spec, "threshold_example")
        .await?;

    // Create storage instances for each party
    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    let mut vaults = Vec::new();

    for i in 1..=NUM_PARTIES {
        let role = threshold_fhe::execution::runtime::party::Role::indexed_from_one(i);

        let pub_storage =
            FileStorage::new(Some(material_dir.path()), StorageType::PUB, Some(role))?;
        let priv_storage =
            FileStorage::new(Some(material_dir.path()), StorageType::PRIV, Some(role))?;

        pub_storages.push(pub_storage);
        priv_storages.push(priv_storage);
        vaults.push(None); // No backup vaults for this example
    }

    // Setup threshold KMS with isolated material
    let (_server_handles, _clients) = setup_threshold_isolated(
        2, // threshold
        pub_storages,
        priv_storages,
        vaults,
        ThresholdTestConfig {
            test_material_path: Some(material_dir.path()),
            ..Default::default()
        },
    )
    .await;

    // TODO: add test operations

    tracing::info!("✅ Threshold isolated test completed successfully");
    Ok(())
}

/// Test using different material types
#[tokio::test]
async fn test_different_material_types() -> Result<()> {
    let manager = TestMaterialManager::new(None);

    // Test with testing material (fast, small keys)
    let testing_spec = TestMaterialSpec::centralized_basic();
    assert_eq!(testing_spec.material_type, MaterialType::Testing);

    let testing_dir = manager
        .setup_test_material(&testing_spec, "testing_material")
        .await?;
    tracing::info!(
        "Testing material setup in: {}",
        testing_dir.path().display()
    );

    // Test with production-like material (slower, larger keys)
    let production_spec = TestMaterialSpec::production_like(None);
    assert_eq!(production_spec.material_type, MaterialType::Default);

    let production_dir = manager
        .setup_test_material(&production_spec, "production_material")
        .await?;
    tracing::info!(
        "Production material setup in: {}",
        production_dir.path().display()
    );

    // Test with comprehensive material (all key types)
    let comprehensive_spec = TestMaterialSpec::comprehensive(Some(4));
    assert!(comprehensive_spec.include_slow_material);

    let comprehensive_dir = manager
        .setup_test_material(&comprehensive_spec, "comprehensive_material")
        .await?;
    tracing::info!(
        "Comprehensive material setup in: {}",
        comprehensive_dir.path().display()
    );

    tracing::info!("✅ Different material types test completed successfully");
    Ok(())
}

/// Test validating test material existance
#[tokio::test]
async fn test_material_validation() -> Result<()> {
    use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists_check_only;

    // Setup test material
    let manager = TestMaterialManager::new(None);
    let spec = TestMaterialSpec::centralized_basic();
    let material_dir = manager
        .setup_test_material(&spec, "validation_test")
        .await?;

    // Validate that material exists
    let material_exists =
        ensure_testing_material_exists_check_only(Some(material_dir.path())).await;
    assert!(material_exists, "Test material should exist after setup");

    // Test with non-existent path
    let temp_dir = TempDir::new()?;
    let empty_path = temp_dir.path().join("nonexistent");
    let no_material = ensure_testing_material_exists_check_only(Some(&empty_path)).await;
    assert!(!no_material, "Material should not exist in empty directory");

    tracing::info!("✅ Material validation test completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::util::key_setup::test_material_spec::{KeyType, TestMaterialSpec};

    #[test]
    fn test_material_spec_creation() {
        // Test centralized spec
        let centralized = TestMaterialSpec::centralized_basic();
        assert!(!centralized.is_threshold());
        assert_eq!(centralized.party_count(), 1);
        assert!(centralized.requires_key_type(KeyType::ClientKeys));
        assert!(centralized.requires_key_type(KeyType::SigningKeys));
        assert!(centralized.requires_key_type(KeyType::FheKeys));
        assert!(!centralized.requires_key_type(KeyType::PrssSetup));

        // Test threshold spec
        let threshold = TestMaterialSpec::threshold_basic(4);
        assert!(threshold.is_threshold());
        assert_eq!(threshold.party_count(), 4);
        assert!(threshold.requires_key_type(KeyType::PrssSetup));
        assert!(threshold.requires_key_type(KeyType::ServerSigningKeys));

        // Test comprehensive spec
        let comprehensive = TestMaterialSpec::comprehensive(Some(4));
        assert!(comprehensive.include_slow_material);
        assert!(comprehensive.requires_key_type(KeyType::CrsKeys));
        assert!(comprehensive.requires_key_type(KeyType::DecompressionKeys));
    }

    #[test]
    fn test_material_spec_serialization() {
        let spec = TestMaterialSpec::threshold_basic(4);

        // Test JSON serialization
        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: TestMaterialSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(spec, deserialized);
    }
}
