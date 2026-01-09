//! Sanity test demonstrating the new consolidated testing module
//!
//! This test shows how to use the new testing infrastructure with the unified prelude
//! and builder pattern that eliminates Docker dependency and provides clean, type-safe APIs.

// NEW: Single import using the consolidated testing module
use crate::testing::prelude::*;

/// Test using isolated centralized setup with NEW builder pattern
///
/// This demonstrates the simplified API using CentralizedTestEnv builder.
/// Compare this to the old approach - much cleaner!
///
/// NOTE: This test is skipped in CI (--skip isolated_test_example) as it's primarily
/// for demonstration purposes. To run locally: cargo test --lib test_centralized_isolated_example
#[tokio::test]
#[ignore] // Skip by default - run explicitly with --ignored
async fn test_centralized_isolated_example() -> Result<()> {
    // NEW: Simple builder pattern - all setup handled automatically!
    let env = CentralizedTestEnv::builder()
        .with_test_name("centralized_example")
        .build()
        .await?;

    // Access the server and client
    let _server = &env.server;
    let _client = &env.client;
    let _material_dir = &env.material_dir;

    // TODO: add test operations
    // Example:
    // let mut client = env.client.clone();
    // let response = client.some_operation(request).await?;

    tracing::info!("✅ Centralized isolated test completed successfully");
    Ok(())
}

/// Test using isolated threshold setup with NEW builder pattern
///
/// This demonstrates the simplified API using ThresholdTestEnv builder.
/// Notice how much simpler this is compared to manual setup!
///
/// NOTE: This test is skipped in CI (--skip isolated_test_example) as it's primarily
/// for demonstration purposes. To run locally: cargo test --lib test_threshold_isolated_example --ignored
#[tokio::test]
#[ignore] // Skip by default - run explicitly with --ignored
async fn test_threshold_isolated_example() -> Result<()> {
    // NEW: Simple builder pattern - all party setup handled automatically!
    let env = ThresholdTestEnv::builder()
        .with_test_name("threshold_example")
        .with_party_count(4)
        .with_threshold(1) // For 4 parties: nodes = 3*threshold + 1, so threshold = 1
        .build()
        .await?;

    // Access servers and clients by party ID
    let _servers = &env.servers;
    let _clients = &env.clients;
    let _material_dir = &env.material_dir;

    // TODO: add test operations
    // Example:
    // for (party_id, client) in &env.clients {
    //     let mut client = client.clone();
    //     let response = client.some_operation(request).await?;
    // }

    tracing::info!("✅ Threshold isolated test completed successfully");
    Ok(())
}

/// Test using different material types with NEW builder pattern
///
/// This demonstrates how to use custom material specifications with the builder.
///
/// NOTE: This test is skipped in CI (--skip isolated_test_example) as it's primarily
/// for demonstration purposes. To run locally: cargo test --lib test_different_material_types --ignored
#[tokio::test]
#[ignore]
async fn test_different_material_types() -> Result<()> {
    // Test with testing material (fast, small keys) - DEFAULT
    let env1 = CentralizedTestEnv::builder()
        .with_test_name("testing_material")
        .build()
        .await?;
    tracing::info!(
        "Testing material setup in: {}",
        env1.material_dir.path().display()
    );

    // Test with production-like material (slower, larger keys)
    let production_spec = TestMaterialSpec::centralized_default();
    let env2 = CentralizedTestEnv::builder()
        .with_test_name("production_material")
        .with_material_spec(production_spec)
        .build()
        .await?;
    tracing::info!(
        "Production material setup in: {}",
        env2.material_dir.path().display()
    );

    // Test with comprehensive material (all key types)
    let comprehensive_spec = TestMaterialSpec::comprehensive(None);
    let env3 = CentralizedTestEnv::builder()
        .with_test_name("comprehensive_material")
        .with_material_spec(comprehensive_spec)
        .build()
        .await?;
    tracing::info!(
        "Comprehensive material setup in: {}",
        env3.material_dir.path().display()
    );

    tracing::info!("✅ Different material types test completed successfully");
    Ok(())
}

/// Test validating test material existence with NEW builder pattern
///
/// Material validation is now handled automatically by the builder.
/// This test demonstrates that setup fails gracefully when material is missing.
#[tokio::test]
async fn test_material_validation() -> Result<()> {
    use std::path::PathBuf;

    // Test that setup fails when material doesn't exist
    let nonexistent_path = PathBuf::from("/nonexistent/test-material");
    let manager = TestMaterialManager::new(Some(nonexistent_path));

    let result = CentralizedTestEnv::builder()
        .with_test_name("validation_test")
        .with_material_manager(manager)
        .build()
        .await;

    assert!(
        result.is_err(),
        "Setup should fail when material doesn't exist"
    );

    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("Material not found"),
            "Error should mention missing material, got: {}",
            error_msg
        );
    }

    tracing::info!("✅ Material validation test completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::testing::material::{KeyType, TestMaterialSpec};

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
