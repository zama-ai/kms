//! Tests for the isolated testing infrastructure
//!
//! These tests validate the testing infrastructure components:
//! - `TestMaterialManager` - copies pre-generated material to isolated directories
//! - `TestMaterialSpec` - declares what cryptographic material a test needs
//! - `CentralizedTestEnv` - builder for centralized KMS test environments
//!
//! For examples of how to write isolated tests, see:
//! - Centralized: `centralized/misc_tests_isolated.rs`

use crate::testing::prelude::*;

/// Validates that CentralizedTestEnv builder fails gracefully when material is missing.
#[tokio::test]
async fn test_material_validation() -> Result<()> {
    use std::path::PathBuf;

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
