//! Tests for the isolated testing infrastructure
//!
//! These tests validate the testing infrastructure components:
//! - `TestMaterialManager` - copies pre-generated material to isolated directories
//! - `TestMaterialSpec` - declares what cryptographic material a test needs
//! - `ThresholdTestEnv` - builder for threshold KMS test environments
//!
//! For examples of how to write isolated tests, see `threshold/misc_tests.rs`.

use crate::testing::prelude::*;

/// Validates that ThresholdTestEnv builder fails gracefully when material is missing.
#[tokio::test]
async fn test_threshold_material_validation() -> Result<()> {
    use std::path::PathBuf;

    let nonexistent_path = PathBuf::from("/nonexistent/test-material");
    let manager = TestMaterialManager::new(Some(nonexistent_path));

    let result = ThresholdTestEnv::builder()
        .with_test_name("threshold_validation_test")
        .with_material_manager(manager)
        .build()
        .await;

    assert!(
        result.is_err(),
        "ThresholdTestEnv setup should fail when material doesn't exist"
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
    use strum::IntoEnumIterator;

    #[test]
    fn test_material_spec_creation() {
        // Expected key types for each spec
        let threshold_expected = &[
            KeyType::ClientKeys,
            KeyType::SigningKeys,
            KeyType::ServerSigningKeys,
            KeyType::FheKeys,
            KeyType::DefaultEpoch,
        ];

        // Test threshold spec
        let threshold = TestMaterialSpec::threshold_basic(4);
        assert_eq!(threshold.party_count, 4);
        for key_type in KeyType::iter() {
            let expected = threshold_expected.contains(&key_type);
            assert_eq!(
                threshold.requires_key_type(key_type),
                expected,
                "threshold_basic: {:?} should be {}",
                key_type,
                if expected { "required" } else { "not required" }
            );
        }

        // Test comprehensive spec (includes ALL key types)
        let comprehensive = TestMaterialSpec::comprehensive(4);
        assert!(comprehensive.include_slow_material);
        for key_type in KeyType::iter() {
            assert!(
                comprehensive.requires_key_type(key_type),
                "comprehensive: {:?} should be required",
                key_type
            );
        }
    }
}
