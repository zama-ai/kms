//! Test material management
//!
//! This module provides utilities for managing pre-generated cryptographic test material.
//! Material is generated once using `generate-test-material --profile ... --parties ...`
//! and then copied into isolated temporary directories for each test, which prevents tests
//! from interfering with each other.
//!
//! # Key Types
//!
//! - **`TestMaterialSpec`**: Declares what cryptographic material a test needs
//! - **`TestMaterialManager`**: Copies pre-generated material into isolated directories
//! - **`MaterialType`**: Testing (fast) vs Default (production-like) parameters
//! - **`KeyType`**: Types of cryptographic keys (FHE, CRS, signing, etc.)
mod manager;
mod spec;

pub use manager::TestMaterialManager;
pub use spec::{KeyType, MaterialType, TestMaterialSpec};

/// On-disk subdirectory name for a given material family.
///
/// These legacy names are kept for compatibility with existing test-material layouts and CI
/// artifacts even though the CLI now refers to them as insecure/secure profiles.
pub fn material_subdir(material_type: MaterialType) -> &'static str {
    match material_type {
        MaterialType::Testing => "testing",
        MaterialType::Default => "default",
    }
}

/// Deterministic threshold FHE key fixture ID label for a material family and party count.
pub fn threshold_key_id_name(material_type: MaterialType, party_count: usize) -> String {
    match material_type {
        MaterialType::Testing => format!("TEST_THRESHOLD_KEY_ID_{party_count}P"),
        MaterialType::Default => format!("DEFAULT_THRESHOLD_KEY_ID_{party_count}P"),
    }
}

/// Deterministic threshold CRS fixture ID label for a material family and party count.
pub fn threshold_crs_id_name(material_type: MaterialType, party_count: usize) -> String {
    match material_type {
        MaterialType::Testing => format!("TEST_THRESHOLD_CRS_ID_{party_count}P"),
        MaterialType::Default => format!("DEFAULT_THRESHOLD_CRS_ID_{party_count}P"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{
        DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_CRS_ID_13P, DEFAULT_THRESHOLD_KEY_ID_4P,
        DEFAULT_THRESHOLD_KEY_ID_13P, TEST_THRESHOLD_CRS_ID_4P, TEST_THRESHOLD_CRS_ID_13P,
        TEST_THRESHOLD_KEY_ID_4P, TEST_THRESHOLD_KEY_ID_13P,
    };
    use crate::engine::base::derive_request_id;

    #[test]
    fn threshold_id_names_match_legacy_constants() {
        let cases = [
            (
                MaterialType::Testing,
                4,
                *TEST_THRESHOLD_KEY_ID_4P,
                *TEST_THRESHOLD_CRS_ID_4P,
            ),
            (
                MaterialType::Testing,
                13,
                *TEST_THRESHOLD_KEY_ID_13P,
                *TEST_THRESHOLD_CRS_ID_13P,
            ),
            (
                MaterialType::Default,
                4,
                *DEFAULT_THRESHOLD_KEY_ID_4P,
                *DEFAULT_THRESHOLD_CRS_ID_4P,
            ),
            (
                MaterialType::Default,
                13,
                *DEFAULT_THRESHOLD_KEY_ID_13P,
                *DEFAULT_THRESHOLD_CRS_ID_13P,
            ),
        ];

        for (material_type, party_count, expected_key_id, expected_crs_id) in cases {
            let derived_key_id =
                derive_request_id(&threshold_key_id_name(material_type, party_count)).unwrap();
            let derived_crs_id =
                derive_request_id(&threshold_crs_id_name(material_type, party_count)).unwrap();

            assert_eq!(derived_key_id, expected_key_id);
            assert_eq!(derived_crs_id, expected_crs_id);
        }
    }
}
