//! Test material specification system for isolated test execution
//!
//! This module defines the specification system for test material requirements,
//! enabling tests to declare exactly what cryptographic material they need
//! without generating it during test execution.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Specification for test material requirements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestMaterialSpec {
    /// Type of material (testing vs default parameters)
    pub material_type: MaterialType,
    /// Required key types for this test
    pub required_keys: HashSet<KeyType>,
    /// Number of parties for threshold tests (None for centralized)
    pub party_count: Option<usize>,
    /// Whether to include slow test material (CRS, etc.)
    pub include_slow_material: bool,
}

/// Type of test material parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MaterialType {
    /// Testing parameters (fast, small keys)
    Testing,
    /// Default parameters (production-like, slower)
    Default,
}

/// Types of cryptographic keys and material
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Client keys for encryption/decryption
    ClientKeys,
    /// Signing keys for authentication
    SigningKeys,
    /// Server signing keys for threshold parties
    ServerSigningKeys,
    /// FHE keys (client, server, public)
    FheKeys,
    /// Common Reference String for zero-knowledge proofs
    CrsKeys,
    /// Fhe public keys
    CompactPublicKeys,
    /// Compact compressed public keys
    CompressedCompactPublicKeys,
    /// Decompression keys for compressed ciphertexts
    DecompressionKeys,
    /// PRSS setup for threshold protocols
    PrssSetup,
}

impl TestMaterialSpec {
    /// Create specification for basic centralized test
    pub fn centralized_basic() -> Self {
        let mut required_keys = HashSet::new();
        required_keys.insert(KeyType::ClientKeys);
        required_keys.insert(KeyType::SigningKeys);
        required_keys.insert(KeyType::FheKeys);

        Self {
            material_type: MaterialType::Testing,
            required_keys,
            party_count: None,
            include_slow_material: false,
        }
    }

    /// Create specification for basic threshold test
    pub fn threshold_basic(party_count: usize) -> Self {
        let mut required_keys = HashSet::new();
        required_keys.insert(KeyType::ClientKeys);
        required_keys.insert(KeyType::SigningKeys);
        required_keys.insert(KeyType::ServerSigningKeys);
        required_keys.insert(KeyType::FheKeys);
        required_keys.insert(KeyType::PrssSetup);

        Self {
            material_type: MaterialType::Testing,
            required_keys,
            party_count: Some(party_count),
            include_slow_material: false,
        }
    }

    /// Create specification for comprehensive test with all material
    pub fn comprehensive(party_count: Option<usize>) -> Self {
        let mut required_keys = HashSet::new();
        required_keys.insert(KeyType::ClientKeys);
        required_keys.insert(KeyType::SigningKeys);
        required_keys.insert(KeyType::FheKeys);
        required_keys.insert(KeyType::CrsKeys);
        required_keys.insert(KeyType::CompactPublicKeys);
        required_keys.insert(KeyType::DecompressionKeys);

        if party_count.is_some() {
            required_keys.insert(KeyType::ServerSigningKeys);
            required_keys.insert(KeyType::PrssSetup);
        }

        Self {
            material_type: MaterialType::Testing,
            required_keys,
            party_count,
            include_slow_material: true,
        }
    }

    /// Create specification for centralized test with Default parameters
    ///
    /// Uses production-like key sizes (MaterialType::Default).
    /// **Requires:** Pre-generated default material via `make generate-test-material-all`
    pub fn centralized_default() -> Self {
        let mut spec = Self::centralized_basic();
        spec.material_type = MaterialType::Default;
        spec
    }

    /// Create specification for threshold test with Default parameters
    ///
    /// Uses production-like key sizes (MaterialType::Default).
    /// **Requires:** Pre-generated default material via `make generate-test-material-all`
    pub fn threshold_default(party_count: usize) -> Self {
        let mut spec = Self::threshold_basic(party_count);
        spec.material_type = MaterialType::Default;
        spec
    }

    /// Create specification for production-like testing
    ///
    /// **Deprecated:** Use `centralized_default()` or `threshold_default()` instead.
    pub fn production_like(party_count: Option<usize>) -> Self {
        let mut spec = if let Some(count) = party_count {
            Self::threshold_basic(count)
        } else {
            Self::centralized_basic()
        };

        spec.material_type = MaterialType::Default;
        spec.include_slow_material = true;
        spec
    }

    /// Check if this specification requires threshold setup
    pub fn is_threshold(&self) -> bool {
        self.party_count.is_some()
    }

    /// Get the party count, defaulting to 1 for centralized
    pub fn party_count(&self) -> usize {
        self.party_count.unwrap_or(1)
    }

    /// Check if a specific key type is required
    pub fn requires_key_type(&self, key_type: KeyType) -> bool {
        self.required_keys.contains(&key_type)
    }
}

impl Default for TestMaterialSpec {
    fn default() -> Self {
        Self::centralized_basic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_grpc::rpc_types::{PrivDataType, PubDataType};
    use strum::IntoEnumIterator;

    /// Maps a PrivDataType to its corresponding KeyType(s).
    /// This function must be exhaustive - the compiler will error if new variants are added.
    fn priv_data_type_to_key_types(pdt: PrivDataType) -> Vec<KeyType> {
        match pdt {
            PrivDataType::SigningKey => vec![KeyType::SigningKeys, KeyType::ServerSigningKeys],
            PrivDataType::FheKeyInfo => vec![KeyType::FheKeys], // Threshold FHE key info
            PrivDataType::CrsInfo => vec![KeyType::CrsKeys],
            PrivDataType::FhePrivateKey => vec![KeyType::FheKeys], // Centralized FHE private key
            #[expect(deprecated)]
            PrivDataType::PrssSetup => vec![KeyType::PrssSetup],
            PrivDataType::PrssSetupCombined => vec![KeyType::PrssSetup],
            PrivDataType::ContextInfo => vec![KeyType::PrssSetup], // MPC context stored with PRSS
        }
    }

    /// Maps a PubDataType to its corresponding KeyType(s).
    /// This function must be exhaustive - the compiler will error if new variants are added.
    fn pub_data_type_to_key_types(pdt: PubDataType) -> Vec<KeyType> {
        match pdt {
            PubDataType::ServerKey => vec![KeyType::FheKeys],
            PubDataType::PublicKey => vec![KeyType::CompactPublicKeys],
            PubDataType::PublicKeyMetadata => vec![KeyType::CompactPublicKeys],
            PubDataType::CRS => vec![KeyType::CrsKeys],
            PubDataType::VerfKey => vec![KeyType::SigningKeys],
            PubDataType::VerfAddress => vec![KeyType::SigningKeys],
            PubDataType::DecompressionKey => vec![KeyType::DecompressionKeys],
            PubDataType::CACert => vec![KeyType::ServerSigningKeys], // TLS certs for MPC nodes
            PubDataType::RecoveryMaterial => vec![KeyType::ClientKeys], // Backup recovery
            PubDataType::CompressedServerKey => vec![KeyType::FheKeys], // Compressed server key
            PubDataType::CompressedCompactPublicKey => vec![KeyType::CompactPublicKeys], // Compressed public key
        }
    }

    /// Ensures KeyType covers all PrivDataType variants.
    /// If a new PrivDataType is added, the exhaustive match in priv_data_type_to_key_types
    /// will cause a compile error, forcing an update to both the mapping and KeyType if needed.
    #[test]
    fn test_key_type_covers_all_priv_data_types() {
        for pdt in PrivDataType::iter() {
            let key_types = priv_data_type_to_key_types(pdt);
            assert!(
                !key_types.is_empty(),
                "PrivDataType::{:?} must map to at least one KeyType",
                pdt
            );
        }
    }

    /// Ensures KeyType covers all PubDataType variants.
    /// If a new PubDataType is added, the exhaustive match in pub_data_type_to_key_types
    /// will cause a compile error, forcing an update to both the mapping and KeyType if needed.
    #[test]
    fn test_key_type_covers_all_pub_data_types() {
        for pdt in PubDataType::iter() {
            let key_types = pub_data_type_to_key_types(pdt);
            assert!(
                !key_types.is_empty(),
                "PubDataType::{:?} must map to at least one KeyType",
                pdt
            );
        }
    }

    #[test]
    fn test_centralized_basic_spec() {
        let spec = TestMaterialSpec::centralized_basic();

        assert_eq!(spec.material_type, MaterialType::Testing);
        assert!(!spec.is_threshold());
        assert_eq!(spec.party_count(), 1);
        assert!(spec.requires_key_type(KeyType::ClientKeys));
        assert!(spec.requires_key_type(KeyType::SigningKeys));
        assert!(spec.requires_key_type(KeyType::FheKeys));
        assert!(!spec.requires_key_type(KeyType::PrssSetup));
    }

    #[test]
    fn test_threshold_basic_spec() {
        let spec = TestMaterialSpec::threshold_basic(4);

        assert_eq!(spec.material_type, MaterialType::Testing);
        assert!(spec.is_threshold());
        assert_eq!(spec.party_count(), 4);
        assert!(spec.requires_key_type(KeyType::ClientKeys));
        assert!(spec.requires_key_type(KeyType::ServerSigningKeys));
        assert!(spec.requires_key_type(KeyType::PrssSetup));
    }

    #[test]
    fn test_comprehensive_spec() {
        let spec = TestMaterialSpec::comprehensive(Some(4));

        assert!(spec.include_slow_material);
        assert!(spec.requires_key_type(KeyType::CrsKeys));
        assert!(spec.requires_key_type(KeyType::DecompressionKeys));
    }

    #[test]
    fn test_serialization() {
        let spec = TestMaterialSpec::threshold_basic(4);
        let serialized = serde_json::to_string(&spec).unwrap();
        let deserialized: TestMaterialSpec = serde_json::from_str(&serialized).unwrap();

        assert_eq!(spec, deserialized);
    }
}
