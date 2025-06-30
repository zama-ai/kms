//! Test helpers for MetaStore Status Service tests
//!
//! This module provides common utilities and fixtures for testing the MetaStore Status Service.

use crate::grpc::metastore_status_service::MetaStoreStatusServiceImpl;
use crate::util::meta_store::MetaStore;
use kms_grpc::RequestId;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Creates a test service with all stores available and configured with standard test capacities
pub fn create_test_service() -> MetaStoreStatusServiceImpl {
    MetaStoreStatusServiceImpl {
        key_gen_store: Some(Arc::new(RwLock::new(MetaStore::new(100, 50)))),
        pub_dec_store: Some(Arc::new(RwLock::new(MetaStore::new(100, 50)))),
        user_dec_store: Some(Arc::new(RwLock::new(MetaStore::new(100, 50)))),
        crs_store: Some(Arc::new(RwLock::new(MetaStore::new(100, 50)))),
        preproc_store: Some(Arc::new(RwLock::new(MetaStore::new(100, 50)))),
    }
}

/// Creates a service with no stores available (all None) for testing unavailable store scenarios
pub fn create_unavailable_service() -> MetaStoreStatusServiceImpl {
    MetaStoreStatusServiceImpl {
        key_gen_store: None,
        pub_dec_store: None,
        user_dec_store: None,
        crs_store: None,
        preproc_store: None,
    }
}

/// Creates a service with mixed store availability for testing partial availability scenarios
pub fn create_mixed_availability_service() -> MetaStoreStatusServiceImpl {
    MetaStoreStatusServiceImpl {
        key_gen_store: Some(Arc::new(RwLock::new(MetaStore::new(100, 50)))),
        pub_dec_store: None, // Not available
        user_dec_store: Some(Arc::new(RwLock::new(MetaStore::new(200, 100)))),
        crs_store: None, // Not available
        preproc_store: Some(Arc::new(RwLock::new(MetaStore::new(300, 150)))),
    }
}

/// Test RequestId constants for consistent testing
pub mod test_request_ids {
    use super::*;

    pub const VALID_HEX_1: &str =
        "d7a8317db860599a6f0e3227d0c8f931bb18a5407adb4643230ff5c6cffb7f23";

    /// Creates a valid RequestId for testing
    pub fn valid_request_id_1() -> RequestId {
        RequestId::from_str(VALID_HEX_1).expect("Should parse valid hex")
    }
}

/// Error case constants for testing invalid inputs
pub mod test_error_cases {
    pub const EMPTY_STRING: &str = "";
    pub const TOO_SHORT: &str = "123";
    pub const INVALID_HEX: &str =
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
    pub const WRONG_LENGTH: &str =
        "d7a8317db860599a6f0e3227d0c8f931bb18a5407adb4643230ff5c6cffb7f2300"; // 65 chars
}
