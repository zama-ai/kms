//! Centralized KMS test environment setup
//!
//! This module provides a builder pattern for setting up isolated centralized KMS
//! test environments with automatic cleanup.

use crate::testing::helpers::{create_test_material_manager, fix_centralized_public_keys};
use crate::testing::material::{TestMaterialManager, TestMaterialSpec};
use crate::testing::types::ServerHandle;
use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
use crate::vault::storage::{file::FileStorage, StorageType};
use anyhow::Result;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use tempfile::TempDir;
use tonic::transport::Channel;

/// Centralized KMS test environment
///
/// Provides an isolated KMS server setup with automatic cleanup.
/// The environment is automatically cleaned up when dropped.
pub struct CentralizedTestEnv {
    /// Isolated test material directory (auto-deleted on drop)
    pub material_dir: TempDir,
    /// Running KMS server handle
    pub server: ServerHandle,
    /// gRPC client for communicating with the server
    pub client: CoreServiceEndpointClient<Channel>,
}

impl CentralizedTestEnv {
    /// Create a new builder for centralized test environment
    pub fn builder() -> CentralizedTestEnvBuilder {
        CentralizedTestEnvBuilder::default()
    }
}

/// Builder for centralized test environments
#[derive(Default)]
pub struct CentralizedTestEnvBuilder {
    test_name: Option<String>,
    material_spec: Option<TestMaterialSpec>,
    material_manager: Option<TestMaterialManager>,
    with_backup_vault: bool,
    rate_limiter_conf: Option<crate::util::rate_limiter::RateLimiterConfig>,
}

impl CentralizedTestEnvBuilder {
    /// Set the test name (used for logging and temp directory naming)
    pub fn with_test_name(mut self, name: impl Into<String>) -> Self {
        self.test_name = Some(name.into());
        self
    }

    /// Set custom material specification
    pub fn with_material_spec(mut self, spec: TestMaterialSpec) -> Self {
        self.material_spec = Some(spec);
        self
    }

    /// Set custom material manager
    pub fn with_material_manager(mut self, manager: TestMaterialManager) -> Self {
        self.material_manager = Some(manager);
        self
    }

    /// Enable backup vault
    pub fn with_backup_vault(mut self) -> Self {
        self.with_backup_vault = true;
        self
    }

    /// Set rate limiter configuration
    pub fn with_rate_limiter(mut self, conf: crate::util::rate_limiter::RateLimiterConfig) -> Self {
        self.rate_limiter_conf = Some(conf);
        self
    }

    /// Build the test environment
    pub async fn build(self) -> Result<CentralizedTestEnv> {
        let test_name = self
            .test_name
            .unwrap_or_else(|| "centralized_test".to_string());
        let manager = self
            .material_manager
            .unwrap_or_else(create_test_material_manager);
        let spec = self
            .material_spec
            .unwrap_or_else(TestMaterialSpec::centralized_basic);

        // Setup isolated material
        let material_dir = manager.setup_test_material(&spec, &test_name).await?;

        // Generate material with correct RequestIds
        ensure_testing_material_exists(Some(material_dir.path())).await;

        let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
        let mut priv_storage =
            FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;

        // Fix public key RequestIds
        fix_centralized_public_keys(&mut pub_storage, &mut priv_storage).await?;

        // Setup KMS server
        let backup_vault = if self.with_backup_vault {
            // TODO: Implement backup vault setup
            None
        } else {
            None
        };

        let (server, client) = crate::client::test_tools::setup_centralized(
            pub_storage,
            priv_storage,
            backup_vault,
            self.rate_limiter_conf,
        )
        .await;

        Ok(CentralizedTestEnv {
            material_dir,
            server,
            client,
        })
    }
}
