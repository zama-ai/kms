//! Centralized KMS test environment setup
//!
//! This module provides a builder pattern for setting up isolated centralized KMS
//! test environments with automatic cleanup.
use crate::consts::SIGNING_KEY_ID;
use crate::testing::helpers::{create_test_material_manager, regenerate_central_keys};
use crate::testing::material::{MaterialType, TestMaterialManager, TestMaterialSpec};
use crate::testing::types::ServerHandle;
use crate::util::key_setup::ensure_client_keys_exist;
use crate::vault::storage::{StorageType, file::FileStorage};
use anyhow::Result;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
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

/// Lifetime guard returned by [`CentralizedTestEnv::into_parts`].
///
/// Owns the tempdir handle. Must be held until the test body finishes — dropping it deletes the
/// tempdir the server reads from.
pub struct CentralizedTestMaterialGuard {
    _material_dir: TempDir,
}

impl CentralizedTestEnv {
    /// Create a new builder for centralized test environment
    pub fn builder() -> CentralizedTestEnvBuilder {
        CentralizedTestEnvBuilder::default()
    }

    /// Build an internal client backed by this env's isolated storage.
    ///
    /// Mirrors the threshold side's [`crate::testing::setup::ThresholdTestEnv::create_internal_client`].
    pub async fn create_internal_client(
        &self,
        params: &threshold_execution::tfhe_internals::parameters::DKGParams,
    ) -> Result<crate::client::client_wasm::Client> {
        let material_path = self.material_dir.path();
        let pub_storage = FileStorage::new(Some(material_path), StorageType::PUB, None)?;
        let client_storage = FileStorage::new(Some(material_path), StorageType::CLIENT, None)?;
        crate::client::client_wasm::Client::new_client(
            client_storage,
            HashMap::from([(1u32, pub_storage)]),
            params,
            None,
        )
        .await
    }

    /// Destructure the env into parts.
    ///
    /// Returns `(server, client, material_path, guard)`. The guard owns the tempdir and must
    /// outlive the running server.
    pub fn into_parts(
        self,
    ) -> (
        ServerHandle,
        CoreServiceEndpointClient<Channel>,
        std::path::PathBuf,
        CentralizedTestMaterialGuard,
    ) {
        let material_path = self.material_dir.path().to_path_buf();
        let guard = CentralizedTestMaterialGuard {
            _material_dir: self.material_dir,
        };
        (self.server, self.client, material_path, guard)
    }
}

/// Builder for centralized test environments
#[derive(Default)]
pub struct CentralizedTestEnvBuilder {
    test_name: Option<String>,
    material_spec: Option<TestMaterialSpec>,
    material_manager: Option<TestMaterialManager>,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
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

    /// Enable custodian keychain (requires backup vault)
    pub fn with_custodian_keychain(mut self) -> Self {
        self.with_backup_vault = true; // Custodian requires backup vault
        self.with_custodian_keychain = true;
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
        let material_dir = manager.setup_test_material_temp(&spec, &test_name).await?;

        let mut pub_storage = FileStorage::new(Some(material_dir.path()), StorageType::PUB, None)?;
        let mut priv_storage =
            FileStorage::new(Some(material_dir.path()), StorageType::PRIV, None)?;

        // For `Testing` material we (re)generate centralized keys to guarantee freshness;
        // for `Default` we trust the pre-generated `test-material/default/` fixture as-is.
        // TODO(dp): runs even when the just-copied fixture is already valid.
        // Could be skipped if `regenerate_central_keys`'s outputs are already
        // present in the dest tempdir.
        if spec.material_type == MaterialType::Testing {
            regenerate_central_keys(&mut pub_storage, &mut priv_storage).await?;
        }

        // Ensure client signing/verification keys exist
        ensure_client_keys_exist(Some(material_dir.path()), &SIGNING_KEY_ID, true).await;

        // Setup KMS server with optional backup vault
        let backup_vault = if self.with_backup_vault {
            use crate::conf::{Keychain, SecretSharingKeychain};
            use crate::vault::Vault;
            use crate::vault::keychain::make_keychain_proxy;
            use std::fs;

            // Create BACKUP directory
            let backup_dir = material_dir.path().join("BACKUP");
            fs::create_dir_all(&backup_dir)?;

            let backup_proxy = crate::vault::storage::StorageProxy::from(FileStorage::new(
                Some(material_dir.path()),
                StorageType::BACKUP,
                None,
            )?);

            let keychain = if self.with_custodian_keychain {
                let pub_proxy = crate::vault::storage::StorageProxy::from(FileStorage::new(
                    Some(material_dir.path()),
                    StorageType::PUB,
                    None,
                )?);
                Some(
                    make_keychain_proxy(
                        &Keychain::SecretSharing(SecretSharingKeychain {}),
                        None,
                        None,
                        Some(&pub_proxy),
                        false,
                    )
                    .await?,
                )
            } else {
                None
            };

            Some(Vault {
                storage: backup_proxy,
                keychain,
            })
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
