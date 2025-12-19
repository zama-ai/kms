//! Threshold KMS test environment setup
//!
//! This module provides a builder pattern for setting up isolated threshold KMS
//! test environments with automatic cleanup.

use crate::consts::{
    BACKUP_STORAGE_PREFIX_THRESHOLD_ALL, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
    PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
};
use crate::testing::helpers::create_test_material_manager;
use crate::testing::material::{TestMaterialHandle, TestMaterialManager, TestMaterialSpec};
use crate::testing::types::ServerHandle;
pub use crate::testing::types::ThresholdTestConfig;
use crate::vault::storage::{file::FileStorage, StorageType};
use anyhow::Result;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::collections::HashMap;
use tonic::transport::Channel;

/// Threshold KMS test environment
///
/// Provides an isolated multi-party KMS setup with automatic cleanup.
/// The environment is automatically cleaned up when dropped (for isolated mode)
/// or kept intact (for shared mode when KMS_TEST_SHARED_MATERIAL=1).
pub struct ThresholdTestEnv {
    /// Test material directory handle (isolated or shared)
    pub material_dir: TestMaterialHandle,
    /// Running KMS server handles (keyed by party ID)
    pub servers: HashMap<u32, ServerHandle>,
    /// gRPC clients for communicating with servers (keyed by party ID)
    pub clients: HashMap<u32, CoreServiceEndpointClient<Channel>>,
}

impl ThresholdTestEnv {
    /// Create a new builder for threshold test environment
    pub fn builder() -> ThresholdTestEnvBuilder {
        ThresholdTestEnvBuilder::default()
    }

    /// Iterate over all clients (more readable than `.clients.values()`)
    pub fn all_clients(&self) -> impl Iterator<Item = &CoreServiceEndpointClient<Channel>> {
        self.clients.values()
    }

    /// Iterate over all servers (more readable than `.servers.values()`)
    pub fn all_servers(&self) -> impl Iterator<Item = &ServerHandle> {
        self.servers.values()
    }

    /// Iterate over all servers with their party IDs
    pub fn all_servers_with_id(&self) -> impl Iterator<Item = (u32, &ServerHandle)> {
        self.servers.iter().map(|(id, server)| (*id, server))
    }

    /// Consume and iterate over all servers (for shutdown)
    pub fn into_servers(self) -> impl Iterator<Item = ServerHandle> {
        self.servers.into_values()
    }

    /// Consume and iterate over all servers with their party IDs (for shutdown)
    pub fn into_servers_with_id(self) -> impl Iterator<Item = (u32, ServerHandle)> {
        self.servers.into_iter()
    }

    /// Get client for a specific party ID
    pub fn client(&self, party_id: u32) -> Option<&CoreServiceEndpointClient<Channel>> {
        self.clients.get(&party_id)
    }

    /// Get server for a specific party ID
    pub fn server(&self, party_id: u32) -> Option<&ServerHandle> {
        self.servers.get(&party_id)
    }

    /// Get all clients except the specified party (useful for crash simulation)
    /// Returns a HashMap for compatibility with existing code
    pub fn clients_except(
        &self,
        excluded_party: u32,
    ) -> HashMap<u32, CoreServiceEndpointClient<Channel>> {
        self.clients
            .iter()
            .filter(|(party_id, _)| **party_id != excluded_party)
            .map(|(party_id, client)| (*party_id, client.clone()))
            .collect()
    }

    /// Iterate over all clients except the specified party (more convenient for loops)
    pub fn all_clients_except(
        &self,
        excluded_party: u32,
    ) -> impl Iterator<Item = CoreServiceEndpointClient<Channel>> + '_ {
        self.clients
            .iter()
            .filter(move |(party_id, _)| **party_id != excluded_party)
            .map(|(_, client)| client.clone())
    }

    /// Get all clients except the specified parties (useful for multi-party crash simulation)
    pub fn clients_except_parties(
        &self,
        excluded_parties: &[u32],
    ) -> HashMap<u32, CoreServiceEndpointClient<Channel>> {
        self.clients
            .iter()
            .filter(|(party_id, _)| !excluded_parties.contains(party_id))
            .map(|(party_id, client)| (*party_id, client.clone()))
            .collect()
    }
}

/// Builder for threshold test environments
pub struct ThresholdTestEnvBuilder {
    test_name: Option<String>,
    party_count: usize,
    threshold: Option<u8>,
    material_spec: Option<TestMaterialSpec>,
    material_manager: Option<TestMaterialManager>,
    run_prss: bool,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    rate_limiter_conf: Option<crate::util::rate_limiter::RateLimiterConfig>,
    decryption_mode: Option<threshold_fhe::execution::endpoints::decryption::DecryptionMode>,
}

impl Default for ThresholdTestEnvBuilder {
    fn default() -> Self {
        Self {
            test_name: None,
            party_count: 4,
            threshold: None,
            material_spec: None,
            material_manager: None,
            run_prss: false,
            with_backup_vault: false,
            with_custodian_keychain: false,
            rate_limiter_conf: None,
            decryption_mode: None,
        }
    }
}

impl ThresholdTestEnvBuilder {
    /// Set the test name (used for logging and temp directory naming)
    pub fn with_test_name(mut self, name: impl Into<String>) -> Self {
        self.test_name = Some(name.into());
        self
    }

    /// Set the number of parties (default: 4)
    pub fn with_party_count(mut self, count: usize) -> Self {
        self.party_count = count;
        self
    }

    /// Set the threshold value (default: computed as (party_count - 1) / 3)
    pub fn with_threshold(mut self, threshold: u8) -> Self {
        self.threshold = Some(threshold);
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

    /// Enable PRSS initialization (required for secure key generation)
    pub fn with_prss(mut self) -> Self {
        self.run_prss = true;
        self
    }

    /// Enable backup vault for all parties
    pub fn with_backup_vault(mut self) -> Self {
        self.with_backup_vault = true;
        self
    }

    /// Enable custodian keychain for all parties (requires backup vault)
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

    /// Set decryption mode
    pub fn with_decryption_mode(
        mut self,
        mode: threshold_fhe::execution::endpoints::decryption::DecryptionMode,
    ) -> Self {
        self.decryption_mode = Some(mode);
        self
    }

    /// Build the test environment
    pub async fn build(self) -> Result<ThresholdTestEnv> {
        let test_name = self
            .test_name
            .unwrap_or_else(|| "threshold_test".to_string());
        let manager = self
            .material_manager
            .unwrap_or_else(create_test_material_manager);
        let spec = self
            .material_spec
            .unwrap_or_else(|| TestMaterialSpec::threshold_basic(self.party_count));

        // Setup material (isolated or shared based on KMS_TEST_SHARED_MATERIAL env var)
        let material_dir = manager.setup_test_material_auto(&spec, &test_name).await?;

        // Create storage for each party
        let mut pub_storages = Vec::new();
        let mut priv_storages = Vec::new();
        let pub_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..self.party_count];
        let priv_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..self.party_count];
        for (pub_prefix, priv_prefix) in pub_prefixes.iter().zip(priv_prefixes) {
            pub_storages.push(FileStorage::new(
                Some(material_dir.path()),
                StorageType::PUB,
                pub_prefix.as_deref(),
            )?);
            priv_storages.push(FileStorage::new(
                Some(material_dir.path()),
                StorageType::PRIV,
                priv_prefix.as_deref(),
            )?);
        }

        // Create backup vaults for each party if requested
        let vaults: Vec<Option<crate::vault::Vault>> = if self.with_backup_vault {
            use crate::conf::{Keychain, SecretSharingKeychain};
            use crate::vault::keychain::make_keychain_proxy;
            use crate::vault::Vault;
            use std::fs;

            let mut vaults = Vec::new();
            let backup_prefixes = &BACKUP_STORAGE_PREFIX_THRESHOLD_ALL[0..self.party_count];
            for (backup_prefix, pub_prefix) in backup_prefixes.iter().zip(pub_prefixes) {
                // Create BACKUP directory for this party
                let backup_dir = material_dir.path().join(backup_prefix.as_deref().unwrap());
                fs::create_dir_all(&backup_dir)?;

                let backup_proxy = crate::vault::storage::StorageProxy::from(FileStorage::new(
                    Some(material_dir.path()),
                    StorageType::BACKUP,
                    backup_prefix.as_deref(),
                )?);

                let keychain = if self.with_custodian_keychain {
                    let pub_proxy = crate::vault::storage::StorageProxy::from(FileStorage::new(
                        Some(material_dir.path()),
                        StorageType::PUB,
                        pub_prefix.as_deref(),
                    )?);
                    Some(
                        make_keychain_proxy(
                            &Keychain::SecretSharing(SecretSharingKeychain {}),
                            None,
                            None,
                            Some(&pub_proxy),
                        )
                        .await?,
                    )
                } else {
                    None
                };

                vaults.push(Some(Vault {
                    storage: backup_proxy,
                    keychain,
                }));
            }
            vaults
        } else {
            (0..self.party_count).map(|_| None).collect()
        };

        // Compute threshold if not provided
        let threshold = self
            .threshold
            .unwrap_or_else(|| ((self.party_count - 1) / 3).max(1) as u8);

        // Setup threshold KMS
        let config = ThresholdTestConfig {
            run_prss: self.run_prss,
            rate_limiter_conf: self.rate_limiter_conf,
            decryption_mode: self.decryption_mode,
            test_material_path: Some(material_dir.path()),
        };

        let (servers, clients) = crate::client::test_tools::setup_threshold_isolated(
            threshold,
            pub_storages,
            priv_storages,
            vaults,
            config,
        )
        .await;

        Ok(ThresholdTestEnv {
            material_dir,
            servers,
            clients,
        })
    }
}
