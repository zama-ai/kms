use crate::error::{Error, Result};
use alloy::primitives::Address;
use bip39::Mnemonic;
use config::{Config as ConfigBuilder, Environment, File, FileFormat};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr, time::Duration};
use tracing::{info, warn};

/// Configuration for the KMS connector
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Gateway L2 RPC endpoint
    pub gwl2_url: String,
    /// KMS Core endpoint
    pub kms_core_endpoint: String,
    /// Mnemonic phrase for the wallet
    pub mnemonic: String,
    /// Chain ID
    pub chain_id: u64,
    /// Decryption manager contract address
    pub decryption_manager_address: String,
    /// HTTPZ contract address
    pub httpz_address: String,
    /// Channel size for event processing
    pub channel_size: Option<usize>,
    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Timeout for decryption requests in seconds (default: 300s / 5min)
    #[serde(default = "default_decryption_timeout")]
    pub decryption_timeout_secs: u64,
    /// Timeout for reencryption requests in seconds (default: 300s / 5min)
    #[serde(default = "default_reencryption_timeout")]
    pub reencryption_timeout_secs: u64,
    /// Retry interval in seconds (default: 5s)
    #[serde(default = "default_retry_interval")]
    pub retry_interval_secs: u64,
    /// Account index for wallet derivation (optional)
    pub account_index: Option<u32>,
    /// EIP-712 domain name for IDecryptionManager contract
    #[serde(default = "default_decryption_manager_domain_name")]
    pub decryption_manager_domain_name: String,
    /// EIP-712 domain version for IDecryptionManager contract
    #[serde(default = "default_decryption_manager_domain_version")]
    pub decryption_manager_domain_version: String,
    /// EIP-712 domain name for IHTTPZ contract
    #[serde(default = "default_httpz_domain_name")]
    pub httpz_domain_name: String,
    /// EIP-712 domain version for IHTTPZ contract
    #[serde(default = "default_httpz_domain_version")]
    pub httpz_domain_version: String,
}

fn default_service_name() -> String {
    "kms-connector".to_string()
}

fn default_decryption_timeout() -> u64 {
    300 // 5 minutes
}

fn default_reencryption_timeout() -> u64 {
    300 // 5 minutes
}

fn default_retry_interval() -> u64 {
    5 // 5 seconds
}

fn default_decryption_manager_domain_name() -> String {
    "IDecryptionManager".to_string()
}

fn default_decryption_manager_domain_version() -> String {
    "1".to_string()
}

fn default_httpz_domain_name() -> String {
    "IHTTPZ".to_string()
}

fn default_httpz_domain_version() -> String {
    "1".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://[::1]:50052".to_string(),
            // Use a valid mnemonic with correct checksum
            mnemonic: "test test test test test test test test test test test junk".to_string(),
            chain_id: 31337,
            decryption_manager_address: "0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string(),
            httpz_address: "0x0000000000000000000000000000000000000001".to_string(),
            channel_size: Some(1000),
            service_name: default_service_name(),
            decryption_timeout_secs: default_decryption_timeout(),
            reencryption_timeout_secs: default_reencryption_timeout(),
            retry_interval_secs: default_retry_interval(),
            account_index: None,
            decryption_manager_domain_name: default_decryption_manager_domain_name(),
            decryption_manager_domain_version: default_decryption_manager_domain_version(),
            httpz_domain_name: default_httpz_domain_name(),
            httpz_domain_version: default_httpz_domain_version(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        info!("Loading configuration from: {}", path.as_ref().display());

        let content = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config file: {}", e)))?;

        // Validate and log configuration
        info!("Configuration loaded successfully:");
        info!("  Service Name: {}", config.service_name);
        info!("  KMS Core Endpoint: {}", config.kms_core_endpoint);
        info!("  Gateway L2 URL: {}", config.gwl2_url);
        info!("  Chain ID: {}", config.chain_id);
        info!(
            "  Decryption Manager: {}",
            config.decryption_manager_address
        );
        info!("  HTTPZ Address: {}", config.httpz_address);
        if let Some(size) = config.channel_size {
            info!("  Channel Size: {}", size);
        } else {
            warn!("  Channel Size: not specified, using default");
        }
        info!("  Decryption Timeout: {}s", config.decryption_timeout_secs);
        info!(
            "  Reencryption Timeout: {}s",
            config.reencryption_timeout_secs
        );
        info!("  Retry Interval: {}s", config.retry_interval_secs);

        // Validate mnemonic
        Mnemonic::parse_normalized(&config.mnemonic)
            .map_err(|e| Error::Config(format!("Invalid mnemonic: {}", e)))?;
        info!("  Mnemonic: validated successfully");

        // Validate addresses
        if !config.decryption_manager_address.starts_with("0x") {
            return Err(Error::Config(
                "DecryptionManager address must start with 0x".into(),
            ));
        }
        Address::from_str(&config.decryption_manager_address)
            .map_err(|e| Error::Config(format!("Invalid DecryptionManager address: {}", e)))?;

        if !config.httpz_address.starts_with("0x") {
            return Err(Error::Config("HTTPZ address must start with 0x".into()));
        }
        Address::from_str(&config.httpz_address)
            .map_err(|e| Error::Config(format!("Invalid HTTPZ address: {}", e)))?;

        Ok(config)
    }

    /// Load configuration from environment variables and optionally from a TOML file
    /// Environment variables take precedence over file configuration
    /// Environment variables are prefixed with KMS_CONNECTOR_
    pub fn from_env_and_file<P: AsRef<Path>>(path: Option<P>) -> Result<Self> {
        let mut builder = ConfigBuilder::builder();

        // Start with default values
        let default_config = Self::default();
        builder = builder.add_source(config::File::from_str(
            &toml::to_string(&default_config)
                .map_err(|e| Error::Config(format!("Failed to serialize default config: {}", e)))?,
            config::FileFormat::Toml,
        ));

        // If path is provided, add it as a config source
        if let Some(path) = path {
            info!(
                "Loading configuration from file: {}",
                path.as_ref().display()
            );
            builder = builder.add_source(
                File::with_name(path.as_ref().to_str().unwrap()).format(FileFormat::Toml),
            );
        }

        // Add environment variables last so they take precedence
        info!("Adding environment variables with prefix KMS_CONNECTOR_");
        builder = builder.add_source(Environment::with_prefix("KMS_CONNECTOR"));

        let settings = builder
            .build()
            .map_err(|e| Error::Config(format!("Failed to build config: {}", e)))?;

        let config: Self = settings
            .try_deserialize()
            .map_err(|e| Error::Config(format!("Failed to deserialize config: {}", e)))?;

        // Log configuration
        info!("Configuration loaded successfully:");
        info!("  Service Name: {}", config.service_name);
        info!("  Gateway L2 URL: {}", config.gwl2_url);
        info!("  KMS Core Endpoint: {}", config.kms_core_endpoint);
        info!("  Chain ID: {}", config.chain_id);
        info!(
            "  DecryptionManager Address: {}",
            config.decryption_manager_address
        );
        info!("  HTTPZ Address: {}", config.httpz_address);
        if let Some(size) = config.channel_size {
            info!("  Channel Size: {}", size);
        } else {
            info!("  Channel Size: default");
        }
        info!("  Decryption Timeout: {}s", config.decryption_timeout_secs);
        info!(
            "  Reencryption Timeout: {}s",
            config.reencryption_timeout_secs
        );
        info!("  Retry Interval: {}s", config.retry_interval_secs);

        // Validate the configuration using existing validation logic
        if !config.decryption_manager_address.starts_with("0x") {
            return Err(Error::Config(
                "DecryptionManager address must start with 0x".into(),
            ));
        }
        Address::from_str(&config.decryption_manager_address)
            .map_err(|e| Error::Config(format!("Invalid DecryptionManager address: {}", e)))?;

        if !config.httpz_address.starts_with("0x") {
            return Err(Error::Config("HTTPZ address must start with 0x".into()));
        }
        Address::from_str(&config.httpz_address)
            .map_err(|e| Error::Config(format!("Invalid HTTPZ address: {}", e)))?;

        // Validate mnemonic
        info!("Validating mnemonic...");
        Mnemonic::parse_normalized(&config.mnemonic)
            .map_err(|e| Error::Config(format!("Invalid mnemonic: {}", e)))?;
        info!("Mnemonic validated successfully");

        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {}", e)))?;

        fs::write(path, content)
            .map_err(|e| Error::Config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Get DecryptionManager address as Address type
    pub fn get_decryption_manager_address(&self) -> Result<Address> {
        Address::from_str(&self.decryption_manager_address)
            .map_err(|e| Error::Config(format!("Invalid DecryptionManager address: {}", e)))
    }

    /// Get HTTPZ address as Address type
    pub fn get_httpz_address(&self) -> Result<Address> {
        Address::from_str(&self.httpz_address)
            .map_err(|e| Error::Config(format!("Invalid HTTPZ address: {}", e)))
    }

    /// Get decryption timeout as Duration
    pub fn decryption_timeout(&self) -> Duration {
        Duration::from_secs(self.decryption_timeout_secs)
    }

    /// Get reencryption timeout as Duration
    pub fn reencryption_timeout(&self) -> Duration {
        Duration::from_secs(self.reencryption_timeout_secs)
    }

    /// Get retry interval as Duration
    pub fn retry_interval(&self) -> Duration {
        Duration::from_secs(self.retry_interval_secs)
    }

    /// Get the account index for wallet derivation
    /// If explicitly set in config, use that value
    /// Otherwise, extract it from the service name (e.g., "kms-connector-2" -> 2)
    pub fn get_account_index(&self) -> u32 {
        if let Some(index) = self.account_index {
            return index;
        }

        // Try to extract index from service name (e.g., "kms-connector-2" -> 2)
        let parts: Vec<&str> = self.service_name.split('-').collect();
        if parts.len() >= 2 {
            // Try to get the last part and parse it as a number
            if let Some(last) = parts.last() {
                if let Ok(index) = last.parse::<u32>() {
                    return index;
                }
            }
        }

        // Default to 0 if service name doesn't contain a number
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;
    use tempfile::NamedTempFile;

    fn get_test_mnemonic() -> String {
        // Use a valid test mnemonic with correct checksum
        "test test test test test test test test test test test junk".to_string()
    }

    fn cleanup_env_vars() {
        env::remove_var("KMS_CONNECTOR_GWL2_URL");
        env::remove_var("KMS_CONNECTOR_KMS_CORE_ENDPOINT");
        env::remove_var("KMS_CONNECTOR_MNEMONIC");
        env::remove_var("KMS_CONNECTOR_CHAIN_ID");
        env::remove_var("KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS");
        env::remove_var("KMS_CONNECTOR_HTTPZ_ADDRESS");
        env::remove_var("KMS_CONNECTOR_CHANNEL_SIZE");
        env::remove_var("KMS_CONNECTOR_SERVICE_NAME");
        env::remove_var("KMS_CONNECTOR_DECRYPTION_TIMEOUT_SECS");
        env::remove_var("KMS_CONNECTOR_REENCRYPTION_TIMEOUT_SECS");
        env::remove_var("KMS_CONNECTOR_RETRY_INTERVAL_SECS");
    }

    #[test]
    #[serial]
    fn test_load_valid_config() {
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: get_test_mnemonic(),
            chain_id: 1,
            decryption_manager_address: "0x0000000000000000000000000000000000000000".to_string(),
            httpz_address: "0x0000000000000000000000000000000000000000".to_string(),
            channel_size: Some(100),
            service_name: "kms-connector".to_string(),
            decryption_timeout_secs: 300,
            reencryption_timeout_secs: 300,
            retry_interval_secs: 5,
            account_index: None,
            decryption_manager_domain_name: "IDecryptionManager".to_string(),
            decryption_manager_domain_version: "1".to_string(),
            httpz_domain_name: "IHTTPZ".to_string(),
            httpz_domain_version: "1".to_string(),
        };

        let temp_file = NamedTempFile::new().unwrap();
        config.to_file(temp_file.path()).unwrap();

        let loaded_config = Config::from_file(temp_file.path()).unwrap();

        // Compare fields
        assert_eq!(config.gwl2_url, loaded_config.gwl2_url);
        assert_eq!(config.kms_core_endpoint, loaded_config.kms_core_endpoint);
        assert_eq!(config.mnemonic, loaded_config.mnemonic);
        assert_eq!(config.chain_id, loaded_config.chain_id);
        assert_eq!(
            config.decryption_manager_address,
            loaded_config.decryption_manager_address
        );
        assert_eq!(config.httpz_address, loaded_config.httpz_address);
        assert_eq!(config.channel_size, loaded_config.channel_size);
        assert_eq!(config.kms_core_endpoint, loaded_config.kms_core_endpoint);
        assert_eq!(config.service_name, loaded_config.service_name);
        assert_eq!(
            config.decryption_timeout_secs,
            loaded_config.decryption_timeout_secs
        );
        assert_eq!(
            config.reencryption_timeout_secs,
            loaded_config.reencryption_timeout_secs
        );
        assert_eq!(
            config.retry_interval_secs,
            loaded_config.retry_interval_secs
        );
        assert_eq!(
            config.decryption_manager_domain_name,
            loaded_config.decryption_manager_domain_name
        );
        assert_eq!(
            config.decryption_manager_domain_version,
            loaded_config.decryption_manager_domain_version
        );
        assert_eq!(config.httpz_domain_name, loaded_config.httpz_domain_name);
        assert_eq!(
            config.httpz_domain_version,
            loaded_config.httpz_domain_version
        );
    }

    #[test]
    #[serial]
    fn test_save_config() {
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: get_test_mnemonic(),
            chain_id: 1,
            decryption_manager_address: "0x0000000000000000000000000000000000000000".to_string(),
            httpz_address: "0x0000000000000000000000000000000000000000".to_string(),
            channel_size: None,
            service_name: "kms-connector".to_string(),
            decryption_timeout_secs: 300,
            reencryption_timeout_secs: 300,
            retry_interval_secs: 5,
            account_index: None,
            decryption_manager_domain_name: "IDecryptionManager".to_string(),
            decryption_manager_domain_version: "1".to_string(),
            httpz_domain_name: "IHTTPZ".to_string(),
            httpz_domain_version: "1".to_string(),
        };

        config.to_file("test_config.toml").unwrap();
        let loaded_config = Config::from_file("test_config.toml").unwrap();
        assert_eq!(config.gwl2_url, loaded_config.gwl2_url);

        fs::remove_file("test_config.toml").unwrap();
    }

    #[test]
    #[serial]
    fn test_invalid_address() {
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: get_test_mnemonic(),
            chain_id: 1,
            decryption_manager_address: "0x0000".to_string(),
            httpz_address: "0x000010".to_string(),
            channel_size: None,
            service_name: "kms-connector".to_string(),
            decryption_timeout_secs: 300,
            reencryption_timeout_secs: 300,
            retry_interval_secs: 5,
            account_index: None,
            decryption_manager_domain_name: "IDecryptionManager".to_string(),
            decryption_manager_domain_version: "1".to_string(),
            httpz_domain_name: "IHTTPZ".to_string(),
            httpz_domain_version: "1".to_string(),
        };

        let temp_file = NamedTempFile::new().unwrap();
        config.to_file(temp_file.path()).unwrap();

        assert!(Config::from_file(temp_file.path()).is_err());
    }

    #[test]
    #[serial]
    fn test_load_from_env() {
        cleanup_env_vars();

        // Set environment variables
        env::set_var("KMS_CONNECTOR_GWL2_URL", "ws://localhost:9545");
        env::set_var("KMS_CONNECTOR_KMS_CORE_ENDPOINT", "http://localhost:50053");
        env::set_var("KMS_CONNECTOR_MNEMONIC", get_test_mnemonic());
        env::set_var("KMS_CONNECTOR_CHAIN_ID", "31888");
        env::set_var(
            "KMS_CONNECTOR_DECRYPTION_MANAGER_ADDRESS",
            "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        );
        env::set_var(
            "KMS_CONNECTOR_HTTPZ_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        env::set_var("KMS_CONNECTOR_CHANNEL_SIZE", "2000");
        env::set_var("KMS_CONNECTOR_SERVICE_NAME", "kms-connector-test");
        env::set_var("KMS_CONNECTOR_DECRYPTION_TIMEOUT_SECS", "600");
        env::set_var("KMS_CONNECTOR_REENCRYPTION_TIMEOUT_SECS", "600");
        env::set_var("KMS_CONNECTOR_RETRY_INTERVAL_SECS", "10");

        // Load config from environment
        let config = Config::from_env_and_file::<&str>(None).unwrap();

        // Verify values
        assert_eq!(config.gwl2_url, "ws://localhost:9545");
        assert_eq!(config.kms_core_endpoint, "http://localhost:50053");
        assert_eq!(config.mnemonic, get_test_mnemonic());
        assert_eq!(config.chain_id, 31888);
        assert_eq!(
            config.decryption_manager_address,
            "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        );
        assert_eq!(
            config.httpz_address,
            "0x0000000000000000000000000000000000000001"
        );
        assert_eq!(config.channel_size, Some(2000));
        assert_eq!(config.service_name, "kms-connector-test");
        assert_eq!(config.decryption_timeout_secs, 600);
        assert_eq!(config.reencryption_timeout_secs, 600);
        assert_eq!(config.retry_interval_secs, 10);

        cleanup_env_vars();
    }

    #[test]
    #[serial]
    fn test_env_overrides_file() {
        cleanup_env_vars();

        // Create a temp config file
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: get_test_mnemonic(),
            chain_id: 1,
            decryption_manager_address: "0x0000000000000000000000000000000000000000".to_string(),
            httpz_address: "0x0000000000000000000000000000000000000000".to_string(),
            channel_size: Some(100),
            service_name: "kms-connector".to_string(),
            decryption_timeout_secs: 300,
            reencryption_timeout_secs: 300,
            retry_interval_secs: 5,
            account_index: None,
            decryption_manager_domain_name: "IDecryptionManager".to_string(),
            decryption_manager_domain_version: "1".to_string(),
            httpz_domain_name: "IHTTPZ".to_string(),
            httpz_domain_version: "1".to_string(),
        };

        let temp_file = NamedTempFile::new().unwrap();
        config.to_file(temp_file.path()).unwrap();

        // Set an environment variable to override the file
        env::set_var("KMS_CONNECTOR_CHAIN_ID", "77737");
        env::set_var("KMS_CONNECTOR_SERVICE_NAME", "kms-connector-override");

        // Load config from both sources
        let loaded_config = Config::from_env_and_file(Some(temp_file.path())).unwrap();

        // Verify that environment variables take precedence
        assert_eq!(loaded_config.chain_id, 77737);
        assert_eq!(loaded_config.service_name, "kms-connector-override");
        // File values should be used for non-overridden fields
        assert_eq!(loaded_config.gwl2_url, "ws://localhost:8545");

        cleanup_env_vars();
    }
}
