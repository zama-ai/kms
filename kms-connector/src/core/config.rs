use crate::error::{Error, Result};
use alloy::primitives::Address;
use bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr};

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
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config file: {}", e)))?;

        // Validate mnemonic
        Mnemonic::parse_normalized(&config.mnemonic)
            .map_err(|e| Error::Config(format!("Invalid mnemonic: {}", e)))?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_valid_config() {
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: "test test test test test test test test test test test junk".to_string(),
            chain_id: 1,
            decryption_manager_address: "0x0000000000000000000000000000000000000000".to_string(),
            httpz_address: "0x0000000000000000000000000000000000000000".to_string(),
            channel_size: Some(100),
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
    }

    #[test]
    fn test_save_config() {
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: "test test test test test test test test test test test junk".to_string(),
            chain_id: 1,
            decryption_manager_address: "0x0000000000000000000000000000000000000000".to_string(),
            httpz_address: "0x0000000000000000000000000000000000000000".to_string(),
            channel_size: None,
        };

        config.to_file("test_config.toml").unwrap();
        let loaded_config = Config::from_file("test_config.toml").unwrap();
        assert_eq!(config.gwl2_url, loaded_config.gwl2_url);

        fs::remove_file("test_config.toml").unwrap();
    }

    #[test]
    fn test_invalid_address() {
        let config = Config {
            gwl2_url: "ws://localhost:8545".to_string(),
            kms_core_endpoint: "http://localhost:50052".to_string(),
            mnemonic: "test test test test test test test test test test test junk".to_string(),
            chain_id: 1,
            decryption_manager_address: "0x0000".to_string(),
            httpz_address: "0x000010".to_string(),
            channel_size: None,
        };

        let temp_file = NamedTempFile::new().unwrap();
        config.to_file(temp_file.path()).unwrap();

        assert!(Config::from_file(temp_file.path()).is_err());
    }
}
