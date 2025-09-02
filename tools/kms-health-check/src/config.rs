use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Minimal config structures - only parse what we need for health checks
#[derive(Debug, Clone)]
pub enum KmsConfig {
    Centralized(CentralizedConfigParsed),
    Threshold(ThresholdConfig),
}

#[derive(Debug, Clone)]
pub struct CentralizedConfigParsed {
    #[allow(dead_code)]
    pub address: String,
    #[allow(dead_code)]
    pub port: u16,
    pub storage: StorageConfig,
}

// Wrapper for parsing different config formats
#[derive(Debug, Deserialize)]
struct RawConfig {
    centralized: Option<CentralizedConfig>,
    threshold: Option<ThresholdConfig>,
    private_vault: Option<VaultConfig>,
}

#[derive(Debug, Deserialize)]
struct VaultConfig {
    storage: VaultStorage,
}

#[derive(Debug, Deserialize)]
struct VaultStorage {
    file: Option<FileStorage>,
    s3: Option<S3Storage>,
    #[allow(dead_code)]
    ram: Option<RamStorage>,
}

#[derive(Debug, Deserialize)]
struct FileStorage {
    path: String,
}

#[derive(Debug, Deserialize)]
struct S3Storage {
    bucket: String,
    #[serde(default)]
    region: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RamStorage {}

#[derive(Debug, Deserialize, Clone)]
pub struct CentralizedConfig {
    #[allow(dead_code)]
    pub address: String,
    pub port: u16,
    #[serde(rename = "private_storage")]
    pub storage: CentralizedStorageConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CentralizedStorageConfig {
    #[serde(rename = "type")]
    pub storage_type: String,
    pub path: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ThresholdConfig {
    pub listen_address: String,
    pub listen_port: u16,
    #[allow(dead_code)]
    pub my_id: usize,
    pub threshold: Option<usize>, // Max corrupted parties
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(skip)]
    pub storage: Option<StorageConfig>,
    // Catch all other fields we don't care about
    #[serde(flatten)]
    #[allow(dead_code)]
    extra: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PeerConfig {
    pub party_id: usize,
    pub address: String,
    pub port: u16,
    #[allow(dead_code)]
    #[serde(rename = "tls_cert")]
    pub tls_cert: Option<TlsCertConfig>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct TlsCertConfig {
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub storage_type: String,
    pub path: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
}

/// Parse and validate KMS configuration file
pub async fn parse_config(config_path: &Path) -> Result<KmsConfig> {
    let contents = tokio::fs::read_to_string(config_path)
        .await
        .context("Failed to read config file")?;

    let raw_config: RawConfig = toml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse TOML config: {}", e))?;

    // Handle different config formats
    match (raw_config.centralized, raw_config.threshold) {
        (Some(c), None) => {
            // Convert CentralizedStorageConfig to StorageConfig
            let storage = StorageConfig {
                storage_type: c.storage.storage_type.clone(),
                path: c.storage.path.clone(),
                bucket: c.storage.bucket.clone(),
                region: c.storage.region.clone(),
            };
            validate_centralized_config(&c)?;
            Ok(KmsConfig::Centralized(CentralizedConfigParsed {
                address: c.address,
                port: c.port,
                storage,
            }))
        }
        (None, Some(mut t)) => {
            // Add storage from private_vault if present
            if let Some(vault) = raw_config.private_vault {
                let storage_config = if vault.storage.file.is_some() {
                    StorageConfig {
                        storage_type: "file".to_string(),
                        path: vault.storage.file.map(|f| f.path),
                        bucket: None,
                        region: None,
                    }
                } else if let Some(s3) = vault.storage.s3 {
                    StorageConfig {
                        storage_type: "s3".to_string(),
                        path: None,
                        bucket: Some(s3.bucket),
                        region: s3.region,
                    }
                } else {
                    StorageConfig {
                        storage_type: "ram".to_string(),
                        path: None,
                        bucket: None,
                        region: None,
                    }
                };
                t.storage = Some(storage_config);
            }
            validate_threshold_config(&t)?;
            Ok(KmsConfig::Threshold(t))
        }
        _ => Err(anyhow::anyhow!(
            "Config must be either centralized or threshold format"
        )),
    }
}

fn validate_centralized_config(config: &CentralizedConfig) -> Result<()> {
    // Basic validation
    if config.port == 0 {
        return Err(anyhow::anyhow!("Invalid port: 0"));
    }

    // Storage validation is handled separately for centralized config
    Ok(())
}

fn validate_threshold_config(config: &ThresholdConfig) -> Result<()> {
    // Basic validation
    if config.listen_port == 0 {
        return Err(anyhow::anyhow!("Invalid listen_port: 0"));
    }

    // Check for duplicate party IDs
    let mut party_ids = Vec::new();
    for peer in &config.peers {
        if party_ids.contains(&peer.party_id) {
            return Err(anyhow::anyhow!("Duplicate party_id: {}", peer.party_id));
        }
        party_ids.push(peer.party_id);
    }

    // Validate ports for all peers
    for peer in &config.peers {
        if peer.port == 0 {
            return Err(anyhow::anyhow!("Invalid peer port: 0"));
        }
    }

    if let Some(ref storage) = config.storage {
        validate_storage(storage)?;
    }
    Ok(())
}

fn validate_storage(storage: &StorageConfig) -> Result<()> {
    match storage.storage_type.as_str() {
        "file" => {
            if storage.path.is_none() {
                return Err(anyhow::anyhow!("File storage requires 'path' field"));
            }
        }
        "s3" => {
            if storage.bucket.is_none() || storage.region.is_none() {
                return Err(anyhow::anyhow!(
                    "S3 storage requires 'bucket' and 'region' fields"
                ));
            }
        }
        "ram" => {
            // RAM storage doesn't need additional fields
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown storage type: {}",
                storage.storage_type
            ))
        }
    }
    Ok(())
}
