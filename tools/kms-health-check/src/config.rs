use anyhow::Result;
use kms_lib::conf::{init_conf, CoreConfig};
use std::path::Path;
use validator::Validate;

/// KMS configuration - reuse the actual server config structure
pub type KmsConfig = CoreConfig;

/// Parse and validate KMS configuration file using the actual KMS server validation
pub async fn parse_config(config_path: &Path) -> Result<KmsConfig> {
    let config_path_str = config_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid config path"))?;

    // Use the actual KMS server config parsing and validation
    let config: CoreConfig = init_conf(config_path_str).map_err(|e| {
        eprintln!("Config parsing error details: {:#?}", e);
        anyhow::anyhow!("Failed to parse config file: {}", e)
    })?;

    // Validate using the same validation rules as the KMS server
    config.validate().map_err(|e| {
        eprintln!("Config validation error details: {:#?}", e);
        anyhow::anyhow!("Config validation failed: {}", e)
    })?;

    Ok(config)
}
