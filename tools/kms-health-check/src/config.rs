use anyhow::Result;
use kms_lib::conf::{init_conf, CoreConfig};
use observability::conf::Settings;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use validator::Validate;

/// KMS configuration - reuse the actual server config structure
pub type KmsConfig = CoreConfig;

/// Health check tool specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Connection timeout in seconds (env: HEALTH_CHECK_CONNECTION_TIMEOUT_SECS)
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    /// Request timeout in seconds (env: HEALTH_CHECK_REQUEST_TIMEOUT_SECS)
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            connection_timeout_secs: default_connection_timeout(),
            request_timeout_secs: default_request_timeout(),
        }
    }
}

impl HealthCheckConfig {
    /// Load configuration with environment variable overrides
    /// Env vars (HEALTH_CHECK__*) take precedence over TOML config
    pub fn load() -> Self {
        let config = Settings::builder()
            .env_prefix("HEALTH_CHECK")
            .build()
            .init_conf()
            .unwrap_or_else(|_| Self::default());

        // Display applied configuration with source information
        let conn_from_env = std::env::var("HEALTH_CHECK__CONNECTION_TIMEOUT_SECS").is_ok();
        let req_from_env = std::env::var("HEALTH_CHECK__REQUEST_TIMEOUT_SECS").is_ok();

        tracing::info!("Health Check Configuration:");
        tracing::info!(
            "  Connection timeout: {}s {}",
            config.connection_timeout_secs,
            if conn_from_env {
                "(from env)"
            } else {
                "(default)"
            }
        );
        tracing::info!(
            "  Request timeout: {}s {}",
            config.request_timeout_secs,
            if req_from_env {
                "(from env)"
            } else {
                "(default)"
            }
        );

        config
    }

    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

fn default_connection_timeout() -> u64 {
    5
}
fn default_request_timeout() -> u64 {
    10
}

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
