use self::threshold::ThresholdParty;
use conf_trace::conf::{Settings, Tracing};
use conf_trace::telemetry::init_tracing;
use serde::{Deserialize, Serialize};
use url::Url;

pub mod threshold;

/// Common configuration parameters that should be set in all scenarios
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoreConfig {
    pub service: ServiceEndpoint,
    pub tracing: Option<Tracing>,
    pub aws: Option<AWSConfig>,
    pub public_vault: Option<Vault>,
    pub private_vault: Option<Vault>,
    pub threshold: Option<ThresholdParty>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceEndpoint {
    // gRPC endpoint for incoming client requests
    pub listen_address: String,
    pub listen_port: u16,
    // gRPC request timeout
    pub timeout_secs: u64,
    // maximum gRPC message size in bytes
    pub grpc_max_message_size: usize,
}

pub trait ConfigTracing {
    fn tracing(&self) -> Option<Tracing>;
}

impl ConfigTracing for CoreConfig {
    fn tracing(&self) -> Option<Tracing> {
        self.tracing.clone()
    }
}

/// Override AWS configuration when running in Nitro enclaves or in test
/// environments
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AWSConfig {
    pub region: String,
    pub imds_endpoint: Option<Url>,
    pub s3_endpoint: Option<Url>,
    pub awskms_endpoint: Option<Url>,
}

/// Where and how to store the key material
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vault {
    pub storage: Url,
    pub keychain: Option<Url>,
}

/// Initialize the configuration from the given file.
pub fn init_conf<'a, T: Deserialize<'a> + std::fmt::Debug>(config_file: &str) -> anyhow::Result<T> {
    Settings::builder()
        .path(config_file)
        .env_prefix("KMS_CORE")
        .build()
        .init_conf()
        .map_err(|e| e.into())
}

/// Initialize the configuration from the given file and initialize tracing.
pub async fn init_conf_trace<'a, T: Deserialize<'a> + std::fmt::Debug + ConfigTracing>(
    config_file: &str,
) -> anyhow::Result<T> {
    let full_config: T = init_conf(config_file)?;
    let tracing = full_config
        .tracing()
        .unwrap_or_else(|| Tracing::builder().service_name("kms_core").build());
    init_tracing(tracing).await?;
    Ok(full_config)
}

/// Initialize the tracing configuration with default values
pub async fn init_trace() -> anyhow::Result<()> {
    let tracing = Tracing::builder().service_name("kms_core").build();
    init_tracing(tracing).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_config() {
        let core_config: CoreConfig = init_conf("config/default_1").unwrap();
        let threshold_config = core_config.threshold.unwrap();
        assert_eq!(core_config.service.listen_address, "0.0.0.0");
        assert_eq!(core_config.service.listen_port, 50100);
        assert_eq!(threshold_config.listen_address, "0.0.0.0");
        assert_eq!(threshold_config.listen_port, 50001);
        assert_eq!(threshold_config.threshold, 1);
        assert_eq!(threshold_config.num_sessions_preproc, Some(2));

        assert_eq!(threshold_config.peers.len(), 4);
        assert_eq!(threshold_config.peers[0].address, "p1");
        assert_eq!(threshold_config.peers[0].port, 50001);
        assert_eq!(threshold_config.peers[0].party_id, 1);
        assert_eq!(threshold_config.peers[1].address, "p2");
        assert_eq!(threshold_config.peers[1].port, 50002);
        assert_eq!(threshold_config.peers[1].party_id, 2);
        assert_eq!(threshold_config.peers[2].address, "p3");
        assert_eq!(threshold_config.peers[2].port, 50003);
        assert_eq!(threshold_config.peers[2].party_id, 3);
        assert_eq!(threshold_config.peers[3].address, "p4");
        assert_eq!(threshold_config.peers[3].port, 50004);
        assert_eq!(threshold_config.peers[3].party_id, 4);
        assert!(threshold_config.preproc_redis.is_none());

        assert_eq!(
            core_config.private_vault.unwrap().storage,
            Url::parse("file://./keys").unwrap()
        );
        assert_eq!(
            core_config.public_vault.unwrap().storage,
            Url::parse("file://./keys").unwrap()
        );

        let core_to_core_net = threshold_config.core_to_core_net;
        assert!(core_to_core_net.is_some());
        let core_to_core_net = core_to_core_net.unwrap();
        assert_eq!(core_to_core_net.message_limit, 70);
        assert_eq!(core_to_core_net.multiplier, 1.1);
        assert_eq!(core_to_core_net.max_interval, 5);
        assert_eq!(core_to_core_net.max_elapsed_time, Some(300));
        assert_eq!(core_to_core_net.network_timeout, 10);
        assert_eq!(core_to_core_net.network_timeout_bk, 300);
        assert_eq!(core_to_core_net.network_timeout_bk_sns, 1200);
        assert_eq!(core_to_core_net.max_en_decode_message_size, 2147483648);
    }

    #[test]
    fn test_centralized_config() {
        let core_config: CoreConfig = init_conf("config/default_centralized").unwrap();
        assert_eq!(core_config.service.listen_address, "0.0.0.0");
        assert_eq!(core_config.service.listen_port, 50051);

        let private_vault = core_config.private_vault.unwrap();

        assert_eq!(private_vault.storage, Url::parse("file://./keys").unwrap());
        assert!(private_vault.keychain.is_none());
        assert_eq!(
            core_config.public_vault.unwrap().storage,
            Url::parse("file://./keys").unwrap()
        );
    }
}
