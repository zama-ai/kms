use conf_trace::conf::{Settings, Tracing};
use conf_trace::telemetry::init_tracing;
use serde::Deserialize;

pub mod centralized;
pub mod storage;
pub mod threshold;

pub trait ConfigTracing {
    fn tracing(&self) -> Option<Tracing>;
}

/// Initialize the configuration from the given file.
pub fn init_conf<'a, T: Deserialize<'a>>(config_file: &str) -> anyhow::Result<T> {
    Settings::builder()
        .path(config_file)
        .env_prefix("KMS_CORE")
        .build()
        .init_conf()
        .map_err(|e| e.into())
}

/// Initialize the configuration from the given file and initialize tracing.
pub fn init_conf_trace<'a, T: Deserialize<'a> + ConfigTracing>(
    config_file: &str,
) -> anyhow::Result<T> {
    let full_config: T = init_conf(config_file)?;
    let tracing = full_config
        .tracing()
        .unwrap_or_else(|| Tracing::builder().service_name("kms_core").build());
    init_tracing(tracing)?;
    Ok(full_config)
}

/// Initialize the tracing configuration with default values
pub fn init_trace() -> anyhow::Result<()> {
    let tracing = Tracing::builder().service_name("kms_core").build();
    init_tracing(tracing)
}

#[cfg(test)]
mod tests {
    use self::tests::centralized::CentralizedConfig;
    use self::tests::storage::StorageConfigWith;
    use self::tests::threshold::ThresholdConfig;
    use super::*;

    #[test]
    fn test_threshold_config() {
        let config: StorageConfigWith<ThresholdConfig> = init_conf("config/default_1").unwrap();
        assert_eq!(config.rest.listen_address_client, "0.0.0.0");
        assert_eq!(config.rest.listen_port_client, 50100);
        assert_eq!(config.rest.listen_address_core, "127.0.0.1");
        assert_eq!(config.rest.listen_port_core, 50001);
        assert_eq!(config.rest.threshold, 1);
        assert_eq!(config.rest.num_sessions_preproc, Some(2));
        assert_eq!(config.rest.param_file_map.len(), 2);
        assert_eq!(
            config.rest.param_file_map.get("test").unwrap(),
            "parameters/small_test_params.json"
        );

        assert_eq!(config.rest.peer_confs.len(), 4);
        assert_eq!(config.rest.peer_confs[0].address, "127.0.0.1");
        assert_eq!(config.rest.peer_confs[0].port, 50001);
        assert_eq!(config.rest.peer_confs[0].party_id, 1);
        assert_eq!(config.rest.peer_confs[1].address, "127.0.0.1");
        assert_eq!(config.rest.peer_confs[1].port, 50002);
        assert_eq!(config.rest.peer_confs[1].party_id, 2);
        assert_eq!(config.rest.peer_confs[2].address, "127.0.0.1");
        assert_eq!(config.rest.peer_confs[2].port, 50003);
        assert_eq!(config.rest.peer_confs[2].party_id, 3);
        assert_eq!(config.rest.peer_confs[3].address, "127.0.0.1");
        assert_eq!(config.rest.peer_confs[3].port, 50004);
        assert_eq!(config.rest.peer_confs[3].party_id, 4);

        assert_eq!(
            config.rest.param_file_map.get("default").unwrap(),
            "parameters/default_params.json"
        );
        assert!(config.rest.preproc_redis_conf.is_none());
        assert_eq!(config.private_storage_url.unwrap(), "file://./keys");
        assert_eq!(config.public_storage_url.unwrap(), "file://./keys");

        let core_to_core_net_conf = config.rest.core_to_core_net_conf;
        assert!(core_to_core_net_conf.is_some());
        let core_to_core_net_conf = core_to_core_net_conf.unwrap();
        assert_eq!(core_to_core_net_conf.message_limit, 70);
        assert_eq!(core_to_core_net_conf.multiplier, 1.1);
        assert_eq!(core_to_core_net_conf.max_interval, 5);
        assert_eq!(core_to_core_net_conf.max_elapsed_time, Some(300));
        assert_eq!(core_to_core_net_conf.network_timeout, 10);
        assert_eq!(core_to_core_net_conf.network_timeout_bk, 300);
        assert_eq!(core_to_core_net_conf.network_timeout_bk_sns, 1200);
        assert_eq!(core_to_core_net_conf.max_en_decode_message_size, 2147483648);
    }

    #[test]
    fn test_centralized_config() {
        let config: StorageConfigWith<CentralizedConfig> =
            init_conf("config/default_centralized").unwrap();
        assert_eq!(config.rest.url, "http://0.0.0.0:50051");
        assert_eq!(config.rest.param_file_map.len(), 2);
        assert_eq!(
            config.rest.param_file_map.get("test").unwrap(),
            "parameters/small_test_params.json"
        );
        assert_eq!(
            config.rest.param_file_map.get("default").unwrap(),
            "parameters/default_params.json"
        );
        assert_eq!(config.private_storage_url.unwrap(), "file://./keys");
        assert_eq!(config.public_storage_url.unwrap(), "file://./keys");
    }
}
