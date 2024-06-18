use std::env;
use std::str::FromStr;

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, Display, EnumString};
use typed_builder::TypedBuilder;

lazy_static::lazy_static! {
    pub(crate) static ref ENVIRONMENT: ExecutionEnvironment = mode();
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, TypedBuilder, Default)]
pub struct Tracing {
    service_name: String,
    endpoint: String,
}

impl Tracing {
    /// Returns the service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Default, Display, Deserialize, Serialize, Clone, EnumString, AsRefStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ExecutionEnvironment {
    #[default]
    Local,
    #[strum(serialize = "dev")]
    Development,
    Stage,
    #[strum(serialize = "prod")]
    Production,
    #[cfg(test)]
    Test,
}

#[derive(TypedBuilder)]
pub struct Settings<'a> {
    path: Option<&'a str>,
}

impl<'a> Settings<'a> {
    /// Creates a new instance of `Settings`.
    pub fn new(path: Option<&'a str>) -> Self {
        Self { path }
    }
}

fn mode() -> ExecutionEnvironment {
    env::var("RUN_MODE")
        .map(|enum_str| ExecutionEnvironment::from_str(enum_str.as_str()).unwrap_or_default())
        .unwrap_or_else(|_| ExecutionEnvironment::Local)
}

impl<'a> Settings<'a> {
    /// Creates a new instance of `Settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created or deserialized.
    pub fn init_conf<'de, T: Deserialize<'de>>(&self) -> Result<T, ConfigError> {
        let mut s = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name("config/kms-core").required(false))
            .add_source(
                File::with_name(&format!("config/kms-core-{}", *ENVIRONMENT)).required(false),
            )
            .add_source(File::with_name("/etc/config/kms-core.toml").required(false));

        if let Some(path) = self.path {
            s = s.add_source(File::with_name(path).required(false))
        };

        let s = s
            .add_source(
                config::Environment::default()
                    .prefix("KMS_CORE")
                    .separator("_")
                    .list_separator(","),
            )
            .build()?;

        let settings: T = s.try_deserialize()?;

        Ok(settings)
    }
}

pub mod centralized;
pub mod telemetry;
pub mod threshold;

#[cfg(test)]
mod tests {
    use self::tests::centralized::CentralizedConfig;
    use self::tests::threshold::ThresholdConfig;
    use super::*;

    #[test]
    fn test_threshold_config() {
        let config: ThresholdConfig = Settings::new(Some("config/default_1")).init_conf().unwrap();
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
        assert_eq!(config.private_storage_path.unwrap(), "keys");
        assert_eq!(config.public_storage_path.unwrap(), "keys");
    }

    #[test]
    fn test_centralized_config() {
        let config: CentralizedConfig = Settings::new(Some("config/default_centralized"))
            .init_conf()
            .unwrap();
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
        assert_eq!(config.private_storage_path.unwrap(), "keys");
        assert_eq!(config.public_storage_path.unwrap(), "keys");
    }
}
