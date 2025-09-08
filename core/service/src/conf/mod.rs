use self::threshold::ThresholdPartyConf;
use crate::util::rate_limiter::RateLimiterConfig;
use clap::ValueEnum;
use observability::{
    conf::{Settings, TelemetryConfig},
    telemetry::{init_telemetry, SdkMeterProvider, SdkTracerProvider},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strum_macros::EnumIs;
use url::Url;
use validator::{Validate, ValidationErrors};

pub mod threshold;

/// Common configuration parameters that should be set in all scenarios
#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    #[validate(nested)]
    pub service: ServiceEndpoint,
    #[validate(nested)]
    pub telemetry: Option<TelemetryConfig>,
    #[validate(nested)]
    pub aws: Option<AWSConfig>,
    #[validate(nested)]
    pub public_vault: Option<VaultConfig>,
    #[validate(nested)]
    pub private_vault: Option<VaultConfig>,
    #[validate(nested)]
    pub backup_vault: Option<VaultConfig>,
    #[validate(nested)]
    pub rate_limiter_conf: Option<RateLimiterConfig>,
    #[validate(nested)]
    pub threshold: Option<ThresholdPartyConf>,
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServiceEndpoint {
    // gRPC endpoint for incoming client requests
    #[validate(length(min = 1))]
    pub listen_address: String,
    #[validate(range(min = 1, max = 65535))]
    pub listen_port: u16,
    // gRPC request timeout
    #[validate(range(min = 1))]
    pub timeout_secs: u64,
    // maximum gRPC message size in bytes
    #[validate(range(min = 1, max = 2147483647))]
    pub grpc_max_message_size: usize,
}

pub trait ConfigTracing {
    fn telemetry(&self) -> Option<TelemetryConfig>;
}

impl ConfigTracing for CoreConfig {
    fn telemetry(&self) -> Option<TelemetryConfig> {
        self.telemetry.clone()
    }
}

/// Override AWS configuration when running in Nitro enclaves or in test
/// environments
#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AWSConfig {
    #[validate(length(min = 1))]
    pub region: String,
    #[validate(length(min = 1))]
    pub role_arn: Option<String>,
    pub imds_endpoint: Option<Url>,
    pub sts_endpoint: Option<Url>,
    pub s3_endpoint: Option<Url>,
    pub awskms_endpoint: Option<Url>,
}

/// Where and how to store the key material
#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub storage: Storage,
    #[validate(range(min = 1))]
    pub storage_cache_size: Option<usize>,
    #[validate(nested)]
    pub keychain: Option<Keychain>,
}

/// How to store the key material
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIs)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Storage {
    Ram(RamStorage),
    File(FileStorage),
    S3(S3Storage),
}

impl Validate for Storage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Storage::Ram(_) => Ok(()),
            Storage::File(s) => s.validate(),
            Storage::S3(s) => s.validate(),
        }
    }
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RamStorage {}

#[derive(Serialize, Deserialize, Validate, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct FileStorage {
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct S3Storage {
    #[validate(length(min = 1))]
    pub bucket: String,
    #[validate(length(min = 1))]
    pub prefix: Option<String>,
}

/// How to encrypt the key material
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIs)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Keychain {
    AwsKms(AwsKmsKeychain),
    SecretSharing(SecretSharingKeychain),
}

/// derive(Validate) doesn't work on enums because the author of `validator` is
/// too lazy to implement it, so we have to define a struct for each enum
/// variant by hand and then write these trivial Validate instances by hand
/// because `enum_dispatch` doesn't work on imported traits
impl Validate for Keychain {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Keychain::AwsKms(k) => k.validate(),
            Keychain::SecretSharing(k) => k.validate(),
        }
    }
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct AwsKmsKeychain {
    #[validate(length(min = 1))]
    pub root_key_id: String,
    pub root_key_spec: AwsKmsKeySpec,
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SecretSharingKeychain {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIs, ValueEnum)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AwsKmsKeySpec {
    Symm,
    Asymm,
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

/// Initialize and validate the configuration from the given file and initialize tracing.
pub async fn init_conf_kms_core_telemetry<
    'a,
    T: Deserialize<'a> + std::fmt::Debug + ConfigTracing + Validate,
>(
    config_file: &str,
) -> anyhow::Result<(T, SdkTracerProvider, SdkMeterProvider)> {
    let full_config: T = init_conf(config_file)?;
    full_config.validate()?;
    let telemetry = full_config.telemetry().unwrap_or_else(|| {
        TelemetryConfig::builder()
            .tracing_service_name("kms_core".to_string())
            .build()
    });
    let (tracer_provider, meter_provider) = init_telemetry(&telemetry).await?;
    Ok((full_config, tracer_provider, meter_provider))
}

/// Initialize the tracing configuration with default values
pub async fn init_kms_core_telemetry() -> anyhow::Result<(SdkTracerProvider, SdkMeterProvider)> {
    let telemetry = TelemetryConfig::builder()
        .tracing_service_name("kms_core".to_string())
        .build();
    let (tracer_provider, meter_provider) = init_telemetry(&telemetry).await?;
    Ok((tracer_provider, meter_provider))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        conf::threshold::{TlsCert, TlsConf, TlsKey},
        util::rate_limiter::RateLimiterConfig,
    };

    #[test]
    fn test_threshold_config() {
        let core_config: CoreConfig = init_conf("config/default_2").unwrap();
        core_config.validate().unwrap();
        let threshold_config = core_config.threshold.unwrap();
        assert_eq!(core_config.service.listen_address, "0.0.0.0");
        assert_eq!(core_config.service.listen_port, 50200);
        assert_eq!(threshold_config.listen_address, "0.0.0.0");
        assert_eq!(threshold_config.listen_port, 50002);
        assert_eq!(threshold_config.threshold, 1);
        assert_eq!(threshold_config.num_sessions_preproc, Some(2));

        let peers = threshold_config.peers.unwrap();

        assert_eq!(peers.len(), 4);
        assert_eq!(peers[0].address, "p1");
        assert_eq!(peers[0].port, 50001);
        assert_eq!(peers[0].party_id, 1);
        assert_eq!(
            peers[0].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p1.pem")))
        );
        assert_eq!(peers[1].address, "p2");
        assert_eq!(peers[1].port, 50002);
        assert_eq!(peers[1].party_id, 2);
        assert_eq!(
            peers[1].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p2.pem")))
        );
        assert_eq!(peers[2].address, "p3");
        assert_eq!(peers[2].port, 50003);
        assert_eq!(peers[2].party_id, 3);
        assert_eq!(
            peers[2].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p3.pem")))
        );
        assert_eq!(peers[3].address, "p4");
        assert_eq!(peers[3].port, 50004);
        assert_eq!(peers[3].party_id, 4);
        assert_eq!(
            peers[3].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p4.pem")))
        );

        assert!(threshold_config.preproc_redis.is_none());
        let tls_config = threshold_config.tls.unwrap();
        assert_eq!(
            tls_config,
            TlsConf::Manual {
                cert: TlsCert::Path(PathBuf::from(r"certs/cert_p2.pem")),
                key: TlsKey::Path(PathBuf::from(r"certs/key_p2.pem")),
            }
        );

        let private_vault = core_config.private_vault.unwrap();

        assert_eq!(
            private_vault.storage,
            Storage::File(FileStorage {
                path: PathBuf::from("./keys")
            })
        );

        assert_eq!(
            core_config.public_vault.unwrap().storage,
            Storage::File(FileStorage {
                path: PathBuf::from("./keys")
            })
        );

        assert_eq!(
            core_config.rate_limiter_conf.unwrap(),
            RateLimiterConfig::default()
        );

        let core_to_core_net = threshold_config.core_to_core_net;
        assert!(core_to_core_net.is_some());
        let core_to_core_net = core_to_core_net.unwrap();
        assert_eq!(core_to_core_net.message_limit, 70);
        assert_eq!(core_to_core_net.multiplier, 2.0);
        assert_eq!(core_to_core_net.max_interval, 60);
        assert_eq!(core_to_core_net.initial_interval_ms, Some(100));
        assert_eq!(core_to_core_net.max_elapsed_time, Some(300));
        assert_eq!(core_to_core_net.network_timeout, 20);
        assert_eq!(core_to_core_net.network_timeout_bk, 300);
        assert_eq!(core_to_core_net.network_timeout_bk_sns, 1200);
        assert_eq!(core_to_core_net.max_en_decode_message_size, 2147483648);
        assert_eq!(core_to_core_net.session_update_interval_secs, Some(60));
        assert_eq!(core_to_core_net.session_cleanup_interval_secs, Some(3600));
        assert_eq!(
            core_to_core_net.discard_inactive_sessions_interval,
            Some(900)
        );
        assert_eq!(
            core_to_core_net.max_waiting_time_for_message_queue,
            Some(60)
        );
        assert_eq!(
            core_to_core_net.max_opened_inactive_sessions_per_party,
            Some(100)
        );
    }

    #[test]
    fn test_centralized_config() {
        let core_config: CoreConfig = init_conf("config/default_centralized").unwrap();
        core_config.validate().unwrap();
        assert_eq!(core_config.service.listen_address, "0.0.0.0");
        assert_eq!(core_config.service.listen_port, 50051);

        let private_vault = core_config.private_vault.unwrap();

        assert_eq!(
            private_vault.storage,
            Storage::File(FileStorage {
                path: PathBuf::from("./keys"),
            })
        );
        assert!(private_vault.keychain.is_none());
        assert_eq!(
            core_config.public_vault.unwrap().storage,
            Storage::File(FileStorage {
                path: PathBuf::from("./keys"),
            })
        );
        assert_eq!(
            core_config.rate_limiter_conf.unwrap(),
            RateLimiterConfig::default()
        );
    }
}
