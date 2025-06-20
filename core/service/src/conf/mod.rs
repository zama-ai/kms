use crate::util::rate_limiter::RateLimiterConfig;

use self::threshold::ThresholdPartyConf;
use observability::{
    conf::{Settings, TelemetryConfig},
    telemetry::{init_telemetry, SdkMeterProvider, SdkTracerProvider},
};
use serde::{Deserialize, Serialize};
use url::Url;

pub mod threshold;

/// Common configuration parameters that should be set in all scenarios
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    pub service: ServiceEndpoint,
    pub telemetry: Option<TelemetryConfig>,
    pub aws: Option<AWSConfig>,
    pub public_vault: Option<VaultConfig>,
    pub private_vault: Option<VaultConfig>,
    pub backup_vault: Option<VaultConfig>,
    pub rate_limiter_conf: Option<RateLimiterConfig>,
    pub threshold: Option<ThresholdPartyConf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
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
    fn telemetry(&self) -> Option<TelemetryConfig>;
}

impl ConfigTracing for CoreConfig {
    fn telemetry(&self) -> Option<TelemetryConfig> {
        self.telemetry.clone()
    }
}

pub trait ValidateConfig {
    /// Validates the configuration parameters.
    fn validate(&self) -> anyhow::Result<()>;
}

impl ValidateConfig for ThresholdPartyConf {
    fn validate(&self) -> anyhow::Result<()> {
        let num_parties = self.peers.len(); // I am in the peer list myself, so num_parties is the length of the peers list

        if self.listen_address.is_empty() {
            return Err(anyhow::anyhow!("Threshold listen address cannot be empty"));
        }
        if self.listen_port == 0 {
            return Err(anyhow::anyhow!("Threshold listen port cannot be zero"));
        }
        if self.threshold == 0 {
            return Err(anyhow::anyhow!("Threshold must be greater than zero"));
        }
        // We assume for now that 3 * threshold + 1 == num_parties.
        // Note: this might change in the future
        if 3 * self.threshold as usize + 1 != num_parties {
            return Err(anyhow::anyhow!(
                    "3*t+1 must be equal to number of parties. Got t={} but expected t={} for n={} parties",
                    self.threshold,
                    (num_parties - 1) / 3,
                    num_parties
                ));
        }
        if self.my_id == 0 || self.my_id > num_parties {
            return Err(anyhow::anyhow!(
                "Party ID must be greater than 0 and cannot be greater than the number of parties ({}), but was {}.",
                num_parties,
                self.my_id,
            ));
        }

        // check peer config
        for peer in &self.peers {
            if peer.address.is_empty() {
                return Err(anyhow::anyhow!("Peer address cannot be empty"));
            }
            if peer.port == 0 {
                return Err(anyhow::anyhow!("Peer port cannot be zero"));
            }
            if peer.party_id == 0 || peer.party_id > num_parties {
                return Err(anyhow::anyhow!(
                    "Peer party ID must be greater than 0 and cannot be greater than the number of parties ({}), but was {}.",
                    num_parties,
                    peer.party_id,
                ));
            }
        }

        Ok(())
    }
}

impl ValidateConfig for AWSConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.region.is_empty() {
            return Err(anyhow::anyhow!("AWS region cannot be empty"));
        }
        if self.role_arn.as_ref().is_some_and(|r| r.is_empty()) {
            return Err(anyhow::anyhow!("AWS role ARN cannot be empty if provided"));
        }
        if self
            .imds_endpoint
            .as_ref()
            .is_some_and(|u| u.as_str().is_empty())
        {
            return Err(anyhow::anyhow!("IMDS endpoint cannot be empty if provided"));
        }
        if self
            .sts_endpoint
            .as_ref()
            .is_some_and(|u| u.as_str().is_empty())
        {
            return Err(anyhow::anyhow!("STS endpoint cannot be empty if provided"));
        }
        if self
            .s3_endpoint
            .as_ref()
            .is_some_and(|u| u.as_str().is_empty())
        {
            return Err(anyhow::anyhow!("S3 endpoint cannot be empty if provided"));
        }
        if self
            .awskms_endpoint
            .as_ref()
            .is_some_and(|u| u.as_str().is_empty())
        {
            return Err(anyhow::anyhow!(
                "AWS KMS endpoint cannot be empty if provided"
            ));
        }
        Ok(())
    }
}

impl ValidateConfig for TelemetryConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self
            .tracing_service_name
            .as_ref()
            .is_some_and(|s| s.is_empty())
        {
            return Err(anyhow::anyhow!(
                "Tracing service name cannot be empty if provided"
            ));
        }

        if self.tracing_endpoint.as_ref().is_some_and(|u| u.is_empty()) {
            return Err(anyhow::anyhow!(
                "Tracing endpoint cannot be empty if provided"
            ));
        }

        if self
            .metrics_bind_address
            .as_ref()
            .is_some_and(|s| s.is_empty())
        {
            return Err(anyhow::anyhow!(
                "Metrics bind address cannot be empty if provided"
            ));
        }

        if self
            .tracing_otlp_timeout_ms
            .as_ref()
            .is_some_and(|t| *t == 0)
        {
            return Err(anyhow::anyhow!(
                "Tracing OTLP timeout cannot be zero if provided"
            ));
        }

        Ok(())
    }
}

impl ValidateConfig for RateLimiterConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.bucket_size == 0 {
            return Err(anyhow::anyhow!("Rate limiter bucket size cannot be zero"));
        }
        if self.pub_decrypt == 0 {
            return Err(anyhow::anyhow!(
                "Rate limiter: public decryption cost cannot be zero"
            ));
        }
        if self.user_decrypt == 0 {
            return Err(anyhow::anyhow!(
                "Rate limiter: user decryption cost cannot be zero"
            ));
        }
        if self.crsgen == 0 {
            return Err(anyhow::anyhow!(
                "Rate limiter: CRS generation cost cannot be zero"
            ));
        }
        if self.keygen == 0 {
            return Err(anyhow::anyhow!(
                "Rate limiter: key generation cost cannot be zero"
            ));
        }
        if self.preproc == 0 {
            return Err(anyhow::anyhow!(
                "Rate limiter: pre-processing cost cannot be zero"
            ));
        }

        Ok(())
    }
}

impl ValidateConfig for VaultConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.storage.as_str().is_empty() {
            return Err(anyhow::anyhow!("Vault storage URL cannot be empty"));
        }
        if self.storage_cache_size.is_some_and(|s| s == 0) {
            return Err(anyhow::anyhow!("Vault storage cache size cannot be zero"));
        }
        if self
            .keychain
            .as_ref()
            .is_some_and(|k| k.as_str().is_empty())
        {
            return Err(anyhow::anyhow!(
                "Vault keychain URL cannot be empty if provided"
            ));
        }

        Ok(())
    }
}

impl ValidateConfig for CoreConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.service.listen_address.is_empty() {
            return Err(anyhow::anyhow!("Service listen address cannot be empty"));
        }
        if self.service.listen_port == 0 {
            return Err(anyhow::anyhow!("Service listen port cannot be zero"));
        }
        if self.service.timeout_secs == 0 {
            return Err(anyhow::anyhow!("Service timeout seconds cannot be zero"));
        }
        if self.service.grpc_max_message_size == 0 {
            return Err(anyhow::anyhow!("gRPC max message size cannot be zero"));
        }

        // if we have a threshold configuration (i.e. not a centralized KMS), validate the threshold config
        if let Some(threshold_party_config) = &self.threshold {
            threshold_party_config.validate()?;
        }

        // Validate rate limiter configuration if provided
        if let Some(rate_limiter_conf) = &self.rate_limiter_conf {
            rate_limiter_conf.validate()?;
        }

        // Validate AWS configuration if provided
        if let Some(aws_config) = &self.aws {
            aws_config.validate()?;
        }

        // Validate telemetry configuration if provided
        if let Some(telemetry) = &self.telemetry {
            telemetry.validate()?;
        }

        // Validate private vault configuration if provided
        if let Some(private_vault) = &self.private_vault {
            private_vault.validate()?;
        }

        // Validate public vault configuration if provided
        if let Some(public_vault) = &self.public_vault {
            public_vault.validate()?;
        }

        // Validate backup vault configuration if provided
        if let Some(backup_vault) = &self.backup_vault {
            backup_vault.validate()?;
        }

        // Config is if we reach this point
        Ok(())
    }
}

/// Override AWS configuration when running in Nitro enclaves or in test
/// environments
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AWSConfig {
    pub region: String,
    pub role_arn: Option<String>,
    pub imds_endpoint: Option<Url>,
    pub sts_endpoint: Option<Url>,
    pub s3_endpoint: Option<Url>,
    pub awskms_endpoint: Option<Url>,
}

/// Where and how to store the key material
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub storage: Url,
    pub storage_cache_size: Option<usize>,
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

/// Initialize and validate the configuration from the given file and initialize tracing.
pub async fn init_conf_kms_core_telemetry<
    'a,
    T: Deserialize<'a> + std::fmt::Debug + ConfigTracing + ValidateConfig,
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
        let core_config: CoreConfig = init_conf("config/default_1").unwrap();
        core_config.validate().unwrap();
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
        assert_eq!(
            threshold_config.peers[0].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p1.pem")))
        );
        assert_eq!(threshold_config.peers[1].address, "p2");
        assert_eq!(threshold_config.peers[1].port, 50002);
        assert_eq!(threshold_config.peers[1].party_id, 2);
        assert_eq!(
            threshold_config.peers[1].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p2.pem")))
        );
        assert_eq!(threshold_config.peers[2].address, "p3");
        assert_eq!(threshold_config.peers[2].port, 50003);
        assert_eq!(threshold_config.peers[2].party_id, 3);
        assert_eq!(
            threshold_config.peers[2].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p3.pem")))
        );
        assert_eq!(threshold_config.peers[3].address, "p4");
        assert_eq!(threshold_config.peers[3].port, 50004);
        assert_eq!(threshold_config.peers[3].party_id, 4);
        assert_eq!(
            threshold_config.peers[3].tls_cert,
            Some(TlsCert::Path(PathBuf::from(r"certs/cert_p4.pem")))
        );

        assert!(threshold_config.preproc_redis.is_none());
        let tls_config = threshold_config.tls.unwrap();
        assert_eq!(
            tls_config,
            TlsConf::Manual {
                cert: TlsCert::Path(PathBuf::from(r"certs/cert_p1.pem")),
                key: TlsKey::Path(PathBuf::from(r"certs/key_p1.pem")),
            }
        );

        assert_eq!(
            core_config.private_vault.unwrap().storage,
            Url::parse("file://./keys").unwrap()
        );
        assert_eq!(
            core_config.public_vault.unwrap().storage,
            Url::parse("file://./keys").unwrap()
        );

        assert_eq!(
            core_config.rate_limiter_conf.unwrap(),
            RateLimiterConfig::default()
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
        core_config.validate().unwrap();
        assert_eq!(core_config.service.listen_address, "0.0.0.0");
        assert_eq!(core_config.service.listen_port, 50051);

        let private_vault = core_config.private_vault.unwrap();

        assert_eq!(private_vault.storage, Url::parse("file://./keys").unwrap());
        assert!(private_vault.keychain.is_none());
        assert_eq!(
            core_config.public_vault.unwrap().storage,
            Url::parse("file://./keys").unwrap()
        );
        assert_eq!(
            core_config.rate_limiter_conf.unwrap(),
            RateLimiterConfig::default()
        );
    }
}
