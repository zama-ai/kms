use crate::{
    conf::{ConfigTracing, ConfigTracing},
    util::rate_limiter::RateLimiterConfig,
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageConfigWith<MoreConfig> {
    pub public_storage_url: Option<String>,
    pub private_storage_url: Option<String>,
    pub root_key_id: Option<String>,
    pub aws_region: Option<String>,
    pub aws_imds_proxy: Option<String>,
    pub aws_s3_proxy: Option<String>,
    pub aws_kms_proxy: Option<String>,
    #[serde(flatten)]
    pub rest: MoreConfig,
    pub telemetry: Option<TelemetryConfig>,
    pub rate_limiter_conf: Option<RateLimiterConfig>,
}

impl<'a, MoreConfig> StorageConfigWith<MoreConfig>
where
    MoreConfig: Deserialize<'a>,
{
    pub fn private_storage_url(&self) -> anyhow::Result<Option<Url>> {
        Ok(self
            .private_storage_url
            .as_deref()
            .map(Url::parse)
            .transpose()?)
    }

    pub fn public_storage_url(&self) -> anyhow::Result<Option<Url>> {
        Ok(self
            .public_storage_url
            .as_deref()
            .map(Url::parse)
            .transpose()?)
    }

    pub fn aws_s3_proxy(&self) -> anyhow::Result<Option<Url>> {
        Ok(self.aws_s3_proxy.as_deref().map(Url::parse).transpose()?)
    }
}

impl<MoreConfig> ConfigTracing for StorageConfigWith<MoreConfig> {
    fn telemetry(&self) -> Option<TelemetryConfig> {
        self.telemetry.clone()
    }
}
