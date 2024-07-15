use crate::conf::{ConfigTracing, Tracing};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageConfigWith<MoreConfig> {
    pub public_storage_url: Option<String>,
    pub private_storage_url: Option<String>,
    pub root_key_id: Option<String>,
    pub aws_region: Option<String>,
    pub aws_s3_proxy: Option<String>,
    pub aws_kms_proxy: Option<String>,
    pub enclave_vsock: Option<String>,
    #[serde(flatten)]
    pub rest: MoreConfig,
    pub tracing: Option<Tracing>,
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
}

impl<MoreConfig> ConfigTracing for StorageConfigWith<MoreConfig> {
    fn tracing(&self) -> Option<Tracing> {
        self.tracing.clone()
    }
}
