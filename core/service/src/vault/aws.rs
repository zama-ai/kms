use aws_config::{
    Region, SdkConfig, default_provider::credentials::DefaultCredentialsChain,
    identity::IdentityCache, imds::client::Client as IMDSClient, provider_config::ProviderConfig,
};
use std::time::Duration;
use url::Url;

/// Constructs an AWS SDK configuration for requesting AWS credentials inside of
/// a Nitro enclave.
pub async fn build_aws_sdk_config(
    aws_region: String,
    aws_imds_endpoint: Option<Url>,
    aws_sts_endpoint: Option<Url>,
) -> SdkConfig {
    let aws_region = Region::new(aws_region);
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

    if let Some(p) = aws_sts_endpoint {
        config_loader = config_loader.endpoint_url(p);
    }

    if let Some(p) = aws_imds_endpoint {
        let imds_client = IMDSClient::builder()
            .endpoint(p)
            .expect("AWS IMDS endpoint invalid")
            .build();
        let provider_config =
            ProviderConfig::without_region().with_region(Some(aws_region.clone()));
        let credentials_provider = DefaultCredentialsChain::builder()
            .configure(provider_config)
            .region(aws_region.clone())
            .imds_client(imds_client)
            .build()
            .await;
        config_loader = config_loader.credentials_provider(credentials_provider);
    }

    config_loader
        .region(aws_region)
        // DNS resolution is sometimes slow in EKS due to ndots 5, and the
        // default 5s timeout isn't enough
        .identity_cache(
            IdentityCache::lazy()
                .load_timeout(Duration::from_secs(10))
                .build(),
        )
        .load()
        .await
}
