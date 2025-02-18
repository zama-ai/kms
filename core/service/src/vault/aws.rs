use aws_config::{
    default_provider::credentials::DefaultCredentialsChain, imds::client::Client as IMDSClient,
    provider_config::ProviderConfig, Region, SdkConfig,
};
use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
use hyper_rustls::HttpsConnectorBuilder;
use url::Url;

/// Given the address of a vsock-to-TCP proxy, constructs an AWS SDK configuration for requesting AWS credentials inside of a Nitro enclave.
pub async fn build_aws_sdk_config(
    aws_region: String,
    aws_imds_endpoint: Option<Url>,
    aws_sts_endpoint: Option<Url>,
) -> SdkConfig {
    let aws_region = Region::new(aws_region);
    let config_loader = match aws_imds_endpoint {
        Some(p) => {
            let imds_client = IMDSClient::builder()
                .endpoint(p)
                .expect("AWS IMDS endpoint invalid")
                .build();
            let https_connector = HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_only()
                // Overrides the hostname checked during the TLS handshake
                .with_server_name(format!("sts.{}.amazonaws.com", aws_region.clone()))
                .enable_http1()
                .build();
            let http_client = HyperClientBuilder::new().build(https_connector);
            let provider_config = ProviderConfig::without_region()
                .with_region(Some(aws_region.clone()))
                .with_http_client(http_client);
            let credentials_provider = DefaultCredentialsChain::builder()
                .configure(provider_config)
                .region(aws_region.clone())
                .imds_client(imds_client)
                .build()
                .await;
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .credentials_provider(credentials_provider)
                .endpoint_url(aws_sts_endpoint.expect("AWS STS endpoint must be set"))
        }
        None => aws_config::defaults(aws_config::BehaviorVersion::latest()),
    };
    config_loader.region(aws_region).load().await
}
