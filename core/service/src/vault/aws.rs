use aws_config::{
    default_provider::credentials::DefaultCredentialsChain, imds::client::Client as IMDSClient,
    Region, SdkConfig,
};
use url::Url;

/// Given the address of a vsock-to-TCP proxy, constructs an AWS SDK configuration for requesting AWS credentials inside of a Nitro enclave.
pub async fn build_aws_sdk_config(
    aws_region: String,
    aws_imds_endpoint: Option<Url>,
    aws_sts_endpoint: Option<Url>,
) -> SdkConfig {
    let config_loader = match aws_imds_endpoint {
        Some(p) => {
            let imds_client = IMDSClient::builder()
                .endpoint(p)
                .expect("AWS IMDS endpoint invalid")
                .build();
            let credentials_provider = DefaultCredentialsChain::builder()
                .imds_client(imds_client)
                .build()
                .await;
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .credentials_provider(credentials_provider)
                .endpoint_url(aws_sts_endpoint.expect("AWS STS endpoint must be set"))
        }
        None => aws_config::defaults(aws_config::BehaviorVersion::latest()),
    };
    config_loader.region(Region::new(aws_region)).load().await
}
