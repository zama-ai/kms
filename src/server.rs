use crate::key_setup::DEFAULT_KMS_KEY_PATH;
use ::kms::file_handling::read_element;
use kms::{
    core::kms_core::{KmsKeys, SoftwareKms},
    kms::kms_endpoint_server::KmsEndpointServer,
};
use tonic::transport::Server;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

mod key_setup;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::WARN))
        .init();

    let addr: std::net::SocketAddr = "0.0.0.0:50051".parse()?;
    let keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string())?;
    let kms = SoftwareKms::new(keys.config, keys.fhe_sk, keys.sig_sk);
    tracing::info!("Starting KMS server ...");
    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(addr)
        .await?;
    tracing::info!("Stopping KMS server ...");
    Ok(())
}
