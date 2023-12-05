use ::kms::file_handling::read_element;
use kms::{
    core::kms_core::{KmsKeys, SoftwareKms},
    kms::kms_endpoint_server::KmsEndpointServer,
};
use tonic::transport::Server;

pub const DEFAULT_KMS_KEY_PATH: &str = "temp/kms-keys.bin";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string())?;
    let kms = SoftwareKms::new(keys.config, keys.fhe_sk, keys.sig_sk);

    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(addr)
        .await?;

    Ok(())
}
