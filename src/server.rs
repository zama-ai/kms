use ::kms::file_handling::{read_as_json, read_element};
use dummy::{DummyKms, KmsKeys, DEFAULT_KEY_PATH};
use kms::kms_endpoint_server::KmsEndpointServer;
use tonic::transport::Server;

pub mod kms {
    tonic::include_proto!("kms"); // The string specified here must match the proto package name
}
pub mod dummy;
pub mod types;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let keys: KmsKeys = read_element(DEFAULT_KEY_PATH.to_string())?;
    let kms = DummyKms::new(keys.config, keys.fhe_sk, keys.sig_sk);

    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(addr)
        .await?;

    Ok(())
}
