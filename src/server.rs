use ::kms::file_handling::read_element;
use kms::{
    core::dummy::{DummyKms, KmsKeys, DEFAULT_KMS_KEY_PATH},
    kms::kms_endpoint_server::KmsEndpointServer,
};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string())?;
    let kms = DummyKms::new(keys.config, keys.fhe_sk, keys.sig_sk);

    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(addr)
        .await?;

    Ok(())
}
