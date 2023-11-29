use dummy::DummyKms;
use tonic::transport::Server;

use kms::kms_endpoint_server::KmsEndpointServer;

pub mod kms {
    tonic::include_proto!("kms"); // The string specified here must match the proto package name
}
pub mod dummy;
pub mod types;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let kms = DummyKms::default();

    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(addr)
        .await?;

    Ok(())
}
