use kms_connector::kms_core_adapter::service::kms::v1::{
    kms_service_server::{KmsService, KmsServiceServer},
    DecryptionRequest, DecryptionResponse, DecryptionResponsePayload, ReencryptionRequest,
    ReencryptionResponse, ReencryptionResponsePayload, TypedCiphertext,
};
use std::net::SocketAddr;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Default)]
pub struct MockKmsService {}

#[tonic::async_trait]
impl KmsService for MockKmsService {
    async fn request_decryption(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        info!("Received decryption request: {:?}", request);

        // Mock successful decryption
        Ok(Response::new(DecryptionResponse {
            request_id: request.into_inner().request_id,
            payload: Some(DecryptionResponsePayload {
                decrypted_result: vec![1, 2, 3, 4],    // Mock decrypted data
                verification_key: vec![9, 10, 11, 12], // Mock verification key
                digest: vec![13, 14, 15, 16],          // Mock digest
                signatures: vec![vec![5, 6, 7, 8]],    // Mock signatures
            }),
        }))
    }

    async fn request_reencryption(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        info!("Received reencryption request: {:?}", request);

        // Mock successful reencryption
        Ok(Response::new(ReencryptionResponse {
            request_id: request.into_inner().request_id,
            payload: Some(ReencryptionResponsePayload {
                ciphertext: Some(TypedCiphertext {
                    bytes: vec![1, 2, 3, 4], // Mock ciphertext
                    fhe_type: 1,             // Mock FHE type
                }),
                verification_key: vec![9, 10, 11, 12], // Mock verification key
                digest: vec![13, 14, 15, 16],          // Mock digest
                signatures: vec![vec![5, 6, 7, 8]],    // Mock signatures
                fhe_type: 1,                           // Mock FHE type
            }),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .compact()
        .init();

    let addr: SocketAddr = "[::1]:50052".parse()?;
    let svc = MockKmsService::default();

    info!("Starting mock KMS Core server on {}", addr);

    Server::builder()
        .add_service(KmsServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
