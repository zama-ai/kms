use kms_grpc::{
    kms::v1::{
        CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse,
        DecryptionResponsePayload, Empty, FheType, InitRequest, KeyGenPreprocRequest,
        KeyGenPreprocResult, KeyGenRequest, KeyGenResult, ReencryptionRequest,
        ReencryptionResponse, ReencryptionResponsePayload, RequestId, TypedPlaintext,
        TypedSigncryptedCiphertext,
    },
    kms_service::v1::core_service_endpoint_server::{
        CoreServiceEndpoint, CoreServiceEndpointServer,
    },
};
use std::net::SocketAddr;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Default)]
pub struct MockKmsService {}

#[tonic::async_trait]
impl CoreServiceEndpoint for MockKmsService {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        info!(
            operation = "init",
            request_id = ?request.get_ref().config,
            "Processing initialization request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!(
            operation = "key_gen_preproc",
            request_id = ?request.get_ref().request_id,
            "Processing key generation preprocessing request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_key_gen_preproc_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        info!(
            operation = "get_key_gen_preproc_result",
            request_id = ?request.get_ref().request_id,
            "Checking preprocessing status"
        );
        Ok(Response::new(KeyGenPreprocResult {}))
    }

    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        info!(
            operation = "key_gen",
            request_id = ?request.get_ref().request_id,
            "Processing key generation request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        info!(
            operation = "get_key_gen_result",
            request_id = ?request.get_ref().request_id,
            "Retrieving key generation results"
        );
        Ok(Response::new(KeyGenResult {
            request_id: Some(RequestId {
                request_id: request.into_inner().request_id,
            }),
            key_results: Default::default(),
        }))
    }

    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!(
            operation = "insecure_key_gen",
            request_id = ?request.get_ref().request_id,
            "Processing insecure key generation request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_insecure_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        info!(
            operation = "get_insecure_key_gen_result",
            request_id = ?request.get_ref().request_id,
            "Retrieving insecure key generation results"
        );
        Ok(Response::new(KeyGenResult {
            request_id: Some(RequestId {
                request_id: request.into_inner().request_id,
            }),
            key_results: Default::default(),
        }))
    }

    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        info!(
            operation = "crs_gen",
            request_id = ?request.get_ref().request_id,
            "Processing CRS generation request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        info!(
            operation = "get_crs_gen_result",
            request_id = ?request.get_ref().request_id,
            "Retrieving CRS generation results"
        );
        Ok(Response::new(CrsGenResult {
            request_id: Some(RequestId {
                request_id: request.into_inner().request_id,
            }),
            crs_results: None,
        }))
    }

    async fn insecure_crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!(
            operation = "insecure_crs_gen",
            request_id = ?request.get_ref().request_id,
            "Processing insecure CRS generation request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_insecure_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        info!(
            operation = "get_insecure_crs_gen_result",
            request_id = ?request.get_ref().request_id,
            "Retrieving insecure CRS generation results"
        );
        Ok(Response::new(CrsGenResult {
            request_id: Some(RequestId {
                request_id: request.into_inner().request_id,
            }),
            crs_results: None,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!(
            operation = "decrypt",
            request_id = ?request.get_ref().request_id,
            num_ciphertexts = request.get_ref().ciphertexts.len(),
            "Processing decryption request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        info!(
            operation = "get_decrypt_result",
            request_id = ?request.get_ref().request_id,
            "Retrieving decryption results"
        );

        let result_bytes = vec![1, 2, 3, 4]; // Simple mock result

        // Mock Core's signature on the payload (256 bytes to simulate a strong cryptographic signature)
        let payload_signature = vec![0x42; 256];

        // Mock EIP-712 signature for blockchain (65 bytes: r[32] + s[32] + v[1])
        let mut eip712_signature = vec![0x19; 65];
        eip712_signature[64] = 27; // v value is either 27 or 28

        Ok(Response::new(DecryptionResponse {
            signature: payload_signature, // Core's signature on the payload
            payload: Some(DecryptionResponsePayload {
                verification_key: vec![],
                digest: result_bytes.clone(),
                plaintexts: vec![TypedPlaintext {
                    bytes: result_bytes,
                    fhe_type: FheType::Euint8 as i32,
                }],
                external_signature: Some(eip712_signature), // EIP-712 signature for blockchain
            }),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!(
            operation = "reencrypt",
            request_id = ?request.get_ref().request_id,
            "Processing reencryption request"
        );
        Ok(Response::new(Empty {}))
    }

    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        info!(
            operation = "get_reencrypt_result",
            request_id = ?request.get_ref().request_id,
            "Retrieving reencryption results"
        );

        let result_bytes = vec![9, 10, 11, 12]; // Simple mock result

        // Mock Core's signature on the payload (256 bytes to simulate a strong cryptographic signature)
        let payload_signature = vec![0x42; 256];

        // Mock EIP-712 signature for blockchain (65 bytes: r[32] + s[32] + v[1])
        let mut eip712_signature = vec![0x19; 65];
        eip712_signature[64] = 28; // v value is either 27 or 28

        Ok(Response::new(ReencryptionResponse {
            signature: payload_signature,         // Core's signature on the payload
            external_signature: eip712_signature, // EIP-712 signature for blockchain (not optional for reencryption)
            payload: Some(ReencryptionResponsePayload {
                verification_key: vec![],
                digest: result_bytes.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    signcrypted_ciphertext: result_bytes.clone(),
                    external_handle: result_bytes,
                    fhe_type: FheType::Euint8 as i32,
                }],
                party_id: 1,
                degree: 1,
            }),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .compact()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .with_thread_names(false)
        .with_ansi(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .init();

    let addr = "[::1]:50052".parse::<SocketAddr>()?;
    let svc = MockKmsService::default();

    info!("Starting mock KMS Core server on {}", addr);

    Server::builder()
        .add_service(CoreServiceEndpointServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
