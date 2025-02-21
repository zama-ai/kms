use kms_grpc::{
    kms::v1::{
        CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse,
        DecryptionResponsePayload, Empty, FheType, InitRequest, KeyGenPreprocRequest,
        KeyGenPreprocStatus, KeyGenPreprocStatusEnum, KeyGenRequest, KeyGenResult,
        ReencryptionRequest, ReencryptionResponse, ReencryptionResponsePayload, RequestId,
        TypedPlaintext, TypedSigncryptedCiphertext, VerifyProvenCtRequest, VerifyProvenCtResponse,
        VerifyProvenCtResponsePayload,
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

impl MockKmsService {
    fn create_mock_handle(handle_index: u8, fhe_type: FheType) -> Vec<u8> {
        // Create a mock keccak256 hash (32 bytes)
        let mut prehandle = vec![0; 32];
        prehandle[..29].copy_from_slice(&[1; 29]); // First 29 bytes of hash
        prehandle[29] = handle_index; // Handle index
        prehandle[30] = fhe_type as u8; // FHE type
        prehandle[31] = 0; // Version (constant 0 for now)
        prehandle
    }
}

#[tonic::async_trait]
impl CoreServiceEndpoint for MockKmsService {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        info!("Received init request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!("Received key_gen_preproc request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_preproc_status(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        info!("Received get_preproc_status request: {:?}", request);
        Ok(Response::new(KeyGenPreprocStatus {
            result: KeyGenPreprocStatusEnum::Finished.into(),
        }))
    }

    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        info!("Received key_gen request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        info!("Received get_key_gen_result request: {:?}", request);
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
        info!("Received insecure_key_gen request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_insecure_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        info!(
            "Received get_insecure_key_gen_result request: {:?}",
            request
        );
        Ok(Response::new(KeyGenResult {
            request_id: Some(RequestId {
                request_id: request.into_inner().request_id,
            }),
            key_results: Default::default(),
        }))
    }

    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        info!("Received crs_gen request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        info!("Received get_crs_gen_result request: {:?}", request);
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
        info!("Received insecure_crs_gen request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_insecure_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        info!(
            "Received get_insecure_crs_gen_result request: {:?}",
            request
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
        info!("Received decrypt request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        info!("Received get_decrypt_result request: {:?}", request);
        let _request_id = request.into_inner().request_id;

        let mock_handle = Self::create_mock_handle(1, FheType::Euint8);

        Ok(Response::new(DecryptionResponse {
            signature: vec![1, 2, 3, 4], // Mock signature
            payload: Some(DecryptionResponsePayload {
                verification_key: vec![5, 6, 7, 8], // Mock verification key
                digest: mock_handle.clone(),        // Using handle format for digest
                plaintexts: vec![TypedPlaintext {
                    bytes: mock_handle.clone(), // Using handle format for data
                    fhe_type: FheType::Euint8 as i32,
                }],
                external_signature: Some(vec![13, 14, 15, 16]), // Mock external signature
            }),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!("Received reencrypt request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        info!("Received get_reencrypt_result request: {:?}", request);
        let _request_id = request.into_inner().request_id;

        let mock_handle = Self::create_mock_handle(2, FheType::Euint8);

        Ok(Response::new(ReencryptionResponse {
            signature: vec![1, 2, 3, 4], // Mock signature
            payload: Some(ReencryptionResponsePayload {
                verification_key: vec![5, 6, 7, 8], // Mock verification key
                digest: mock_handle.clone(),        // Using handle format for digest
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: FheType::Euint8 as i32,
                    signcrypted_ciphertext: mock_handle.clone(), // Using handle format
                    external_handle: mock_handle.clone(),        // Using handle format
                }],
                party_id: 1,
                degree: 2,
                external_signature: vec![13, 14, 15, 16], // Mock external signature
            }),
        }))
    }

    async fn verify_proven_ct(
        &self,
        request: Request<VerifyProvenCtRequest>,
    ) -> Result<Response<Empty>, Status> {
        info!("Received verify_proven_ct request: {:?}", request);
        Ok(Response::new(Empty {}))
    }

    async fn get_verify_proven_ct_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<VerifyProvenCtResponse>, Status> {
        info!(
            "Received get_verify_proven_ct_result request: {:?}",
            request
        );
        let request_id = request.into_inner().request_id;

        let mock_handle = Self::create_mock_handle(3, FheType::Euint8);

        Ok(Response::new(VerifyProvenCtResponse {
            payload: Some(VerifyProvenCtResponsePayload {
                request_id: Some(RequestId { request_id }),
                contract_address: "0x1234567890123456789012345678901234567890".to_string(),
                client_address: "0x0987654321098765432109876543210987654321".to_string(),
                ct_digest: mock_handle.clone(), // Using handle format
                external_signature: vec![13, 14, 15, 16], // Mock external signature
            }),
            signature: vec![1, 2, 3, 4], // Using same signature format
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
