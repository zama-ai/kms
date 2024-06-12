use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;

use tokio::task::JoinHandle;
use tonic::{transport, Request, Response, Status};

use crate::consts::{BASE_PORT, DEFAULT_URL};
use crate::kms::core_service_endpoint_server::{CoreServiceEndpoint, CoreServiceEndpointServer};
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenRequest, KeyGenResult, ReencryptionRequest, ReencryptionResponse, RequestId,
    SignedPubDataHandle,
};
use crate::rpc::rpc_types::{Plaintext, PubDataType, CURRENT_FORMAT_VERSION};

pub async fn setup_mock_kms(n: usize) -> HashMap<u32, JoinHandle<()>> {
    let mut out = HashMap::new();
    for i in 1..=n {
        let port = BASE_PORT + (i as u16) * 100;
        let url = format!("{DEFAULT_URL}:{}", port);
        let addr = SocketAddr::from_str(url.as_str()).unwrap();
        let handle = tokio::spawn(async move {
            let kms = MockThresholdKms::default();
            let _ = transport::Server::builder()
                .add_service(CoreServiceEndpointServer::new(kms))
                .serve(addr)
                .await;
        });
        out.insert(i as u32, handle);
    }
    // We need to sleep as the servers keep running in the background and hence do not return
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    out
}

/// This is a mock threshold KMS that doesn't do anything and only
/// returns dummy values on grpc calls.
#[derive(Default)]
pub struct MockThresholdKms {}

#[tonic::async_trait]
impl CoreServiceEndpoint for MockThresholdKms {
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_preproc_status(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        Ok(Response::new(KeyGenPreprocStatus {
            result: KeyGenPreprocStatusEnum::Finished as i32,
        }))
    }

    async fn key_gen(&self, _request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let dummy_info = SignedPubDataHandle {
            key_handle: "12".to_string(),
            signature: vec![3, 4],
        };

        let pk = PubDataType::PublicKey;
        let sk = PubDataType::ServerKey;
        Ok(Response::new(KeyGenResult {
            request_id: Some(request.into_inner()),
            key_results: HashMap::from_iter(vec![
                (pk.to_string(), dummy_info.clone()),
                (sk.to_string(), dummy_info),
            ]),
        }))
    }

    async fn reencrypt(
        &self,
        _request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_reencrypt_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: 0,
            verification_key: vec![],
            digest: "dummy digest".as_bytes().to_vec(),
            fhe_type: crate::kms::FheType::Euint8.into(),
            signcrypted_ciphertext: "signcrypted_ciphertext".as_bytes().to_vec(),
        }))
    }

    async fn decrypt(
        &self,
        _request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_decrypt_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        Ok(Response::new(DecryptionResponse {
            signature: vec![],
            payload: Some(DecryptionResponsePayload {
                version: CURRENT_FORMAT_VERSION,
                servers_needed: 0,
                verification_key: vec![],
                digest: "dummy digest".as_bytes().to_vec(),
                plaintext: serde_asn1_der::to_vec(&Plaintext::new(42, crate::kms::FheType::Euint8))
                    .unwrap(),
            }),
        }))
    }

    async fn crs_gen(&self, _request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        Ok(Response::new(CrsGenResult {
            request_id: Some(request.into_inner()),
            crs_results: Some(SignedPubDataHandle::default()),
        }))
    }
}
