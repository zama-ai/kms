use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;

use bincode::serialize;
use tokio::task::JoinHandle;
use tonic::{transport, Request, Response, Status};

use super::generic::*;
use crate::consts::{BASE_PORT, DEFAULT_URL};
use crate::kms::core_service_endpoint_server::CoreServiceEndpointServer;
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenRequest, KeyGenResult, ReencryptionRequest, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId, SignedPubDataHandle,
};
use crate::rpc::rpc_types::{Plaintext, PubDataType, CURRENT_FORMAT_VERSION};

pub async fn setup_mock_kms(n: usize) -> HashMap<u32, JoinHandle<()>> {
    let mut out = HashMap::new();
    for i in 1..=n {
        let port = BASE_PORT + (i as u16) * 100;
        let url = format!("{DEFAULT_URL}:{}", port);
        let addr = SocketAddr::from_str(url.as_str()).unwrap();
        let handle = tokio::spawn(async move {
            let kms = new_dummy_threshold_kms();
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
type DummyThresholdKms = GenericKms<
    DummyInitiator,
    DummyReencryptor,
    DummyDecryptor,
    DummyKeyGenerator,
    DummyPreprocessor,
    DummyCrsGenerator,
>;

fn new_dummy_threshold_kms() -> DummyThresholdKms {
    let handle = tokio::spawn(async {});
    DummyThresholdKms::new(
        DummyInitiator {},
        DummyReencryptor { degree: 1 },
        DummyDecryptor {},
        DummyKeyGenerator {},
        DummyPreprocessor {},
        DummyCrsGenerator {},
        handle.abort_handle(),
    )
}

struct DummyInitiator;

#[tonic::async_trait]
impl Initiator for DummyInitiator {
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
}

struct DummyReencryptor {
    pub degree: u32,
}

#[tonic::async_trait]
impl Reencryptor for DummyReencryptor {
    async fn reencrypt(
        &self,
        _request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let payload = ReencryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            verification_key: vec![],
            digest: "dummy digest".as_bytes().to_vec(),
            fhe_type: crate::kms::FheType::Euint8.into(),
            signcrypted_ciphertext: "signcrypted_ciphertext".as_bytes().to_vec(),
            party_id: self.degree + 1,
            degree: self.degree,
        };
        Ok(Response::new(ReencryptionResponse {
            signature: vec![],
            payload: Some(payload),
        }))
    }
}

struct DummyDecryptor;

#[tonic::async_trait]
impl Decryptor for DummyDecryptor {
    async fn decrypt(
        &self,
        _request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        Ok(Response::new(DecryptionResponse {
            signature: vec![],
            payload: Some(DecryptionResponsePayload {
                version: CURRENT_FORMAT_VERSION,
                verification_key: vec![],
                digest: "dummy digest".as_bytes().to_vec(),
                plaintexts: vec![
                    serialize(&Plaintext::new(42, crate::kms::FheType::Euint8)).unwrap()
                ],
            }),
        }))
    }
}

struct DummyKeyGenerator;

#[tonic::async_trait]
impl KeyGenerator for DummyKeyGenerator {
    async fn key_gen(&self, _request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
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
}

struct DummyPreprocessor;
#[tonic::async_trait]
impl KeyGenPreprocessor for DummyPreprocessor {
    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
    async fn get_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        Ok(Response::new(KeyGenPreprocStatus {
            result: KeyGenPreprocStatusEnum::Finished as i32,
        }))
    }
}

struct DummyCrsGenerator;

#[tonic::async_trait]
impl CrsGenerator for DummyCrsGenerator {
    async fn crs_gen(&self, _request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        Ok(Response::new(CrsGenResult {
            request_id: Some(request.into_inner()),
            crs_results: Some(SignedPubDataHandle::default()),
        }))
    }
}
