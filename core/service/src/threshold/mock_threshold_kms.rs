use futures_util::FutureExt;
use kms_grpc::rpc_types::{PubDataType, CURRENT_FORMAT_VERSION};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;
use tonic::{transport, Request, Response, Status};

use super::generic::*;
use crate::client::test_tools::ServerHandle;
use crate::consts::DEFAULT_URL;
use crate::util::random_free_port::random_free_ports;
use kms_grpc::kms::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenRequest, KeyGenResult, ReencryptionRequest, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId, SignedPubDataHandle, TypedPlaintext,
    VerifyProvenCtRequest, VerifyProvenCtResponse, VerifyProvenCtResponsePayload,
};

pub async fn setup_mock_kms(n: usize) -> HashMap<u32, ServerHandle> {
    let mut out = HashMap::new();
    let ip_addr = DEFAULT_URL.parse().unwrap();
    let client_ports = random_free_ports(50000, 55000, &ip_addr, n).await.unwrap();
    for i in 1..=n {
        let port = client_ports[i - 1];
        let url = format!("{ip_addr}:{port}");
        let addr = SocketAddr::from_str(url.as_str()).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let kms = new_dummy_threshold_kms();
            let _ = transport::Server::builder()
                .add_service(CoreServiceEndpointServer::new(kms))
                .serve_with_shutdown(addr, rx.map(drop))
                .await;
        });
        out.insert(i as u32, ServerHandle::new(port, handle, tx, None));
    }
    // We need to sleep as the servers keep running in the background and hence do not return
    tokio::time::sleep(tokio::time::Duration::from_secs(2 * (n as u64) / 4)).await;
    out
}

/// This is a mock threshold KMS that doesn't do anything and only
/// returns dummy values on grpc calls.
#[cfg(not(feature = "insecure"))]
type DummyThresholdKms = GenericKms<
    DummyInitiator,
    DummyReencryptor,
    DummyDecryptor,
    DummyKeyGenerator,
    DummyPreprocessor,
    DummyCrsGenerator,
    DummyProvenCtVerifier,
>;

#[cfg(feature = "insecure")]
type DummyThresholdKms = GenericKms<
    DummyInitiator,
    DummyReencryptor,
    DummyDecryptor,
    DummyKeyGenerator,
    DummyKeyGenerator, // the insecure one is the same as the dummy one
    DummyPreprocessor,
    DummyCrsGenerator,
    DummyCrsGenerator, // the insecure one is the same as the dummy one
    DummyProvenCtVerifier,
>;

fn new_dummy_threshold_kms() -> DummyThresholdKms {
    let handle = tokio::spawn(async {});
    DummyThresholdKms::new(
        DummyInitiator {},
        DummyReencryptor { degree: 1 },
        DummyDecryptor {},
        DummyKeyGenerator {},
        #[cfg(feature = "insecure")]
        DummyKeyGenerator {},
        DummyPreprocessor {},
        DummyCrsGenerator {},
        #[cfg(feature = "insecure")]
        DummyCrsGenerator {},
        DummyProvenCtVerifier {},
        Arc::new(TaskTracker::new()), // todo should this be captured in a dummy as well ?
        Arc::new(Mutex::new(HashMap::new())),
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
            fhe_type: kms_grpc::kms::FheType::Euint8.into(),
            signcrypted_ciphertext: "signcrypted_ciphertext".as_bytes().to_vec(),
            party_id: self.degree + 1,
            degree: self.degree,
        };
        Ok(Response::new(ReencryptionResponse {
            signature: vec![1, 2],
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
            signature: vec![1, 2],
            payload: Some(DecryptionResponsePayload {
                version: CURRENT_FORMAT_VERSION,
                verification_key: vec![],
                digest: "dummy digest".as_bytes().to_vec(),
                plaintexts: vec![TypedPlaintext::new(42, kms_grpc::kms::FheType::Euint8)],
                external_signature: Some(vec![23_u8; 65]),
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
            signature: vec![1, 2],
            external_signature: vec![3, 4],
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

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl InsecureKeyGenerator for DummyKeyGenerator {
    async fn insecure_key_gen(
        &self,
        _request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let dummy_info = SignedPubDataHandle {
            key_handle: "12".to_string(),
            signature: vec![1, 2],
            external_signature: vec![3, 4],
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

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl InsecureCrsGenerator for DummyCrsGenerator {
    async fn insecure_crs_gen(
        &self,
        _request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
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

struct DummyProvenCtVerifier;

#[tonic::async_trait]
impl ProvenCtVerifier for DummyProvenCtVerifier {
    async fn verify(
        &self,
        _request: Request<VerifyProvenCtRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<VerifyProvenCtResponse>, Status> {
        let inner = request.into_inner();
        let payload = Some(VerifyProvenCtResponsePayload {
            request_id: Some(inner),
            contract_address: "0xEe344eeDA74E25D746dd1853Bb65C800D1674264".to_string(),
            client_address: "0x355d755538C0310D725b589eA45fB17F320f707B".to_string(),
            ct_digest: "dummy digest".as_bytes().to_vec(),
            external_signature: vec![23_u8; 65],
        });
        Ok(Response::new(VerifyProvenCtResponse {
            payload,
            signature: vec![1, 2],
        }))
    }
}
