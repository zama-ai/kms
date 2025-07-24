use crate::client::await_server_ready;
use crate::client::test_tools::ServerHandle;
use crate::consts::DEFAULT_URL;
use crate::engine::threshold::threshold_kms::ThresholdKms;
use crate::engine::threshold::traits::{
    BackupOperator, ContextManager, CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator,
    PublicDecryptor, UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use crate::util::random_free_port::get_listeners_random_free_ports;
use futures_util::FutureExt;
use itertools::Itertools;
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocResult,
    KeyGenRequest, KeyGenResult, PublicDecryptionRequest, PublicDecryptionResponse,
    PublicDecryptionResponsePayload, RequestId, SignedPubDataHandle, TypedPlaintext,
    TypedSigncryptedCiphertext, UserDecryptionRequest, UserDecryptionResponse,
    UserDecryptionResponsePayload,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::PubDataType;
use std::collections::HashMap;
use std::sync::Arc;
use tfhe::FheTypes;
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::server::NamedService;
use tonic::{transport, transport::server::TcpIncoming, Request, Response, Status};
use tonic_health::pb::health_server::{Health, HealthServer};

pub async fn setup_mock_kms(n: usize) -> HashMap<u32, ServerHandle> {
    let mut out = HashMap::new();
    let ip_addr = DEFAULT_URL.parse().unwrap();
    let service_listeners = get_listeners_random_free_ports(&ip_addr, n).await.unwrap();
    let mut ports = Vec::new();
    for (i, (service_listener, service_port)) in (1..=n).zip_eq(service_listeners.into_iter()) {
        ports.push(service_port);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (kms, health_service) = new_dummy_threshold_kms().await;
        let arc_kms = Arc::new(kms);
        let arc_kms_clone = Arc::clone(&arc_kms);
        tokio::spawn(async move {
            transport::Server::builder()
                .add_service(health_service)
                .add_service(CoreServiceEndpointServer::from_arc(arc_kms))
                .serve_with_incoming_shutdown(TcpIncoming::from(service_listener), rx.map(drop))
                .await
                .expect("Failed to start mock server {i}");
        });
        out.insert(
            i as u32,
            ServerHandle::new_centralized(arc_kms_clone, service_port, tx),
        );
    }
    for i in 1..=n {
        let service_name = <CoreServiceEndpointServer<DummyThresholdKms> as NamedService>::NAME;
        await_server_ready(service_name, ports[i - 1]).await;
    }
    out
}

/// This is a mock threshold KMS that doesn't do anything and only
/// returns dummy values on grpc calls.
#[cfg(not(feature = "insecure"))]
type DummyThresholdKms = ThresholdKms<
    DummyInitiator,
    DummyUserDecryptor,
    DummyPublicDecryptor,
    DummyKeyGenerator,
    DummyPreprocessor,
    DummyCrsGenerator,
    DummyContextManager,
    DummyBackupOperator,
>;

#[cfg(feature = "insecure")]
type DummyThresholdKms = ThresholdKms<
    DummyInitiator,
    DummyUserDecryptor,
    DummyPublicDecryptor,
    DummyKeyGenerator,
    DummyKeyGenerator, // the insecure one is the same as the dummy one
    DummyPreprocessor,
    DummyCrsGenerator,
    DummyCrsGenerator, // the insecure one is the same as the dummy one
    DummyContextManager,
    DummyBackupOperator,
>;

async fn new_dummy_threshold_kms() -> (DummyThresholdKms, HealthServer<impl Health>) {
    let handle = tokio::spawn(async { Ok(()) });
    let (threshold_health_reporter, threshold_health_service) =
        tonic_health::server::health_reporter();
    threshold_health_reporter
        .set_serving::<CoreServiceEndpointServer<DummyThresholdKms>>()
        .await;
    (
        DummyThresholdKms::new(
            DummyInitiator {},
            DummyUserDecryptor { degree: 1 },
            DummyPublicDecryptor {},
            DummyKeyGenerator {},
            #[cfg(feature = "insecure")]
            DummyKeyGenerator {},
            DummyPreprocessor {},
            DummyCrsGenerator {},
            #[cfg(feature = "insecure")]
            DummyCrsGenerator {},
            DummyContextManager {},
            DummyBackupOperator {},
            Arc::new(TaskTracker::new()),
            Arc::new(RwLock::new(threshold_health_reporter)),
            handle,
        ),
        threshold_health_service,
    )
}

struct DummyInitiator;

#[tonic::async_trait]
impl Initiator for DummyInitiator {
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
}

struct DummyUserDecryptor {
    pub degree: u32,
}

#[tonic::async_trait]
impl UserDecryptor for DummyUserDecryptor {
    async fn user_decrypt(
        &self,
        _request: Request<UserDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<UserDecryptionResponse>, Status> {
        let signcrypted_ciphertexts = vec![TypedSigncryptedCiphertext {
            signcrypted_ciphertext: "signcrypted_ciphertexts".as_bytes().to_vec(),
            fhe_type: FheTypes::Uint8 as i32,
            external_handle: vec![1, 2, 3],
            packing_factor: 1,
        }];
        let payload = UserDecryptionResponsePayload {
            verification_key: vec![],
            digest: "dummy digest".as_bytes().to_vec(),
            signcrypted_ciphertexts,
            party_id: self.degree + 1,
            degree: self.degree,
        };
        Ok(Response::new(UserDecryptionResponse {
            signature: vec![1, 2],
            external_signature: vec![1, 2, 3],
            payload: Some(payload),
        }))
    }
}

struct DummyPublicDecryptor;

#[tonic::async_trait]
impl PublicDecryptor for DummyPublicDecryptor {
    async fn public_decrypt(
        &self,
        _request: Request<PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<PublicDecryptionResponse>, Status> {
        Ok(Response::new(PublicDecryptionResponse {
            signature: vec![1, 2],
            payload: Some(PublicDecryptionResponsePayload {
                verification_key: vec![],
                digest: "dummy digest".as_bytes().to_vec(),
                plaintexts: vec![TypedPlaintext::new(42, FheTypes::Uint8)],
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
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        Ok(Response::new(KeyGenPreprocResult {}))
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

struct DummyContextManager;

#[tonic::async_trait]
impl ContextManager for DummyContextManager {
    async fn new_kms_context(
        &self,
        _request: Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }

    async fn destroy_kms_context(
        &self,
        _request: Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }

    async fn new_custodian_context(
        &self,
        _request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }

    async fn destroy_custodian_context(
        &self,
        _request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }
}

struct DummyBackupOperator;

#[tonic::async_trait]
impl BackupOperator for DummyBackupOperator {
    async fn get_operator_public_key(
        &self,
        _request: Request<kms_grpc::kms::v1::Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::OperatorPublicKey>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::OperatorPublicKey {
            public_key: vec![],
            attestation_document: vec![],
        }))
    }

    async fn custodian_backup_restore(
        &self,
        _request: Request<kms_grpc::kms::v1::Empty>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
        Ok(Response::new(kms_grpc::kms::v1::Empty {}))
    }
}
