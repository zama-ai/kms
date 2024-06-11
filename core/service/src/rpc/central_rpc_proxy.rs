use crate::kms::core_service_endpoint_client::CoreServiceEndpointClient;
use crate::kms::core_service_endpoint_server::{CoreServiceEndpoint, CoreServiceEndpointServer};
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, Empty, InitRequest,
    KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenRequest, KeyGenResult, ReencryptionRequest,
    ReencryptionResponse, RequestId,
};
use backoff::future::retry;
use backoff::ExponentialBackoff;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

use super::central_rpc::CentralizedConfigNoStorage;

pub struct KmsProxy {
    kms_client: Arc<Mutex<CoreServiceEndpointClient<Channel>>>,
}

pub async fn server_handle(
    config: CentralizedConfigNoStorage,
    client_uri: &str,
) -> anyhow::Result<()> {
    let server_socket = config.get_socket_addr()?;
    tracing::info!(
        "Starting KMS proxy on {} for {} ...",
        server_socket.to_string(),
        client_uri.to_string()
    );
    let backoff = ExponentialBackoff::default();
    let kms_client = retry(backoff, || async {
        Ok(CoreServiceEndpointClient::connect(client_uri.to_owned()).await?)
    })
    .await?;
    let kms_proxy = KmsProxy {
        kms_client: Arc::new(Mutex::new(kms_client)),
    };
    Server::builder()
        .add_service(CoreServiceEndpointServer::new(kms_proxy))
        .serve(server_socket)
        .await?;
    Ok(())
}

/// Implements all KMS endpoints by relaying all requests and responses to/from another KMS server
/// unchanged. The use case of the KMS proxy is to allow a KMS server running in a Nitro enclave to
/// communicate with the outside world.
#[tonic::async_trait]
impl CoreServiceEndpoint for KmsProxy {
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.init(request).await?;
        Ok(response)
    }

    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.key_gen_preproc(request).await?;
        Ok(response)
    }

    async fn get_preproc_status(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_preproc_status(request).await?;
        Ok(response)
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.reencrypt(request).await?;
        Ok(response)
    }

    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_reencrypt_result(request).await?;
        Ok(response)
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.decrypt(request).await?;
        Ok(response)
    }

    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_decrypt_result(request).await?;
        Ok(response)
    }

    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.key_gen(request).await?;
        Ok(response)
    }

    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_key_gen_result(request).await?;
        Ok(response)
    }

    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.crs_gen(request).await?;
        Ok(response)
    }

    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_crs_gen_result(request).await?;
        Ok(response)
    }
}
