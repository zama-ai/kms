use crate::kms::{
    coordinator_endpoint_client::CoordinatorEndpointClient,
    coordinator_endpoint_server::{CoordinatorEndpoint, CoordinatorEndpointServer},
    KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenResult,
};
use crate::kms::{CrsGenRequest, CrsGenResult, Empty, RequestId};
use crate::kms::{
    DecryptionRequest, DecryptionResponse, KeyGenRequest, ReencryptionRequest, ReencryptionResponse,
};
use backoff::{future::retry, ExponentialBackoff};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

pub struct KmsProxy {
    kms_client: Arc<Mutex<CoordinatorEndpointClient<Channel>>>,
}

pub async fn server_handle(server_socket: SocketAddr, client_uri: &str) -> anyhow::Result<()> {
    tracing::info!(
        "Starting KMS proxy on {} for {} ...",
        server_socket.to_string(),
        client_uri.to_string()
    );
    let backoff = ExponentialBackoff::default();
    let kms_client = retry(backoff, || async {
        Ok(CoordinatorEndpointClient::connect(client_uri.to_owned()).await?)
    })
    .await?;
    let kms_proxy = KmsProxy {
        kms_client: Arc::new(Mutex::new(kms_client)),
    };
    Server::builder()
        .add_service(CoordinatorEndpointServer::new(kms_proxy))
        .serve(server_socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl CoordinatorEndpoint for KmsProxy {
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
