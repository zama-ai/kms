use crate::kms::kms_endpoint_client::KmsEndpointClient;
use crate::kms::kms_endpoint_server::{KmsEndpoint, KmsEndpointServer};
use crate::kms::{
    CrsCeremonyRequest, CrsHandle, CrsResponse, DecryptionRequest, DecryptionResponse,
    GetAllKeysRequest, GetAllKeysResponse, GetKeyRequest, KeyGenRequest, KeyResponse,
    ReencryptionRequest, ReencryptionResponse,
};
use backoff::{future::retry, ExponentialBackoff};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

pub struct KmsProxy {
    kms_client: Arc<Mutex<KmsEndpointClient<Channel>>>,
}

pub async fn server_handle(server_socket: SocketAddr, client_uri: &str) -> anyhow::Result<()> {
    tracing::info!(
        "Starting KMS proxy on {} for {} ...",
        server_socket.to_string(),
        client_uri.to_string()
    );
    let backoff = ExponentialBackoff::default();
    let kms_client = retry(backoff, || async {
        Ok(KmsEndpointClient::connect(client_uri.to_owned()).await?)
    })
    .await?;
    let kms_proxy = KmsProxy {
        kms_client: Arc::new(Mutex::new(kms_client)),
    };
    Server::builder()
        .add_service(KmsEndpointServer::new(kms_proxy))
        .serve(server_socket)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl KmsEndpoint for KmsProxy {
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.reencrypt(request).await?;
        Ok(response)
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.decrypt(request).await?;
        Ok(response)
    }

    async fn key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<KeyResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.key_gen(request).await?;
        Ok(response)
    }

    async fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> Result<Response<KeyResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_key(request).await?;
        Ok(response)
    }

    async fn get_all_keys(
        &self,
        request: Request<GetAllKeysRequest>,
    ) -> Result<Response<GetAllKeysResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.get_all_keys(request).await?;
        Ok(response)
    }

    async fn crs_ceremony(
        &self,
        request: Request<CrsCeremonyRequest>,
    ) -> Result<Response<CrsResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.crs_ceremony(request).await?;
        Ok(response)
    }

    async fn crs_request(
        &self,
        request: Request<CrsHandle>,
    ) -> Result<Response<CrsResponse>, Status> {
        let mut kms_client = self.kms_client.lock().await;
        let response = kms_client.crs_request(request).await?;
        Ok(response)
    }
}
