use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tonic::{transport::Channel, Request, Response, Status};
use tracing::{error, info};

use crate::error::Result;

pub mod kms {
    pub mod v1 {
        tonic::include_proto!("kms.v1");
    }
}

use kms::v1::{DecryptionRequest, DecryptionResponse, ReencryptionRequest, ReencryptionResponse};

#[tonic::async_trait]
pub trait KmsService {
    async fn request_decryption(
        &self,
        request: Request<DecryptionRequest>,
    ) -> std::result::Result<Response<DecryptionResponse>, Status>;

    async fn request_reencryption(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> std::result::Result<Response<ReencryptionResponse>, Status>;
}

const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct KmsServiceImpl {
    kms_core_endpoint: String,
    running: Arc<AtomicBool>,
    client: Arc<tokio::sync::Mutex<Option<kms::v1::kms_service_client::KmsServiceClient<Channel>>>>,
}

impl KmsServiceImpl {
    /// Create a new KMS service instance
    pub fn new(kms_core_endpoint: &str) -> Self {
        Self {
            kms_core_endpoint: kms_core_endpoint.to_string(),
            running: Arc::new(AtomicBool::new(true)),
            client: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Initialize the KMS client connection
    pub async fn initialize(&self) -> Result<()> {
        let channel = Channel::from_shared(self.kms_core_endpoint.clone())
            .map_err(|e| crate::error::Error::Transport(e.to_string()))?
            .connect()
            .await
            .map_err(|e| crate::error::Error::Transport(e.to_string()))?;

        let mut client_guard = self.client.lock().await;
        *client_guard = Some(kms::v1::kms_service_client::KmsServiceClient::new(channel));
        info!("Connected to KMS-core at {}", self.kms_core_endpoint);
        Ok(())
    }

    /// Get a client, attempting to reconnect if necessary
    async fn get_client(&self) -> Result<kms::v1::kms_service_client::KmsServiceClient<Channel>> {
        loop {
            {
                let client_guard = self.client.lock().await;
                if let Some(client) = client_guard.clone() {
                    return Ok(client);
                }
            }

            // No client available, try to connect
            match self.initialize().await {
                Ok(_) => continue, // Client is now initialized, try to get it
                Err(e) => {
                    error!("Failed to connect to KMS-core: {}, retrying...", e);
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }

            if !self.running.load(Ordering::SeqCst) {
                return Err(crate::error::Error::Transport(
                    "KMS service is shutting down".to_string(),
                ));
            }
        }
    }
}

#[tonic::async_trait]
impl KmsService for KmsServiceImpl {
    async fn request_decryption(
        &self,
        request: Request<DecryptionRequest>,
    ) -> std::result::Result<Response<DecryptionResponse>, Status> {
        // Extract the inner request data
        let inner_request = request.into_inner();

        loop {
            match self.get_client().await {
                Ok(mut client) => {
                    // Create a new request with the cloned inner data
                    let new_request = Request::new(inner_request.clone());
                    match client.request_decryption(new_request).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            error!("Failed to process decryption request: {}, retrying...", e);
                            // Clear the client so we'll try to reconnect
                            *self.client.lock().await = None;
                            tokio::time::sleep(RETRY_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get KMS client: {}, retrying...", e);
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }

            if !self.running.load(Ordering::SeqCst) {
                return Err(Status::unavailable("KMS service is shutting down"));
            }
        }
    }

    async fn request_reencryption(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> std::result::Result<Response<ReencryptionResponse>, Status> {
        // Extract the inner request data
        let inner_request = request.into_inner();

        loop {
            match self.get_client().await {
                Ok(mut client) => {
                    // Create a new request with the cloned inner data
                    let new_request = Request::new(inner_request.clone());
                    match client.request_reencryption(new_request).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            error!("Failed to process reencryption request: {}, retrying...", e);
                            // Clear the client so we'll try to reconnect
                            *self.client.lock().await = None;
                            tokio::time::sleep(RETRY_DELAY).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get KMS client: {}, retrying...", e);
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }

            if !self.running.load(Ordering::SeqCst) {
                return Err(Status::unavailable("KMS service is shutting down"));
            }
        }
    }
}

impl KmsServiceImpl {
    /// Stop the KMS service
    pub fn stop(&self) {
        info!("Stopping KMS service...");
        self.running.store(false, Ordering::SeqCst);
    }
}
