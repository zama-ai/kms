use anyhow::{Context, Result};
use kms_grpc::kms::v1::{
    Empty, HealthStatusResponse, KeyMaterialAvailabilityResponse, OperatorPublicKey,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use std::time::{Duration, Instant};
use tonic::transport::Channel;

pub struct GrpcHealthClient {
    endpoint: String,
}

impl GrpcHealthClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        // Add http:// prefix if not present
        let endpoint = if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            format!("http://{}", endpoint)
        } else {
            endpoint
        };
        Self { endpoint }
    }

    /// Test basic connectivity to the KMS endpoint
    pub async fn test_connectivity(&self) -> Result<Duration> {
        let start = Instant::now();
        let channel = Channel::from_shared(self.endpoint.clone())
            .context("Invalid endpoint URL")?
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .context("Failed to connect to KMS endpoint")?;

        let _client = CoreServiceEndpointClient::new(channel.clone());
        Ok(start.elapsed())
    }

    /// Get available key material from KMS
    pub async fn get_key_material_availability(&self) -> Result<KeyMaterialAvailabilityResponse> {
        let channel = Channel::from_shared(self.endpoint.clone())?
            .timeout(Duration::from_secs(10))
            .connect()
            .await?;

        let mut client = CoreServiceEndpointClient::new(channel.clone());
        let response = client.get_key_material_availability(Empty {}).await?;
        Ok(response.into_inner())
    }

    /// Get operator public key from KMS
    pub async fn get_operator_public_key(&self) -> Result<OperatorPublicKey> {
        let channel = Channel::from_shared(self.endpoint.clone())?
            .timeout(Duration::from_secs(10))
            .connect()
            .await?;

        let mut client = CoreServiceEndpointClient::new(channel.clone());
        let response = client.get_operator_public_key(Empty {}).await?;
        Ok(response.into_inner())
    }

    /// Get comprehensive health status including peer health
    pub async fn get_health_status(&self) -> Result<HealthStatusResponse> {
        let channel = Channel::from_shared(self.endpoint.clone())?
            .timeout(Duration::from_secs(10))
            .connect()
            .await?;

        let mut client = CoreServiceEndpointClient::new(channel.clone());
        let response = client.get_health_status(Empty {}).await?;
        Ok(response.into_inner())
    }
}
