use super::metrics::OpenTelemetryMetrics;
use crate::conf::OracleConfig;
use crate::domain::oracle::Oracle;
use events::kms::KmsEvent;
use tokio::time::Duration;
use tonic::transport::{Channel, Endpoint};

#[derive(Clone)]
pub struct OracleClient {
    _channel: Channel,
    _metrics: OpenTelemetryMetrics,
}

impl OracleClient {
    pub async fn new(config: OracleConfig, metrics: OpenTelemetryMetrics) -> anyhow::Result<Self> {
        if config.addresses.is_empty() {
            return Err(anyhow::anyhow!("No addresses provided for Oracle"));
        }
        let endpoints = config
            .addresses
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| anyhow::anyhow!("Error connecting to Oracle {:?}", e))?;

        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let channel = Channel::balance_list(endpoints);

        Ok(Self {
            _channel: channel,
            _metrics: metrics,
        })
    }
}

#[async_trait::async_trait]
impl Oracle for OracleClient {
    async fn respond(&self, _event: KmsEvent) -> anyhow::Result<()> {
        // TODO
        //   let client = OracleServiceClient::new(self.channel.clone());
        //   let request = tonic::Request::new(OracleRequest { event: Some(event) });
        //   let response = client.respond(request).await?;
        //   self.metrics.increment(MetricType::OracleResponse, 1, &[]);

        //   tracing::info!("Oracle response: {:?}", response);
        //   Ok(())
        Ok(())
    }
}
