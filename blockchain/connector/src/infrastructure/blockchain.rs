use crate::conf::BlockchainConfig;
use crate::domain::blockchain::{Blockchain, KmsOperationResponse};
use crate::infrastructure::metrics::{MetricType, Metrics};
use async_trait::async_trait;
use events::kms::{KmsEvent, KmsEventMessage, OperationValue};
use kms_blockchain_client::client::{Client, ClientBuilder};
use kms_blockchain_client::query_client::{QueryClient, QueryClientBuilder};
use retrying::retry;
use std::sync::Arc;
use tokio::sync::Mutex;
use typed_builder::TypedBuilder;

use super::metrics::OpenTelemetryMetrics;

#[derive(Clone, TypedBuilder)]
pub struct KmsBlockchain {
    client: Arc<Mutex<Client>>,
    query_client: Arc<Mutex<QueryClient>>,
    config: BlockchainConfig,
    metrics: Arc<OpenTelemetryMetrics>,
}

impl KmsBlockchain {
    pub async fn new(
        config: BlockchainConfig,
        metrics: OpenTelemetryMetrics,
    ) -> Result<Self, anyhow::Error> {
        let client: Client = ClientBuilder::builder()
            .contract_address(&config.contract)
            .grpc_addresses(config.grpc_addresses())
            .coin_denom(&config.fee.denom)
            .mnemonic_wallet(config.signkey.mnemonic.as_deref())
            .bip32_private_key(config.signkey.bip32.as_deref())
            .build()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Error creating blockchain client {:?}", e))?;

        let query_client: QueryClient = QueryClientBuilder::builder()
            .grpc_addresses(config.grpc_addresses())
            .build()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Error creating blockchain query client {:?}", e))?;
        Ok(KmsBlockchain {
            client: Arc::new(Mutex::new(client)),
            query_client: Arc::new(Mutex::new(query_client)),
            config,
            metrics: Arc::new(metrics),
        })
    }

    #[retry(stop=(attempts(4)|duration(10)),wait=fixed(2))]
    async fn call_execute_contract(
        &self,
        client: &mut Client,
        msg: &[u8],
        amount_fee: u64,
    ) -> anyhow::Result<()> {
        client
            .execute_contract(msg, amount_fee)
            .await
            .map(|_| ())
            .map_err(|e| e.into())
    }
}

#[async_trait]
impl Blockchain for KmsBlockchain {
    #[tracing::instrument(skip(self, result), fields(tx_id = %result.txn_id_hex()))]
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()> {
        let mut client = self.client.lock().await;
        let msg_str: KmsEventMessage = result.into();
        let msg_str = msg_str
            .to_json()
            .map_err(|e| {
                self.metrics.increment(
                    MetricType::BlockchainError,
                    1,
                    &[("error", &e.to_string())],
                );
                e
            })?
            .to_string();
        tracing::info!("Sending result to contract: {:?}", msg_str);
        self.call_execute_contract(&mut client, msg_str.as_bytes(), self.config.fee.amount)
            .await
            .map_err(|e| {
                self.metrics.increment(
                    MetricType::BlockchainError,
                    1,
                    &[("error", &e.to_string())],
                );
                e
            })
    }

    #[tracing::instrument(skip(self))]
    async fn get_operation_value(&self, event: &KmsEvent) -> anyhow::Result<OperationValue> {
        let query_client = self.query_client.lock().await;
        let query = serde_json::json!({
            "get_operations_value": {
                "event": event
            }
        });
        let result = query_client
            .query_contract(
                self.config.contract.to_owned(),
                query.to_string().as_bytes(),
            )
            .await
            .map(|msg| serde_json::from_slice::<Vec<OperationValue>>(&msg))??;
        result
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Operation value not found for tx_id: {:?}", event))
    }
}
