use super::metrics::OpenTelemetryMetrics;
use crate::conf::BlockchainConfig;
use crate::domain::blockchain::{Blockchain, KmsOperationResponse};
use crate::infrastructure::metrics::{MetricType, Metrics};
use async_trait::async_trait;
use events::kms::{KmsCoreConf, KmsEvent, KmsMessage, OperationValue};
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest};
use kms_blockchain_client::query_client::{
    ContractQuery, EventQuery, QueryClient, QueryClientBuilder, QueryContractRequest,
};
use retrying::retry;
use std::sync::Arc;
use tokio::sync::Mutex;
use typed_builder::TypedBuilder;

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
            .kv_store_address(config.kv_store_address.as_deref())
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
        request: &ExecuteContractRequest,
    ) -> anyhow::Result<()> {
        client
            .execute_contract(request.clone())
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
        let msg_str: KmsMessage = result.into();
        let request = ExecuteContractRequest::builder()
            .message(msg_str)
            .gas_limit(self.config.fee.amount)
            .build();
        tracing::info!("Sending result to contract: {:?}", request);
        self.call_execute_contract(&mut client, &request)
            .await
            .inspect_err(|e| {
                self.metrics.increment(
                    MetricType::BlockchainError,
                    1,
                    &[("error", &e.to_string())],
                );
            })
    }

    #[tracing::instrument(skip(self))]
    async fn get_operation_value(&self, event: &KmsEvent) -> anyhow::Result<OperationValue> {
        let query_client = self.query_client.lock().await;
        let request = QueryContractRequest::builder()
            .contract_address(self.config.contract.to_owned())
            .query(ContractQuery::GetOperationsValue(
                EventQuery::builder().event(event.clone()).build(),
            ))
            .build();
        let result: Vec<OperationValue> = query_client.query_contract(request).await?;
        result
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Operation value not found for tx_id: {:?}", event))
    }

    #[tracing::instrument(skip(self))]
    async fn get_config_contract(&self) -> anyhow::Result<KmsCoreConf> {
        let query_client = self.query_client.lock().await;
        let request = QueryContractRequest::builder()
            .contract_address(self.config.contract.to_owned())
            .query(ContractQuery::GetKmsCoreConf {})
            .build();
        let result = query_client.query_contract(request).await?;
        Ok(result)
    }
}
