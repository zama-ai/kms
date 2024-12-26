use super::metrics::OpenTelemetryMetrics;
use crate::conf::BlockchainConfig;
use crate::domain::blockchain::{Blockchain, KmsOperationResponse};
use crate::infrastructure::metrics::{MetricType, Metrics};
use async_trait::async_trait;
use events::kms::{FheParameter, KmsEvent, KmsMessage, OperationValue};
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest};
use kms_blockchain_client::errors::Error;
use kms_blockchain_client::query_client::{
    AscQuery, CscQuery, EventQuery, QueryClient, QueryClientBuilder,
};
use kms_common::retry_fatal_loop;
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
            .asc_address(&config.asc_address)
            .csc_address(&config.csc_address)
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

    async fn call_execute_contract(
        &self,
        client: &mut Client,
        request: &ExecuteContractRequest,
    ) -> anyhow::Result<()> {
        // Try to post to the contract with a retry loop executing at most 4 times with 2 seconds sleep between each try
        retry_fatal_loop!(
            || async {
                match client.execute_contract(request.clone()).await {
                    Ok(resp) => {
                        tracing::info!("KMS contract execution returned the message: {:?}", resp);
                        Ok(())
                    }
                    Err(error) => {
                        if let Error::ExecutionContractError(inner_err) = &error {
                            let no_transaction = "No transaction response received";
                            // In case of no transaction response, we can retry
                            if inner_err.contains(no_transaction) {
                                return Err(LoopErr::Transient(anyhow::anyhow!(no_transaction)));
                            }
                        }
                        // In all other cases we break the loop and log the error
                        let fatal_msg =
                            format!("Fatal error while sending to contract: {:?}", &error);
                        Err(LoopErr::Fatal(anyhow::anyhow!(fatal_msg)))
                    }
                }
            },
            2000,
            4
        )
        .map_err(|e| anyhow::anyhow!("Error while sending to contract: {e}"))
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
                tracing::error!("Error while sending to contract: {e}");
                self.metrics.increment(
                    MetricType::BlockchainError,
                    1,
                    &[("error", &e.to_string())],
                );
            })
    }

    /// Get all the operation values associated with a given event (operation type + transaction ID) from the ASC
    #[tracing::instrument(skip(self))]
    async fn get_operation_value(&self, event: &KmsEvent) -> anyhow::Result<OperationValue> {
        let result: Vec<OperationValue> = {
            let query_client = self.query_client.lock().await;
            query_client
                .query_asc(
                    self.config.asc_address.to_owned(),
                    AscQuery::GetOperationsValuesFromEvent(EventQuery {
                        event: event.clone(),
                    }),
                )
                .await?
        };
        result
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Operation value not found for tx_id: {:?}", event))
    }

    /// Get the param choice from the CSC
    #[tracing::instrument(skip(self))]
    async fn get_fhe_parameter(&self) -> anyhow::Result<FheParameter> {
        let fhe_parameter = {
            let query_client = self.query_client.lock().await;
            query_client
                .query_csc(
                    self.config.csc_address.to_owned(),
                    CscQuery::GetFheParameter {},
                )
                .await?
        };
        Ok(fhe_parameter)
    }

    async fn get_public_key(&self) -> kms_blockchain_client::crypto::pubkey::PublicKey {
        self.client.lock().await.get_public_key()
    }
}
