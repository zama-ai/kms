use crate::conf::ConnectorConfig;
use crate::domain::blockchain::{Blockchain, KmsOperationResponse};
use async_trait::async_trait;
use events::kms::KmsEvent;
use kms_blockchain_client::client::{Client, ClientBuilder};
use retrying::retry;
use std::sync::Arc;
use tokio::sync::Mutex;
use typed_builder::TypedBuilder;

#[derive(Clone, TypedBuilder)]
pub struct KmsBlockchain {
    client: Arc<Mutex<Client>>,
    config: ConnectorConfig,
}

impl KmsBlockchain {
    pub(crate) async fn new(config: ConnectorConfig) -> Result<Self, anyhow::Error> {
        let client: Client = ClientBuilder::builder()
            .contract_address(&config.contract_address)
            .grpc_addresses(config.grpc_addresses())
            .coin_denom(&config.contract_fee.coin_denom)
            .mnemonic_wallet("")
            .build()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Error creating blockchain client {:?}", e))?;
        Ok(KmsBlockchain {
            client: Arc::new(Mutex::new(client)),
            config,
        })
    }

    #[retry(stop=(attempts(4)|duration(5)),wait=fixed(10))]
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
        let msg_str = <KmsOperationResponse as Into<KmsEvent>>::into(result)
            .to_json()?
            .to_string();
        tracing::info!("Sending result to contract: {:?}", msg_str);
        self.call_execute_contract(
            &mut client,
            msg_str.as_bytes(),
            self.config.contract_fee.amount,
        )
        .await
    }
}
