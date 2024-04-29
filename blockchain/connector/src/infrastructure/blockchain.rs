use crate::conf::ConnectorConfig;
use crate::domain::blockchain::{Blockchain, KmsOperationResponse};
use async_trait::async_trait;
use cosmos_proto::messages::cosmwasm::wasm::v1::msg_client::MsgClient;
use cosmos_proto::messages::cosmwasm::wasm::v1::MsgExecuteContract;
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use typed_builder::TypedBuilder;

#[derive(Clone, TypedBuilder)]
pub struct KmsBlockchain {
    channel: Channel,
    config: ConnectorConfig,
}

impl KmsBlockchain {
    pub(crate) async fn new(config: crate::conf::ConnectorConfig) -> Result<Self, anyhow::Error> {
        let endpoints = config
            .grpc_addresses
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| anyhow::anyhow!("Error connecting to blockchain {:?}", e))?;
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let channel = Channel::balance_list(endpoints);
        tracing::debug!("Connecting to gRPC server {:?}", config.grpc_addresses);
        Ok(KmsBlockchain { channel, config })
    }
}

#[async_trait]
impl Blockchain for KmsBlockchain {
    async fn send_result(&self, result: KmsOperationResponse) -> anyhow::Result<()> {
        let mut client = MsgClient::new(self.channel.clone());
        let msg = serde_json::to_string(&result)?.as_bytes().to_vec();
        client
            .execute_contract(MsgExecuteContract {
                contract: self.config.contract_addresses.clone(),
                msg,
                sender: "kms".to_string(),
                funds: vec![],
            })
            .await?;
        Ok(())
    }
}
