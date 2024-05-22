use crate::kms::KmsOperation;

use super::handler::{EventsMode, SubscriptionError};
use async_trait::async_trait;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_proto::messages::cosmos::base::node::v1beta1::service_client::ServiceClient as BaseServiceClient;
use cosmos_proto::messages::cosmos::base::node::v1beta1::StatusRequest;
use cosmos_proto::messages::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_proto::messages::cosmos::tx::v1beta1::{GetTxsEventRequest, OrderBy};
#[cfg(test)]
use mockall::automock;
use strum::IntoEnumIterator;
use tokio::time::Duration;
use tonic::transport::{Channel, Endpoint};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait BlockchainService {
    async fn get_events(&self, from_height: u64) -> Result<Vec<TxResponse>, SubscriptionError>;
    async fn get_last_height(&self) -> Result<u64, SubscriptionError>;
}

pub struct GrpcBlockchainService<'a> {
    channel: Channel,
    contract_address: &'a str,
    mode: Option<EventsMode>,
}

impl<'a> GrpcBlockchainService<'a> {
    pub(crate) fn new(
        addresses: &[&str],
        contract_address: &'a str,
        mode: Option<EventsMode>,
    ) -> Result<Self, SubscriptionError> {
        if addresses.is_empty() {
            return Err(SubscriptionError::ConnectionError(
                "No gRPC addresses provided".to_string(),
            ));
        }
        let endpoints = addresses
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| SubscriptionError::ConnectionError(e.to_string()))?;
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let channel = Channel::balance_list(endpoints);
        tracing::info!("Connecting to gRPC server {:?}", addresses);

        Ok(GrpcBlockchainService {
            channel,
            contract_address,
            mode,
        })
    }
    pub(crate) fn to_query(&self, height: u64) -> String {
        format!(
            "tx.height>{} AND execute._contract_address='{}'",
            height, self.contract_address,
        )
    }

    fn filter_attributes(&self, attr: &KmsOperation) -> bool {
        if let Some(mode) = self.mode {
            match mode {
                EventsMode::Request => attr.is_request(),
                EventsMode::Response => attr.is_response(),
            }
        } else {
            true
        }
    }

    fn is_kms_request_operation(&self, tx: &TxResponse) -> bool {
        tx.events.iter().any(|event| {
            KmsOperation::iter()
                .filter(|attr| self.filter_attributes(attr))
                .any(|attr| event.r#type == format!("wasm-{}", attr))
        })
    }
}

#[async_trait]
impl BlockchainService for GrpcBlockchainService<'_> {
    async fn get_events(&self, from_height: u64) -> Result<Vec<TxResponse>, SubscriptionError> {
        let mut client = ServiceClient::new(self.channel.clone());
        let mut results = vec![];
        #[allow(deprecated)]
        let mut request = GetTxsEventRequest {
            events: vec![],
            query: self.to_query(from_height),
            page: 1,
            limit: 10,
            order_by: OrderBy::Asc.into(),
            pagination: None,
        };
        tracing::debug!("Getting txs with query: {:?}", request);
        loop {
            let response = client.get_txs_event(request.clone()).await?;
            let txs = response.into_inner();
            if txs.total == 0 {
                break;
            }
            if txs.tx_responses.is_empty() {
                tracing::debug!("No more transactions to fetch");
                break;
            }
            results.extend(
                txs.tx_responses
                    .iter()
                    .filter(|x| self.is_kms_request_operation(x))
                    .cloned(),
            );
            let total_pages = txs.total / 10 + 1;
            tracing::debug!(
                "Total pages with transactions: {} - Current page: {}",
                total_pages,
                request.page
            );
            if request.page == total_pages {
                break;
            }
            request.page += 1;
        }
        Ok(results)
    }

    async fn get_last_height(&self) -> Result<u64, SubscriptionError> {
        let mut client = BaseServiceClient::new(self.channel.clone());
        let response = client.status(StatusRequest {}).await?;
        let status = response.into_inner();
        Ok(status.height)
    }
}
