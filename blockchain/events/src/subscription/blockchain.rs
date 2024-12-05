use std::sync::Arc;

use crate::kms::KmsOperation;

use super::handler::{EventsMode, SubscriptionError};
use async_trait::async_trait;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_proto::messages::cosmos::base::node::v1beta1::service_client::ServiceClient as BaseServiceClient;
use cosmos_proto::messages::cosmos::base::node::v1beta1::StatusRequest;
use cosmos_proto::messages::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_proto::messages::cosmos::tx::v1beta1::{
    GetBlockWithTxsRequest, GetTxsEventRequest, OrderBy, Tx,
};
#[cfg(test)]
use mockall::automock;
use strum::IntoEnumIterator;
use tokio::time::Duration;
use tonic::transport::{Channel, Endpoint};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait BlockchainService: Send + Sync {
    /// Generic function to get events from KMS BC, those events may be filtered according to the implementation.
    async fn get_events(&self, from_height: u64) -> Result<Vec<TxResponse>, SubscriptionError>;
    /// Generic function to get events from KMS BC, filter to return only request events.
    async fn get_events_requests(
        &self,
        from_height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError>;
    /// Generic function to get events from KMS BC, filter to return only request events.
    async fn get_events_responses(
        &self,
        from_height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError>;
    async fn get_last_height(&self) -> Result<u64, SubscriptionError>;
    async fn get_all_tx_from_to_height(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<Tx>, SubscriptionError>;

    async fn get_all_tx_from_to_height_filter_map<
        T: 'static + Send,
        F: Fn(Tx) -> Option<T> + Send + 'static,
    >(
        &self,
        from_height: u64,
        to_height: u64,
        filter: F,
    ) -> Result<Vec<T>, SubscriptionError>;
}

#[derive(Clone)]
pub struct GrpcBlockchainService {
    channel: Channel,
    contract_address: String,
    mode: Option<EventsMode>,
}

impl GrpcBlockchainService {
    pub(crate) fn new(
        addresses: &[&str],
        contract_address: &str,
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
            contract_address: contract_address.to_string(),
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
impl BlockchainService for GrpcBlockchainService {
    /// Fetch all events that have a height > _from_height_
    /// and filter them based on the mode of the given [`GrpcBlockchainService`]:
    /// - returns only the requests if mode is [`EventsMode::Request`]
    /// - returns only the responses if mode is [`EventsMode::Response`]
    /// - returns both if mode is [`None`]
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
            let total_pages = txs.total.div_ceil(10);
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

    /// Generic function to get events from KMS BC, filter to return only request events.
    async fn get_events_requests(
        &self,
        from_height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError> {
        let mut temp_service = self.clone();
        temp_service.mode = Some(EventsMode::Request);
        temp_service.get_events(from_height).await
    }
    /// Generic function to get events from KMS BC, filter to return only request events.
    async fn get_events_responses(
        &self,
        from_height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError> {
        let mut temp_service = self.clone();
        temp_service.mode = Some(EventsMode::Response);
        temp_service.get_events(from_height).await
    }

    async fn get_last_height(&self) -> Result<u64, SubscriptionError> {
        let mut client = BaseServiceClient::new(self.channel.clone());
        let response = client.status(StatusRequest {}).await?;
        let status = response.into_inner();
        Ok(status.height)
    }

    /// Returns all transactions in blocks between
    /// heights _from\_height_ and _to\_height_ both included
    async fn get_all_tx_from_to_height(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<Tx>, SubscriptionError> {
        self.get_all_tx_from_to_height_filter_map(from_height, to_height, Some)
            .await
    }

    /// Returns transactions in blocks between
    /// heights _from\_height_ and _to\_height_ both included
    /// tranformed as per the given filter
    async fn get_all_tx_from_to_height_filter_map<
        T: 'static + Send,
        F: Fn(Tx) -> Option<T> + Send + 'static,
    >(
        &self,
        from_height: u64,
        to_height: u64,
        filter: F,
    ) -> Result<Vec<T>, SubscriptionError> {
        let mut client = ServiceClient::new(self.channel.clone());

        let mut all_txs = Vec::new();
        for curr_height in from_height..=to_height {
            let request = GetBlockWithTxsRequest {
                height: curr_height as i64,
                pagination: None,
            };
            let block = client.get_block_with_txs(request).await?.into_inner();
            block
                .txs
                .into_iter()
                .filter_map(&filter)
                .for_each(|tx| all_txs.push(tx));
        }

        Ok(all_txs)
    }
}

/// Trivial implementation for the Arc version
#[async_trait]
impl<A> BlockchainService for Arc<A>
where
    A: BlockchainService,
{
    async fn get_events(&self, from_height: u64) -> Result<Vec<TxResponse>, SubscriptionError> {
        (**self).get_events(from_height).await
    }

    async fn get_events_requests(
        &self,
        from_height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError> {
        (**self).get_events_requests(from_height).await
    }

    async fn get_events_responses(
        &self,
        from_height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError> {
        (**self).get_events_responses(from_height).await
    }

    async fn get_last_height(&self) -> Result<u64, SubscriptionError> {
        (**self).get_last_height().await
    }
    async fn get_all_tx_from_to_height(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<Tx>, SubscriptionError> {
        (**self)
            .get_all_tx_from_to_height(from_height, to_height)
            .await
    }

    async fn get_all_tx_from_to_height_filter_map<
        T: 'static + Send,
        F: Fn(Tx) -> Option<T> + Send + 'static,
    >(
        &self,
        from_height: u64,
        to_height: u64,
        filter: F,
    ) -> Result<Vec<T>, SubscriptionError> {
        (**self)
            .get_all_tx_from_to_height_filter_map(from_height, to_height, filter)
            .await
    }
}
