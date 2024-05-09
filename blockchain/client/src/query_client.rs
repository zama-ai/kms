use crate::errors::Error;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_proto::messages::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_proto::messages::cosmos::tx::v1beta1::{GetTxRequest, GetTxsEventRequest, OrderBy};
use cosmos_proto::messages::cosmwasm::wasm::v1::query_client::QueryClient as WasmQueryClient;
use cosmos_proto::messages::cosmwasm::wasm::v1::{
    QueryContractsByCodeRequest, QueryContractsByCodeResponse, QuerySmartContractStateRequest,
};
use std::str;
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct QueryClientBuilder<'a> {
    grpc_addresses: Vec<&'a str>,
}

impl TryFrom<QueryClientBuilder<'_>> for QueryClient {
    type Error = Error;
    fn try_from(value: QueryClientBuilder) -> Result<Self, Self::Error> {
        let endpoints = value
            .grpc_addresses
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| {
                Error::GrpcClientCreateError(format!("Error connecting to blockchain {:?}", e))
            })?;
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let client = Channel::balance_list(endpoints);

        tracing::info!("gRPC QueryClient initialized successfully");

        Ok(QueryClient { client })
    }
}

/// A QueryClient for interacting with CosmWasm smart contracts via Cosmos SDK's Tendermint protocol.
pub struct QueryClient {
    client: Channel,
}

impl QueryClient {
    pub fn builder<'a>() -> QueryClientBuilderBuilder<'a> {
        QueryClientBuilder::builder()
    }

    /// Queries the contract state on the blockchain.
    /// # Arguments
    /// * `query_data` - The query data to be sent to the contract.
    /// # Returns
    /// A `Result` containing the response from the contract or an error.
    #[tracing::instrument(skip(self, query_data))]
    pub async fn query_contract(
        &self,
        contract_address: String,
        query_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut query = WasmQueryClient::new(self.client.clone());
        let request = QuerySmartContractStateRequest {
            address: contract_address,
            query_data: query_data.to_vec(),
        };
        let result = query
            .smart_contract_state(request)
            .await
            .map(|response| response.into_inner().data)?;

        tracing::info!("Query executed successfully {:?}", result.len());

        Ok(result)
    }

    #[tracing::instrument(skip(self))]
    pub async fn query_tx(&self, tx_hash: String) -> Result<TxResponse, Error> {
        let mut query = ServiceClient::new(self.client.clone());
        let req = GetTxRequest {
            hash: tx_hash.clone(),
        };
        let result = query
            .get_tx(req)
            .await
            .map(|response| response.into_inner().tx_response)?;

        if let Some(response) = result {
            if response.code == 0 {
                tracing::info!("Query Tx executed successfully {:?}", response);
                Ok(response)
            } else {
                Err(Error::QueryError(format!(
                    "Transaction found for {:?} with error code {:?} and message {:?}",
                    tx_hash.clone(),
                    response.code,
                    response.raw_log
                )))
            }
        } else {
            Err(Error::QueryError(format!(
                "Transaction not found for {:?}",
                tx_hash
            )))
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn query_tx_by_block_and_index(
        &self,
        block_height: u64,
        tx_index: u32,
    ) -> Result<TxResponse, Error> {
        let mut query = ServiceClient::new(self.client.clone());
        #[allow(deprecated)]
        let request = GetTxsEventRequest {
            events: vec![],
            query: format!("tx.height={}", block_height),
            page: 1,
            limit: 10,
            order_by: OrderBy::Asc.into(),
            pagination: None,
        };

        let result = query
            .get_txs_event(request)
            .await
            .map(|response| response.into_inner())?;

        result
            .tx_responses
            .into_iter()
            .nth(tx_index as usize)
            .ok_or_else(|| {
                Error::QueryError(format!(
                    "Transaction not found for block {} and height {}",
                    block_height, tx_index
                ))
            })
    }

    pub async fn list_contracts(&self) -> Result<QueryContractsByCodeResponse, Error> {
        let mut query = WasmQueryClient::new(self.client.clone());
        let req = QueryContractsByCodeRequest {
            pagination: None,
            code_id: 1,
        };
        let result = query
            .contracts_by_code(req)
            .await
            .map(|response| response.into_inner())?;

        tracing::info!("Query Contracts executed successfully {:?}", result);

        Ok(result)
    }
}
