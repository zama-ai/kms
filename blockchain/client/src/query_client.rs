use crate::errors::Error;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_proto::messages::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_proto::messages::cosmos::tx::v1beta1::{GetTxRequest, GetTxsEventRequest, OrderBy};
use cosmos_proto::messages::cosmwasm::wasm::v1::query_client::QueryClient as WasmQueryClient;
use cosmos_proto::messages::cosmwasm::wasm::v1::{
    QueryContractInfoRequest, QueryContractInfoResponse, QueryContractsByCodeRequest,
    QueryContractsByCodeResponse, QuerySmartContractStateRequest,
};
use events::kms::{KmsEvent, TransactionId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::str;
use std::time::Duration;
use strum_macros::EnumString;
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

/// Message input for getting the operation values associated to an event from the ASC
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct EventQuery {
    pub event: KmsEvent,
}

/// Message input for getting the transaction from the ASC
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct TransactionQuery {
    pub txn_id: TransactionId,
}

/// Message input for getting the key ID from the ASC
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct GenKeyIdQuery {
    pub key_id: String,
}

/// Message input for getting the CRS ID from the ASC
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct GenCrsIdQuery {
    pub crs_id: String,
}

/// Messages for querying the ASC
///
/// Important: serde's rename must exactly match the ASC's associated method name
#[derive(EnumString, Serialize, Debug)]
pub enum AscQuery {
    #[serde(rename = "get_key_gen_response_values")]
    GetKeyGenResponseValues(GenKeyIdQuery),
    #[serde(rename = "get_crs_gen_response_values")]
    GetCrsGenResponseValues(GenCrsIdQuery),
    #[serde(rename = "get_operations_values_from_event")]
    GetOperationsValuesFromEvent(EventQuery),
    #[serde(rename = "get_transaction")]
    GetTransaction(TransactionQuery),
}

/// Messages for querying the CSC
///
/// Important: serde's rename must exactly match the CSC's associated method name
#[derive(EnumString, Serialize, Debug)]
pub enum CscQuery {
    #[serde(rename = "get_fhe_parameter")]
    GetFheParameter {},
    #[serde(rename = "get_num_parties")]
    GetNumParties {},
    #[serde(rename = "get_response_count_for_majority_vote")]
    GetResponseCountForMajorityVote {},
    #[serde(rename = "get_response_count_for_reconstruction")]
    GetResponseCountForReconstruction {},
    #[serde(rename = "get_degree_for_reconstruction")]
    GetDegreeForReconstruction {},
    #[serde(rename = "get_storage_base_url")]
    GetStorageBaseUrl {},
    #[serde(rename = "get_parties")]
    GetParties {},
}

impl QueryClient {
    pub fn builder<'a>() -> QueryClientBuilderBuilder<'a> {
        QueryClientBuilder::builder()
    }

    /// Query ASC's state with a specific message.
    ///
    /// # Arguments
    /// * `contract_address` - The ASC's address to query.
    /// * `query_msg` - The message to be sent to the ASC.
    ///
    /// # Returns
    /// A `Result` containing the response from the ASC or an error.
    #[tracing::instrument(skip(self))]
    pub async fn query_asc<T: DeserializeOwned>(
        &self,
        contract_address: String,
        query_msg: AscQuery,
    ) -> Result<T, Error> {
        tracing::info!("contract address: {}", contract_address);
        let request = QuerySmartContractStateRequest {
            address: contract_address,
            query_data: serde_json::json!(query_msg).to_string().as_bytes().to_vec(),
        };
        self.send_request(request).await
    }

    /// Query CSC's state with a specific message.
    ///
    /// # Arguments
    /// * `contract_address` - The CSC's address to query.
    /// * `query_msg` - The message to be sent to the CSC.
    ///
    /// # Returns
    /// A `Result` containing the response from the CSC or an error.
    #[tracing::instrument(skip(self))]
    pub async fn query_csc<T: DeserializeOwned>(
        &self,
        contract_address: String,
        query_msg: CscQuery,
    ) -> Result<T, Error> {
        tracing::info!("contract address: {}", contract_address);
        let request = QuerySmartContractStateRequest {
            address: contract_address,
            query_data: serde_json::json!(query_msg).to_string().as_bytes().to_vec(),
        };
        self.send_request(request).await
    }

    /// Send a request
    ///
    /// # Arguments
    /// * `request` - The request to be sent, containing the contract's address and the query data.
    ///
    /// # Returns
    /// A `Result` containing the response from the contract or an error.
    #[tracing::instrument(skip(self))]
    pub async fn send_request<T: DeserializeOwned>(
        &self,
        request: QuerySmartContractStateRequest,
    ) -> Result<T, Error> {
        let mut query = WasmQueryClient::new(self.client.clone());
        let result = query
            .smart_contract_state(request)
            .await
            .map(|response| response.into_inner().data)?;

        tracing::info!("Query executed successfully. Length: {:?}", result.len());

        let result_type = serde_json::from_slice(&result).map_err(|e| {
            Error::QueryError(format!("Error deserializing query response {:?}", e))
        })?;

        Ok(result_type)
    }

    #[tracing::instrument(skip(self))]
    pub async fn query_tx(&self, tx_hash: String) -> Result<Option<TxResponse>, Error> {
        let mut query = ServiceClient::new(self.client.clone());
        let req = GetTxRequest {
            hash: tx_hash.clone(),
        };
        let result = query
            .get_tx(req)
            .await
            .map(|response| Ok(response.into_inner().tx_response))
            .unwrap_or_else(|e| {
                if e.code() == tonic::Code::NotFound {
                    Ok(None)
                } else {
                    Err(Error::QueryError(format!(
                        "Error querying transaction {:?}",
                        e
                    )))
                }
            })?;

        if let Some(response) = result {
            if response.code == 0 {
                tracing::info!("Query Tx executed successfully {:?}", response.txhash);
                tracing::trace!("Tx payload: {:?}", response);
                Ok(Some(response))
            } else {
                Err(Error::QueryError(format!(
                    "Transaction found for {:?} with error code {:?} and message {:?}",
                    tx_hash.clone(),
                    response.code,
                    response.raw_log
                )))
            }
        } else {
            tracing::info!("Transaction not found for {:?}", tx_hash.clone());
            Ok(None)
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

    pub async fn get_contract_metadata(
        &self,
        contract_address: String,
    ) -> Result<QueryContractInfoResponse, Error> {
        let mut query = WasmQueryClient::new(self.client.clone());
        let req = QueryContractInfoRequest {
            address: contract_address,
        };
        let result = query
            .contract_info(req)
            .await
            .map(|response| response.into_inner())?;

        Ok(result)
    }

    /// Lists all contracts for a given code ID.
    ///
    /// Code ID are defined by the order of contract upload in `deploy_contracts.sh`, starting from 1.
    pub async fn list_contracts(
        &self,
        code_id: u64,
    ) -> Result<QueryContractsByCodeResponse, Error> {
        let mut query = WasmQueryClient::new(self.client.clone());
        let req = QueryContractsByCodeRequest {
            pagination: None,
            code_id,
        };
        let result = query
            .contracts_by_code(req)
            .await
            .map(|response| response.into_inner())?;

        tracing::info!("Query contracts executed successfully {:?}", result);

        Ok(result)
    }
}

#[test]
fn test_get_fhe_parameter_serialization() {
    let obj = CscQuery::GetFheParameter {};
    let ser = serde_json::json!(obj).to_string();
    assert_eq!(ser, "{\"get_fhe_parameter\":{}}");
}
