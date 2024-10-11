use crate::errors::Error;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_proto::messages::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_proto::messages::cosmos::tx::v1beta1::{GetTxRequest, GetTxsEventRequest, OrderBy};
use cosmos_proto::messages::cosmwasm::wasm::v1::query_client::QueryClient as WasmQueryClient;
use cosmos_proto::messages::cosmwasm::wasm::v1::{
    QueryContractInfoRequest, QueryContractInfoResponse, QueryContractsByCodeRequest,
    QueryContractsByCodeResponse, QuerySmartContractStateRequest,
};
use events::kms::{KmsEvent, KmsOperation, TransactionId};
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

/// Query for the blockchain used when querying it in relation to a specific operation.
#[derive(Debug, Serialize, Clone, PartialEq, Default, TypedBuilder)]
pub struct OperationQuery {
    pub operation: KmsOperation,
}

/// Query for the blockchain used when querying it in relation to a specific event, i.e. transaction.
#[derive(Debug, Serialize, Clone, PartialEq, Default, TypedBuilder)]
pub struct EventQuery {
    pub event: KmsEvent,
}

#[derive(Debug, Serialize, Clone, PartialEq, Default, TypedBuilder)]
pub struct TransactionQuery {
    pub txn_id: TransactionId,
}

#[derive(Debug, EnumString, Serialize, Clone, PartialEq)]
pub enum ContractQuery {
    #[strum(serialize = "get_all_values_from_operation")]
    #[serde(rename = "get_all_values_from_operation")]
    GetAllValuesFromOperation(OperationQuery),
    #[strum(serialize = "get_all_operations_values")]
    #[serde(rename = "get_all_operations_values")]
    GetAllOperationsValues(OperationQuery),
    #[strum(serialize = "get_operations_value")]
    #[serde(rename = "get_operations_value")]
    GetOperationsValue(EventQuery),
    #[strum(serialize = "get_transaction")]
    #[serde(rename = "get_transaction")]
    GetTransaction(TransactionQuery),
    #[strum(serialize = "get_kms_core_conf")]
    #[serde(rename = "get_kms_core_conf")]
    GetKmsCoreConf {},
}

#[derive(TypedBuilder, Clone)]
pub struct QueryContractRequest {
    contract_address: String,
    query: ContractQuery,
}

impl QueryClient {
    pub fn builder<'a>() -> QueryClientBuilderBuilder<'a> {
        QueryClientBuilder::builder()
    }

    /// Queries the contract state on the blockchain.
    ///
    /// # Arguments
    /// * `request` - The query data to be sent to the contract.
    ///
    /// # Returns
    /// A `Result` containing the response from the contract or an error.
    #[tracing::instrument(skip(self, request))]
    pub async fn query_contract<T: DeserializeOwned>(
        &self,
        request: QueryContractRequest,
    ) -> Result<T, Error> {
        let mut query = WasmQueryClient::new(self.client.clone());
        tracing::info!("contract address: {}", request.contract_address);
        let request = QuerySmartContractStateRequest {
            address: request.contract_address,
            query_data: serde_json::json!(request.query)
                .to_string()
                .as_bytes()
                .to_vec(),
        };
        let result = query
            .smart_contract_state(request)
            .await
            .map(|response| response.into_inner().data)?;

        tracing::info!("Query executed successfully {:?}", result.len());

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

#[test]
fn test_get_kms_core_conf_serialization() {
    let obj = ContractQuery::GetKmsCoreConf {};
    let ser = serde_json::json!(obj).to_string();
    assert_eq!(ser, "{\"get_kms_core_conf\":{}}");
}
