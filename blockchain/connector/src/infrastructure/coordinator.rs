use super::metrics::OpenTelemetryMetrics;
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KeyGenResponseVal, KmsOperationResponse,
    ReencryptResponseVal,
};
use crate::domain::kms::{CrsGenVal, DecryptVal, KeyGenVal, Kms, ReencryptVal};
use anyhow::anyhow;
use async_trait::async_trait;
use events::kms::{DecryptResponseValues, KeyGenResponseValues, ReencryptResponseValues};
use kms_lib::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
use kms_lib::kms::RequestId;
use kms_lib::kms::{Config, CrsGenRequest, ParamChoice};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::{Channel, Endpoint};
use typed_builder::TypedBuilder;

const MAX_CRS_GEN_DURATION_PER_PARTY_SECS: u64 = 60;

#[derive(Clone, TypedBuilder)]
pub struct KmsCoordinator {
    channel: Channel,
    n_parties: u64,
    _metrics: Arc<OpenTelemetryMetrics>,
}
impl KmsCoordinator {
    pub(crate) async fn new(
        config: crate::conf::CoordinatorConfig,
        metrics: OpenTelemetryMetrics,
    ) -> Result<Self, anyhow::Error> {
        // NOTE: we don't need multiple endpoints for now
        // but we keep it like this to match the blockchain implementation
        let endpoints = config
            .coordinator_addresses()
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| anyhow::anyhow!("Error connecting to blockchain {:?}", e))?;
        // TODO should we have a configurable timeout?
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let channel = Channel::balance_list(endpoints);
        tracing::info!(
            "Connecting to coordinator server {:?}",
            config.coordinator_addresses()
        );
        Ok(KmsCoordinator {
            channel,
            n_parties: config.parties,
            _metrics: Arc::new(metrics),
        })
    }
}

#[async_trait]
impl Kms for DecryptVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        // TODO: Implement this
        Ok(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
            decrypt_response: DecryptResponseValues::builder()
                .plaintext(
                    "This is a mocked response of decyprt request"
                        .as_bytes()
                        .to_vec(),
                )
                .build(),
            operation_val: BlockchainOperationVal {
                tx_id: self.operation_val.tx_id.clone(),
            },
        }))
    }
}

#[async_trait]
impl Kms for ReencryptVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        Ok(KmsOperationResponse::ReencryptResponse(
            ReencryptResponseVal {
                reencrypt_response: ReencryptResponseValues::builder()
                    .cyphertext([9; 10].to_vec())
                    .build(),
                operation_val: BlockchainOperationVal {
                    tx_id: self.operation_val.tx_id.clone(),
                },
            },
        ))
    }
}

#[async_trait]
impl Kms for KeyGenVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        Ok(KmsOperationResponse::KeyGenResponse(KeyGenResponseVal {
            keygen_response: KeyGenResponseValues::builder()
                .key([9; 10].to_vec())
                .build(),
            operation_val: BlockchainOperationVal {
                tx_id: self.operation_val.tx_id.clone(),
            },
        }))
    }
}

#[async_trait]
impl Kms for CrsGenVal {
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };
        let req = CrsGenRequest {
            config: Some(Config {}),
            params: ParamChoice::Test.into(), // TODO load from blockchain
            request_id: Some(req_id.clone()),
        };
        // the response should be empty
        let _resp = client.crs_gen(tonic::Request::new(req)).await?;

        // loop to get response
        const RETRY_INTERVAL: u64 = 10;
        let mut cnt = 0u64;
        loop {
            sleep(Duration::from_secs(RETRY_INTERVAL)).await;
            let resp = client
                .get_crs_gen_result(tonic::Request::new(req_id.clone()))
                .await;
            match resp {
                Ok(res) => {
                    let inner = res.into_inner();
                    let request_id = inner.request_id.ok_or(anyhow!("empty request_id"))?;
                    let crs_results = inner.crs_results.ok_or(anyhow!("empty crs result"))?;
                    return Ok(KmsOperationResponse::CrsGenResponse(
                        crate::domain::blockchain::CrsGenResponseVal {
                            crs_gen_response: events::kms::CrsGenResponseValues::builder()
                                .request_id(request_id.request_id)
                                .digest(crs_results.key_handle)
                                .signature(crs_results.signature)
                                .build(),
                            operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
                            },
                        },
                    ));
                }
                Err(_) => {
                    let max_dur = MAX_CRS_GEN_DURATION_PER_PARTY_SECS
                        * self.operation_val.kms_client.n_parties;
                    if cnt > max_dur {
                        // NOTE: CRS generation time is proportional to the number of parties
                        // so we need to multiply the max timeout by the number of parties
                        return Err(anyhow!("time out while trying to get response"));
                    } else {
                        cnt += 1;
                        tracing::info!(
                            "Retrying get CRS response, tries: {cnt}, interval: {RETRY_INTERVAL}, max duration: {max_dur}"
                        );
                    }
                }
            }
        }
    }
}
