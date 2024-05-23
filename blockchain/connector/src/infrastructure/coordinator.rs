use super::metrics::OpenTelemetryMetrics;
use crate::conf::TimeoutConfig;
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse, ReencryptResponseVal,
};
use crate::domain::kms::Kms;
use crate::infrastructure::metrics::{MetricType, Metrics};
use anyhow::anyhow;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use events::kms::{
    DecryptResponseValues, DecryptValues, KeyGenPreprocResponseValues, KeyGenResponseValues,
    KeyGenValues, KmsEvent, OperationValue, Proof, ReencryptResponseValues, ReencryptValues,
    TransactionId,
};
use events::HexVector;
use kms_lib::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
use kms_lib::kms::{
    Config, CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse,
    DecryptionResponsePayload, Eip712DomainMsg, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenResult, ParamChoice, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse,
};
use kms_lib::kms::{KeyGenPreprocRequest, KeyGenRequest, RequestId};
use kms_lib::rpc::rpc_types::{PubDataType, CURRENT_FORMAT_VERSION};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::{Channel, Endpoint};
use tonic::{Response, Status};
use typed_builder::TypedBuilder;

pub struct KmsOperationVal {
    pub kms_client: KmsCoordinator,
    pub tx_id: TransactionId,
    pub proof: Proof,
}

pub struct DecryptVal {
    pub decrypt: DecryptValues,
    pub operation_val: KmsOperationVal,
}

pub struct ReencryptVal {
    pub reencrypt: ReencryptValues,
    pub operation_val: KmsOperationVal,
}

pub struct KeyGenPreprocVal {
    pub operation_val: KmsOperationVal,
}

pub struct KeyGenVal {
    pub keygen: KeyGenValues,
    pub operation_val: KmsOperationVal,
}

pub struct CrsGenVal {
    pub operation_val: KmsOperationVal,
}

#[enum_dispatch]
pub enum KmsOperationRequest {
    Reencrypt(ReencryptVal),
    Decrypt(DecryptVal),
    KeyGen(KeyGenVal),
    KeyGenPreproc(KeyGenPreprocVal),
    CrsGen(CrsGenVal),
}

#[async_trait]
impl Kms for KmsCoordinator {
    async fn run(
        &self,
        event: KmsEvent,
        operation_value: OperationValue,
    ) -> anyhow::Result<KmsOperationResponse> {
        let operation = self.create_kms_operation(event, operation_value)?;
        operation.run_operation().await
    }
}

#[async_trait]
#[enum_dispatch(KmsOperationRequest)]
pub trait KmsEventHandler {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse>;
}

#[derive(Clone, TypedBuilder)]
pub struct KmsCoordinator {
    channel: Channel,
    shares_needed: u64,
    metrics: Arc<OpenTelemetryMetrics>,
    timeout_config: TimeoutConfig,
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
            .map_err(|e| anyhow::anyhow!("Error connecting to coordinator {:?}", e))?;

        // TODO should we have a configurable timeout?
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.timeout(Duration::from_secs(60)).clone());
        let channel = Channel::balance_list(endpoints);
        tracing::info!(
            "Connecting to coordinator server {:?}",
            config.coordinator_addresses(),
        );
        Ok(KmsCoordinator {
            channel,
            shares_needed: config.shares_needed,
            metrics: Arc::new(metrics),
            timeout_config: config.timeout_config.clone(),
        })
    }

    fn create_kms_operation(
        &self,
        event: KmsEvent,
        operation_value: OperationValue,
    ) -> anyhow::Result<KmsOperationRequest> {
        let operation_val = KmsOperationVal {
            kms_client: self.clone(),
            tx_id: event.txn_id().clone(),
            proof: event.proof().clone(),
        };
        let request = match operation_value {
            OperationValue::Reencrypt(reencrypt) => KmsOperationRequest::Reencrypt(ReencryptVal {
                reencrypt,
                operation_val,
            }),
            OperationValue::Decrypt(decrypt) => KmsOperationRequest::Decrypt(DecryptVal {
                decrypt,
                operation_val,
            }),
            OperationValue::KeyGenPreproc(_keygen_preproc) => {
                KmsOperationRequest::KeyGenPreproc(KeyGenPreprocVal { operation_val })
            }
            OperationValue::KeyGen(keygen) => KmsOperationRequest::KeyGen(KeyGenVal {
                keygen,
                operation_val,
            }),
            OperationValue::CrsGen(_) => KmsOperationRequest::CrsGen(CrsGenVal { operation_val }),
            _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
        };
        Ok(request)
    }
}

enum PollerStatus<T> {
    Done(T),
    Poll,
}

/// This is a macro that helps us simplify polling code.
/// On a high level, [f_to_poll] is the async function that we are polling
/// and [res_map] is a mapping from the output of f_to_poll to
/// [Result<PollerStatus>]. These two inputs are split because rust does not
/// currently support async closures.
macro_rules! poller {
    ($f_to_poll:expr,$res_map:expr,$timeout_triple:expr,$info:expr,$metrics:expr) => {
        // first wait a bit because some requests are slow.
        tokio::time::sleep(Duration::from_secs($timeout_triple.initial_wait_time)).await;

        // start polling
        let mut cnt = 0u64;
        loop {
            sleep(Duration::from_secs($timeout_triple.retry_interval)).await;
            let resp = $f_to_poll.await;
            match $res_map(resp) {
                Ok(PollerStatus::Done(res)) => {
                    $metrics.increment(MetricType::CoordinatorResponseSuccess, 1, &[("ok", "ok")]);
                    return Ok(res);
                }
                Ok(PollerStatus::Poll) => {
                    if cnt > $timeout_triple.max_poll_count {
                        let err_msg =
                            format!("Time out after {cnt} tries while trying to get response");
                        $metrics.increment(
                            MetricType::CoordinatorResponseError,
                            1,
                            &[("error", &err_msg)],
                        );
                        return Err(anyhow!(err_msg));
                    } else {
                        cnt += 1;
                        tracing::info!(
                            "Polling coordinator {}, tries: {cnt}, timeout_triple: {:?}",
                            $info,
                            $timeout_triple,
                        );
                    }
                }
                Err(e) => {
                    let err_msg = format!("error while trying to get response {e}");
                    $metrics.increment(
                        MetricType::CoordinatorResponseError,
                        1,
                        &[("error", &err_msg)],
                    );
                    return Err(anyhow!(err_msg));
                }
            }
        }
    };
}

#[async_trait]
impl KmsEventHandler for DecryptVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        if self.operation_val.kms_client.shares_needed as u32 != self.decrypt.servers_needed() {
            return Err(anyhow!(
                "shares_needed not supported: supported={}, requested={}",
                self.operation_val.kms_client.shares_needed,
                self.decrypt.servers_needed()
            ));
        }

        if CURRENT_FORMAT_VERSION != self.decrypt.version() {
            return Err(anyhow!(
                "version not supported: supported={}, requested={}",
                CURRENT_FORMAT_VERSION,
                self.decrypt.version()
            ));
        }

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };
        let version = self.decrypt.version();
        let servers_needed = self.decrypt.servers_needed();
        let key_id = self.decrypt.key_id().to_hex();
        let fhe_type = self.decrypt.fhe_type() as i32;
        let ciphertext = self.decrypt.ciphertext().into();
        let randomness = self.decrypt.randomness().into();

        let req = DecryptionRequest {
            version,
            servers_needed,
            randomness,
            fhe_type,
            key_id: Some(RequestId { request_id: key_id }),
            ciphertext,
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        // the response should be empty
        let _resp = client
            .decrypt(tonic::Request::new(req.clone()))
            .await
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(err_msg);
                metrics.increment(MetricType::CoordinatorError, 1, &[("error", &err_msg)]);
                e
            })?;
        metrics.increment(MetricType::CoordinatorSuccess, 1, &[("ok", "Decrypt")]);

        let g =
            |res: Result<Response<DecryptionResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let payload: DecryptionResponsePayload = inner.payload.ok_or(anyhow!("empty decryption payload"))?;
                        Ok(PollerStatus::Done(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
                            decrypt_response: DecryptResponseValues::builder()
                                .signature(inner.signature)
                                .payload(serde_asn1_der::to_vec(&payload)?)
                                .build(),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
                                proof: self.operation_val.proof.clone(),
                            },
                        })))
                }
                Err(_) => {
                    Ok(PollerStatus::Poll)
                }
            }
        };

        // loop to get response
        let timeout_triple = self
            .operation_val
            .kms_client
            .timeout_config
            .decryption
            .clone();
        poller!(
            client.get_decrypt_result(tonic::Request::new(req_id.clone())),
            g,
            timeout_triple,
            "(Decrypt)",
            metrics
        );
    }
}

struct WrappingFheType(events::kms::FheType);

impl TryFrom<i32> for WrappingFheType {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> anyhow::Result<Self> {
        let fhe_type = if kms_lib::kms::FheType::Bool as i32 == value {
            events::kms::FheType::Ebool
        } else if kms_lib::kms::FheType::Euint4 as i32 == value {
            events::kms::FheType::Euint4
        } else if kms_lib::kms::FheType::Euint8 as i32 == value {
            events::kms::FheType::Euint8
        } else if kms_lib::kms::FheType::Euint16 as i32 == value {
            events::kms::FheType::Euint16
        } else if kms_lib::kms::FheType::Euint32 as i32 == value {
            events::kms::FheType::Euint32
        } else if kms_lib::kms::FheType::Euint64 as i32 == value {
            events::kms::FheType::Euint64
        } else if kms_lib::kms::FheType::Euint128 as i32 == value {
            events::kms::FheType::Euint128
        } else if kms_lib::kms::FheType::Euint160 as i32 == value {
            events::kms::FheType::Euint160
        } else {
            return Err(anyhow!("invalid fhe type"));
        };
        Ok(WrappingFheType(fhe_type))
    }
}

#[async_trait]
impl KmsEventHandler for ReencryptVal {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };

        if self.operation_val.kms_client.shares_needed as u32 != self.reencrypt.servers_needed() {
            return Err(anyhow!(
                "shares_needed not supported: supported={}, requested={}",
                self.operation_val.kms_client.shares_needed,
                self.reencrypt.servers_needed()
            ));
        }

        if CURRENT_FORMAT_VERSION != self.reencrypt.version() {
            return Err(anyhow!(
                "version not supported: supported={}, requested={}",
                CURRENT_FORMAT_VERSION,
                self.reencrypt.version()
            ));
        }

        let reencrypt = &self.reencrypt;
        let req = ReencryptionRequest {
            signature: self.reencrypt.signature().into(),
            payload: Some(ReencryptionRequestPayload {
                version: reencrypt.version(),
                servers_needed: reencrypt.servers_needed(),
                verification_key: reencrypt.verification_key().into(),
                randomness: reencrypt.randomness().into(),
                enc_key: reencrypt.enc_key().into(),
                fhe_type: reencrypt.fhe_type() as i32,
                key_id: Some(RequestId {
                    request_id: reencrypt.key_id().to_hex(),
                }),
                ciphertext: Some(reencrypt.ciphertext().into()),
                ciphertext_digest: reencrypt.ciphertext_digest().into(),
            }),
            domain: Some(Eip712DomainMsg {
                name: reencrypt.eip712_name().to_string(),
                version: reencrypt.eip712_version().to_string(),
                chain_id: reencrypt.eip712_chain_id().into(),
                verifying_contract: reencrypt.eip712_verifying_contract().to_string(),
                salt: reencrypt.eip712_salt().into(),
            }),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        // the response should be empty
        let _resp = client
            .reencrypt(tonic::Request::new(req.clone()))
            .await
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(err_msg);
                metrics.increment(MetricType::CoordinatorError, 1, &[("error", &err_msg)]);
                e
            })?;
        metrics.increment(MetricType::CoordinatorSuccess, 1, &[("ok", "Reencrypt")]);

        let g =
            |res: Result<Response<ReencryptionResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let fhe_type: WrappingFheType = WrappingFheType::try_from(inner.fhe_type)?;
                    Ok(PollerStatus::Done(KmsOperationResponse::ReencryptResponse(
                        ReencryptResponseVal {
                            reencrypt_response: ReencryptResponseValues::builder()
                                .version(inner.version)
                                .servers_needed(inner.servers_needed)
                                .verification_key(inner.verification_key.clone())
                                .digest(inner.digest.clone())
                                .fhe_type(fhe_type.0)
                                .signcrypted_ciphertext(inner.signcrypted_ciphertext.clone())
                                .build(),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
                                proof: self.operation_val.proof.clone(),
                            },
                        },
                    )))
                }
                Err(_) => {
                    Ok(PollerStatus::Poll)
                }
            }
        };

        // we wait for a bit before even trying
        let timeout_triple = self
            .operation_val
            .kms_client
            .timeout_config
            .reencryption
            .clone();

        // loop to get response
        poller!(
            client.get_reencrypt_result(tonic::Request::new(req_id.clone())),
            g,
            timeout_triple,
            "(Reencrypt)",
            metrics
        );
    }
}

#[async_trait]
impl KmsEventHandler for KeyGenPreprocVal {
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };
        let req = KeyGenPreprocRequest {
            config: Some(Config {}),
            params: ParamChoice::Test.into(), // TODO load from blockchain
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        // the response should be empty
        let _resp = client
            .key_gen_preproc(tonic::Request::new(req.clone()))
            .await
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(err_msg);
                metrics.increment(MetricType::CoordinatorError, 1, &[("error", &err_msg)]);
                e
            })?;
        metrics.increment(
            MetricType::CoordinatorSuccess,
            1,
            &[("ok", "KeyGenPreproc")],
        );

        let g =
            |res: Result<Response<KeyGenPreprocStatus>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner().result;
                    let status = KeyGenPreprocStatusEnum::try_from(inner)?;
                    match status {
                        KeyGenPreprocStatusEnum::Finished => {
                            Ok(PollerStatus::Done(KmsOperationResponse::KeyGenPreprocResponse(
                                crate::domain::blockchain::KeyGenPreprocResponseVal {
                                    keygen_preproc_response: KeyGenPreprocResponseValues {},
                                    operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                        tx_id: self.operation_val.tx_id.clone(),
                                        proof: self.operation_val.proof.clone(),
                                    },
                                },
                            )))
                        }
                        KeyGenPreprocStatusEnum::InProgress => {
                            Ok(PollerStatus::Poll)
                        }
                        other => {
                            Err(anyhow!("error while getting status: {}", other.as_str_name()))
                        }
                    }
                }
                Err(e) => {
                    Err(anyhow!(e.to_string()))
                }
            }
        };

        // loop to get response
        let timeout_triple = self.operation_val.kms_client.timeout_config.preproc.clone();
        poller!(
            client.get_preproc_status(tonic::Request::new(req.clone())),
            g,
            timeout_triple,
            "(KeyGenPreproc)",
            metrics
        );
    }
}

#[async_trait]
impl KmsEventHandler for KeyGenVal {
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };

        let preproc_id = RequestId {
            request_id: self.keygen.preproc_id().to_hex(),
        };
        let req = KeyGenRequest {
            config: Some(Config {}),
            // TODO load params from blockchain, timeout needs to be adjusted for this
            params: ParamChoice::Test.into(),
            preproc_id: Some(preproc_id),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        // the response should be empty
        let _resp = client
            .key_gen(tonic::Request::new(req))
            .await
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(err_msg);
                metrics.increment(MetricType::CoordinatorError, 1, &[("error", &err_msg)]);
                e
            })?;
        metrics.increment(MetricType::CoordinatorSuccess, 1, &[("ok", "KeyGen")]);

        let g =
            |res: Result<Response<KeyGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or(anyhow!("empty request_id"))?;
                        let pk_info = inner
                            .key_results
                            .get(&PubDataType::PublicKey.to_string())
                            .ok_or(anyhow!("empty public key info"))?;
                        let ek_info = inner
                            .key_results
                            .get(&PubDataType::ServerKey.to_string())
                            .ok_or(anyhow!("empty evaluation key info"))?;
                        Ok(PollerStatus::Done(KmsOperationResponse::KeyGenResponse(
                            crate::domain::blockchain::KeyGenResponseVal {
                                keygen_response: KeyGenResponseValues::builder()
                                    .request_id(HexVector::from_hex(&request_id.request_id)?)
                                    .public_key_digest(pk_info.key_handle.clone())
                                    .public_key_signature(pk_info.signature.clone())
                                    .server_key_digest(ek_info.key_handle.clone())
                                    .server_key_signature(ek_info.signature.clone())
                                    .build(),
                                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                    tx_id: self.operation_val.tx_id.clone(),
                                    proof: self.operation_val.proof.clone(),
                                },
                            },
                        )))
                    }
                    // we ignore all errors and just poll
                    Err(_) => Ok(PollerStatus::Poll),
                }
            };

        // loop to get response
        let timeout_triple = self.operation_val.kms_client.timeout_config.keygen.clone();
        poller!(
            client.get_key_gen_result(tonic::Request::new(req_id.clone())),
            g,
            timeout_triple,
            "(KeyGen)",
            metrics
        );
    }
}

#[async_trait]
impl KmsEventHandler for CrsGenVal {
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };
        let req = CrsGenRequest {
            config: Some(Config {}),
            // TODO load params from blockchain, timeout needs to be adjusted for this
            params: ParamChoice::Test.into(),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        // the response should be empty
        let _resp = client
            .crs_gen(tonic::Request::new(req))
            .await
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(err_msg);
                metrics.increment(MetricType::CoordinatorError, 1, &[("error", &err_msg)]);
                e
            })?;
        metrics.increment(MetricType::CoordinatorSuccess, 1, &[("ok", "CRS")]);

        let g =
            |res: Result<Response<CrsGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or(anyhow!("empty request_id"))?;
                        let crs_results = inner.crs_results.ok_or(anyhow!("empty crs result"))?;
                        Ok(PollerStatus::Done(KmsOperationResponse::CrsGenResponse(
                            crate::domain::blockchain::CrsGenResponseVal {
                                crs_gen_response: events::kms::CrsGenResponseValues::builder()
                                    .request_id(request_id.request_id)
                                    .digest(crs_results.key_handle)
                                    .signature(crs_results.signature)
                                    .build(),
                                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                    tx_id: self.operation_val.tx_id.clone(),
                                    proof: self.operation_val.proof.clone(),
                                },
                            },
                        )))
                    }
                    Err(_) => Ok(PollerStatus::Poll),
                }
            };

        let timeout_triple = self.operation_val.kms_client.timeout_config.crs.clone();
        poller!(
            client.get_crs_gen_result(tonic::Request::new(req_id.clone())),
            g,
            timeout_triple,
            "(CRS)",
            metrics
        );
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};

    use super::KmsEventHandler as _;
    use crate::{
        conf::{CoordinatorConfig, TimeoutConfig},
        domain::blockchain::KmsOperationResponse,
        infrastructure::{
            coordinator::{KmsCoordinator, WrappingFheType},
            metrics::OpenTelemetryMetrics,
        },
    };
    use events::{
        kms::{
            CrsGenValues, DecryptValues, KeyGenPreprocValues, KeyGenValues, KmsEvent,
            OperationValue, Proof, ReencryptValues, TransactionId,
        },
        HexVector,
    };
    use kms_lib::{
        client::{test_tools, Client},
        consts::{
            AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT, DEFAULT_URL, TEST_KEY_ID, TEST_MSG,
            TEST_PARAM_PATH, TEST_REENC_ID, TEST_THRESHOLD_CT_PATH, TEST_THRESHOLD_KEYS_PATH,
            THRESHOLD,
        },
        kms::{AggregatedReencryptionResponse, DecryptionResponsePayload, ReencryptionResponse},
        rpc::rpc_types::{Plaintext, PrivDataType, PubDataType, CURRENT_FORMAT_VERSION},
        storage::{FileStorage, PublicStorage, PublicStorageReader, StorageType},
        threshold::mock_threshold_kms::setup_mock_kms,
        util::{
            file_handling::read_element_async,
            key_setup::{
                ensure_ciphertext_exist, ensure_dir_exist, ensure_threshold_keys_exist,
                ThresholdTestingKeys,
            },
        },
    };
    use tokio::task::JoinSet;

    async fn setup_keys() {
        ensure_dir_exist();
        ensure_threshold_keys_exist(
            TEST_PARAM_PATH,
            TEST_THRESHOLD_KEYS_PATH,
            &TEST_KEY_ID.to_string(),
        )
        .await;
        let threshold_keys: ThresholdTestingKeys =
            read_element_async(format!("{TEST_THRESHOLD_KEYS_PATH}-1.bin"))
                .await
                .unwrap();
        ensure_ciphertext_exist(TEST_THRESHOLD_CT_PATH, &threshold_keys.fhe_pub);
    }

    /// Before running this function, ensure [setup_keys] is executed
    async fn generic_sunshine_test(
        slow: bool,
        op: OperationValue,
    ) -> (Vec<KmsOperationResponse>, TransactionId, Vec<u32>) {
        let txn_id = TransactionId::from(vec![2u8; 20]);

        let coordinator_handles = if slow {
            let mut pub_storage = FileStorage::new(&StorageType::PUB.to_string());
            // Delete potentially existing CRS
            let _ = pub_storage
                .delete_data(
                    &pub_storage
                        .compute_url(&txn_id.to_hex(), &PubDataType::CRS.to_string())
                        .unwrap(),
                )
                .await;
            let mut priv_storage = Vec::new();
            for i in 1..=AMOUNT_PARTIES {
                let cur_priv = FileStorage::new(&format!("priv-p{i}"));
                // Delete potentially existing CRS info
                let _ = pub_storage
                    .delete_data(
                        &cur_priv
                            .compute_url(&txn_id.to_hex(), &PrivDataType::CrsInfo.to_string())
                            .unwrap(),
                    )
                    .await;
                priv_storage.push(cur_priv);
            }
            test_tools::setup_threshold_no_client(THRESHOLD as u8, pub_storage, priv_storage).await
        } else {
            setup_mock_kms(AMOUNT_PARTIES).await
        };

        // create configs
        let configs = (0..AMOUNT_PARTIES as u16)
            .map(|i| {
                let port = BASE_PORT + i + 1;
                let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
                CoordinatorConfig {
                    addresses: vec![url],
                    shares_needed: THRESHOLD as u64 + 1,
                    timeout_config: if slow {
                        TimeoutConfig::testing_default()
                    } else {
                        TimeoutConfig::mocking_default()
                    },
                }
            })
            .collect::<Vec<_>>();

        // create the clients
        let mut clients = vec![];
        for config in configs {
            clients.push(
                KmsCoordinator::new(config.clone(), OpenTelemetryMetrics::new())
                    .await
                    .unwrap(),
            );
        }

        // create events
        let events = vec![
            KmsEvent::builder()
                .operation(op.clone())
                .txn_id(txn_id.clone())
                .proof(Proof::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
                .build();
            AMOUNT_PARTIES
        ];

        // each client will make the request
        // but this needs to happen in parallel
        assert_eq!(events.len(), clients.len());
        let mut tasks = JoinSet::new();
        for (i, (event, client)) in events.into_iter().zip(clients).enumerate() {
            let op = client.create_kms_operation(event, op.clone()).unwrap();
            tasks.spawn(async move { (i as u32 + 1, op.run_operation().await) });
        }
        let mut results = vec![];
        let mut ids = vec![];
        // tasks.join_next().await.unwrap().unwrap().1.unwrap();
        while let Some(Ok((i, Ok(res)))) = tasks.join_next().await {
            results.push(res);
            ids.push(i);
        }
        assert_eq!(results.len(), AMOUNT_PARTIES);

        for (_, h) in coordinator_handles {
            h.abort();
        }

        (results, txn_id, ids)
    }

    async fn ddec_sunshine(slow: bool) {
        setup_keys().await;
        let (ct, fhe_type): (Vec<u8>, kms_lib::kms::FheType) =
            read_element_async(TEST_THRESHOLD_CT_PATH.to_string())
                .await
                .unwrap();
        let op = OperationValue::Decrypt(
            DecryptValues::builder()
                .version(CURRENT_FORMAT_VERSION)
                .servers_needed(THRESHOLD as u32 + 1)
                .key_id(HexVector::from_hex(&TEST_KEY_ID.request_id).unwrap())
                .fhe_type(WrappingFheType::try_from(fhe_type as i32).unwrap().0)
                .ciphertext(ct)
                .randomness(vec![1, 2, 3])
                .build(),
        );
        let (results, txn_id, _) = generic_sunshine_test(slow, op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        for result in results {
            match result {
                KmsOperationResponse::DecryptResponse(resp) => {
                    let payload: DecryptionResponsePayload = serde_asn1_der::from_bytes(
                        <&HexVector as Into<Vec<u8>>>::into(resp.decrypt_response.payload())
                            .as_slice(),
                    )
                    .unwrap();
                    assert_eq!(
                        serde_asn1_der::from_bytes::<Plaintext>(&payload.plaintext)
                            .unwrap()
                            .as_u8(),
                        TEST_MSG
                    );
                    assert_eq!(payload.version, CURRENT_FORMAT_VERSION);
                    assert_eq!(resp.operation_val.tx_id, txn_id);
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }

    async fn reenc_sunshine(slow: bool) {
        setup_keys().await;
        let (ct, fhe_type): (Vec<u8>, kms_lib::kms::FheType) =
            read_element_async(TEST_THRESHOLD_CT_PATH.to_string())
                .await
                .unwrap();

        // we need a KMS client to simply the boilerplate
        // for setting up the request correctly
        let testing_keys: ThresholdTestingKeys =
            read_element_async(format!("{TEST_THRESHOLD_KEYS_PATH}-1.bin"))
                .await
                .unwrap();
        let mut kms_client = Client::new(
            HashSet::from_iter(testing_keys.server_keys),
            testing_keys.client_pk,
            Some(testing_keys.client_sk),
            THRESHOLD as u32 + 1,
            AMOUNT_PARTIES as u32,
            testing_keys.params.to_noiseflood_parameters(),
        );

        fn dummy_domain() -> alloy_sol_types::Eip712Domain {
            alloy_sol_types::eip712_domain!(
                name: "dummy",
                version: "1",
                chain_id: 1,
                verifying_contract: alloy_primitives::Address::ZERO,
            )
        }

        let request_id = &TEST_REENC_ID;
        let key_id = &TEST_KEY_ID;
        let (kms_req, enc_pk, enc_sk) = kms_client
            .reencryption_request(ct, &dummy_domain(), fhe_type, request_id, key_id)
            .unwrap();
        let payload = kms_req.payload.clone().unwrap();
        let eip712 = kms_req.domain.clone().unwrap();
        let op = OperationValue::Reencrypt(
            ReencryptValues::builder()
                .signature(kms_req.signature.clone())
                .version(payload.version)
                .servers_needed(payload.servers_needed)
                .verification_key(payload.verification_key)
                .randomness(payload.randomness)
                .enc_key(payload.enc_key)
                .fhe_type(WrappingFheType::try_from(payload.fhe_type).unwrap().0)
                .key_id(HexVector::from_hex(payload.key_id.unwrap().request_id.as_str()).unwrap())
                .ciphertext(payload.ciphertext.unwrap())
                .ciphertext_digest(payload.ciphertext_digest)
                .eip712_name(eip712.name)
                .eip712_version(eip712.version)
                .eip712_chain_id(eip712.chain_id)
                .eip712_verifying_contract(eip712.verifying_contract)
                .eip712_salt(eip712.salt)
                .build(),
        );
        let (results, txn_id, ids) = generic_sunshine_test(slow, op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        if slow {
            // process the result using the kms client when we're running in the slow mode
            // i.e., it is an integration test
            let agg_resp = AggregatedReencryptionResponse {
                responses: HashMap::from_iter(ids.into_iter().zip(results.into_iter().map(|r| {
                    let r = match r {
                        KmsOperationResponse::ReencryptResponse(resp) => resp,
                        _ => panic!("invalid response"),
                    }
                    .reencrypt_response;
                    ReencryptionResponse {
                        version: r.version(),
                        servers_needed: r.servers_needed(),
                        verification_key: r.verification_key().into(),
                        digest: r.digest().into(),
                        fhe_type: r.fhe_type() as i32,
                        signcrypted_ciphertext: r.signcrypted_ciphertext().into(),
                    }
                }))),
            };
            _ = kms_client
                .process_reencryption_resp(Some(kms_req), &agg_resp, &enc_pk, &enc_sk)
                .unwrap()
        } else {
            // otherwise just check that we're getting dummy values back
            for result in results {
                match result {
                    KmsOperationResponse::ReencryptResponse(resp) => {
                        let payload = &resp.reencrypt_response;
                        assert_eq!(resp.operation_val.tx_id, txn_id);
                        assert_eq!(payload.version(), CURRENT_FORMAT_VERSION);
                        assert_eq!(
                            payload.digest().clone(),
                            <Vec<u8> as Into<HexVector>>::into("dummy digest".as_bytes().to_vec())
                        );
                    }
                    _ => {
                        panic!("invalid response");
                    }
                }
            }
        }
    }

    async fn keygen_sunshine(slow: bool) {
        setup_keys().await;
        if slow {
            panic!("slow/integration test is not supported since there's no preprocessing material")
        }

        let op = OperationValue::KeyGen(
            KeyGenValues::builder()
                .preproc_id(
                    HexVector::from_hex("1111111111111111111111111111111111112222").unwrap(),
                )
                .build(),
        );
        let (results, txn_id, _) = generic_sunshine_test(slow, op).await;
        for result in results {
            match result {
                KmsOperationResponse::KeyGenResponse(resp) => {
                    assert!(!resp.keygen_response.public_key_digest().is_empty());
                    assert!(!resp.keygen_response.public_key_signature().0.is_empty());
                    assert!(!resp.keygen_response.server_key_digest().is_empty());
                    assert!(!resp.keygen_response.server_key_signature().0.is_empty());
                    assert_eq!(resp.operation_val.tx_id, txn_id);
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }

    async fn preproc_sunshine(slow: bool) {
        setup_keys().await;
        let op = OperationValue::KeyGenPreproc(KeyGenPreprocValues {});
        let (results, txn_id, _) = generic_sunshine_test(slow, op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        for result in results {
            match result {
                KmsOperationResponse::KeyGenPreprocResponse(resp) => {
                    assert_eq!(resp.operation_val.tx_id, txn_id);
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }

    async fn crs_sunshine(slow: bool) {
        setup_keys().await;
        let op = OperationValue::CrsGen(CrsGenValues {});
        let (results, txn_id, _) = generic_sunshine_test(slow, op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        // we stop testing the response logic in "fast" mode, which uses a dummy kms
        if !slow {
            return;
        }

        // the digests should all be the same but the signatures are all different
        let mut digest = None;
        let mut signature: Option<Vec<u8>> = None;
        for result in results {
            match result {
                KmsOperationResponse::CrsGenResponse(resp) => {
                    assert_eq!(resp.crs_gen_response.request_id(), txn_id.to_hex());
                    assert_eq!(resp.crs_gen_response.digest().len(), 40);
                    if digest.is_some() {
                        assert_eq!(digest.clone().unwrap(), resp.crs_gen_response.digest());
                    } else {
                        digest = Some(resp.crs_gen_response.digest().to_string());
                    }
                    assert_eq!(
                        <&HexVector as Into<Vec<u8>>>::into(resp.crs_gen_response.signature())
                            .len(),
                        72
                    );
                    if signature.is_some() {
                        assert_ne!(
                            signature.clone().unwrap(),
                            <&HexVector as Into<Vec<u8>>>::into(resp.crs_gen_response.signature())
                        );
                    } else {
                        signature = Some(resp.crs_gen_response.signature().into());
                    }
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ddec_sunshine_mocked_coordinator() {
        ddec_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn reenc_sunshine_mocked_coordinator() {
        reenc_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn keygen_sunshine_mocked_coordinator() {
        keygen_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn preproc_sunshine_mocked_coordinator() {
        preproc_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn crs_sunshine_mocked_coordinator() {
        crs_sunshine(false).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn ddec_sunshine_slow() {
        ddec_sunshine(true).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn reenc_sunshine_slow() {
        reenc_sunshine(true).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn preproc_sunshine_slow() {
        preproc_sunshine(true).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn crs_sunshine_slow() {
        crs_sunshine(true).await
    }
}
