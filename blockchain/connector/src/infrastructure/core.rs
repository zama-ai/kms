use super::metrics::OpenTelemetryMetrics;
use crate::conf::TimeoutConfig;
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse, ReencryptResponseVal,
};
use crate::domain::kms::Kms;
use crate::domain::storage::Storage;
use crate::infrastructure::metrics::{MetricType, Metrics};
use anyhow::anyhow;
use async_trait::async_trait;
use conf_trace::grpc::make_request;
use enum_dispatch::enum_dispatch;
use events::kms::{
    DecryptResponseValues, DecryptValues, KeyGenPreprocResponseValues, KeyGenResponseValues,
    KeyGenValues, KmsCoreConf, KmsEvent, OperationValue, ReencryptResponseValues, ReencryptValues,
    TransactionId,
};
use events::HexVector;
use kms_lib::kms::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_lib::kms::{
    Config, CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse,
    DecryptionResponsePayload, Eip712DomainMsg, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenResult, ParamChoice, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse, ReencryptionResponsePayload, TypedCiphertext,
};
use kms_lib::kms::{KeyGenPreprocRequest, KeyGenRequest, RequestId};
use kms_lib::rpc::rpc_types::{PubDataType, CURRENT_FORMAT_VERSION};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::{Channel, Endpoint};
use tonic::{Response, Status};
use typed_builder::TypedBuilder;

pub struct KmsOperationVal<S> {
    pub kms_client: KmsCore<S>,
    pub tx_id: TransactionId,
}

pub struct DecryptVal<S> {
    pub decrypt: DecryptValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct ReencryptVal<S> {
    pub reencrypt: ReencryptValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct KeyGenPreprocVal<S> {
    pub operation_val: KmsOperationVal<S>,
}

pub struct KeyGenVal<S> {
    pub keygen: KeyGenValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct CrsGenVal<S> {
    pub operation_val: KmsOperationVal<S>,
}

pub enum KmsOperationRequest<S> {
    Reencrypt(ReencryptVal<S>),
    Decrypt(DecryptVal<S>),
    KeyGen(KeyGenVal<S>),
    KeyGenPreproc(KeyGenPreprocVal<S>),
    CrsGen(CrsGenVal<S>),
}

#[async_trait]
impl<S> KmsEventHandler for KmsOperationRequest<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        match self {
            KmsOperationRequest::Reencrypt(reencrypt) => {
                reencrypt.run_operation(config_contract).await
            }
            KmsOperationRequest::Decrypt(decrypt) => decrypt.run_operation(config_contract).await,
            KmsOperationRequest::KeyGenPreproc(keygen_preproc) => {
                keygen_preproc.run_operation(config_contract).await
            }
            KmsOperationRequest::KeyGen(keygen) => keygen.run_operation(config_contract).await,
            KmsOperationRequest::CrsGen(crsgen) => crsgen.run_operation(config_contract).await,
        }
    }
}

#[async_trait]
impl<S> Kms for KmsCore<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    async fn run(
        &self,
        event: KmsEvent,
        operation_value: OperationValue,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let operation = self.create_kms_operation(event, operation_value)?;
        operation.run_operation(config_contract).await
    }
}

#[async_trait]
#[enum_dispatch(KmsOperationRequest)]
pub trait KmsEventHandler {
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse>;
}

#[derive(Clone, TypedBuilder)]
pub struct KmsCore<S> {
    channel: Channel,
    metrics: Arc<OpenTelemetryMetrics>,
    timeout_config: TimeoutConfig,
    storage: S,
}

impl<S> KmsCore<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(
        config: crate::conf::CoreConfig,
        storage: S,
        metrics: OpenTelemetryMetrics,
    ) -> Result<Self, anyhow::Error> {
        // NOTE: we don't need multiple endpoints for now
        // but we keep it like this to match the blockchain implementation
        let endpoints = config
            .addresses()
            .iter()
            .map(|endpoint| Endpoint::new(endpoint.to_string()))
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| anyhow::anyhow!("Error connecting to core {:?}", e))?;

        let endpoints = endpoints.into_iter().map(|e| {
            e.timeout(Duration::from_secs(config.timeout_config.channel_timeout))
                .clone()
        });
        let channel = Channel::balance_list(endpoints);
        tracing::info!("Connecting to core server {:?}", config.addresses(),);
        Ok(KmsCore {
            channel,
            metrics: Arc::new(metrics),
            timeout_config: config.timeout_config.clone(),
            storage,
        })
    }

    fn create_kms_operation(
        &self,
        event: KmsEvent,
        operation_value: OperationValue,
    ) -> anyhow::Result<KmsOperationRequest<S>> {
        let operation_val = KmsOperationVal {
            kms_client: self.clone(),
            tx_id: event.txn_id().clone(),
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
                    $metrics.increment(MetricType::CoreResponseSuccess, 1, &[("ok", "ok")]);
                    return Ok(res);
                }
                Ok(PollerStatus::Poll) => {
                    if cnt > $timeout_triple.max_poll_count {
                        let err_msg =
                            format!("Time out after {cnt} tries while trying to get response");
                        $metrics.increment(
                            MetricType::CoreResponseError,
                            1,
                            &[("error", &err_msg)],
                        );
                        return Err(anyhow!(err_msg));
                    } else {
                        cnt += 1;
                        tracing::info!(
                            "Polling core {}, tries: {cnt}, timeout_triple: {:?}",
                            $info,
                            $timeout_triple,
                        );
                    }
                }
                Err(e) => {
                    let err_msg = format!("error while trying to get response {e}");
                    $metrics.increment(MetricType::CoreResponseError, 1, &[("error", &err_msg)]);
                    return Err(anyhow!(err_msg));
                }
            }
        }
    };
}

#[async_trait]
impl<S> KmsEventHandler for DecryptVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    async fn run_operation(
        &self,
        _config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoreServiceEndpointClient::new(chan.clone());

        if CURRENT_FORMAT_VERSION != self.decrypt.version() {
            return Err(anyhow!(
                "version not supported: supported={}, requested={}",
                CURRENT_FORMAT_VERSION,
                self.decrypt.version()
            ));
        }

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;

        let version = self.decrypt.version();
        let key_id = self.decrypt.key_id().to_hex();

        let ct_handles = self.decrypt.ciphertext_handles();
        let fhe_types = self.decrypt.fhe_types();

        if ct_handles.0.len() != fhe_types.len() {
            return Err(anyhow!(
                "ct_handles and fhe_types must have the same length, but did not: #ct_handles={} - #fhe_types={}",
                ct_handles.0.len(),
                fhe_types.len()
            ));
        }

        // vector of TypedCiphertext to send to kms core to decrypt
        let mut ciphertexts = Vec::new();

        // iterate over ciphertext handles and get actual ciphertext values from storage
        for (idx, ch) in ct_handles.0.iter().enumerate() {
            let ct_handle = ch.0.clone();

            let ciphertext = self
                .operation_val
                .kms_client
                .storage
                .get_ciphertext(ct_handle)
                .await?;

            ciphertexts.push(TypedCiphertext {
                ciphertext,
                fhe_type: fhe_types[idx] as i32,
            });
        }

        // decryption request for the kms core
        let req = DecryptionRequest {
            version,
            ciphertexts,
            key_id: Some(RequestId { request_id: key_id }),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;
        // the response should be empty
        let _resp = client.decrypt(request).await.map_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            e
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "Decrypt")]);

        let g =
            |res: Result<Response<DecryptionResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let payload: DecryptionResponsePayload = inner.payload.ok_or_else(||anyhow!("empty decryption payload"))?;
                        Ok(PollerStatus::Done(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
                            decrypt_response: DecryptResponseValues::builder()
                                .signature(inner.signature)
                                .payload(bincode::serialize(&payload)?)
                                .build(),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
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
            client.get_decrypt_result(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(Decrypt)",
            metrics
        );
    }
}

#[async_trait]
impl<S> KmsEventHandler for ReencryptVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    async fn run_operation(
        &self,
        _config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoreServiceEndpointClient::new(chan.clone());

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;

        if CURRENT_FORMAT_VERSION != self.reencrypt.version() {
            return Err(anyhow!(
                "version not supported: supported={}, requested={}",
                CURRENT_FORMAT_VERSION,
                self.reencrypt.version()
            ));
        }

        let reencrypt = &self.reencrypt;
        let ciphertext_handle: Vec<u8> = reencrypt.ciphertext_handle().deref().into();
        let ciphertext = self
            .operation_val
            .kms_client
            .storage
            .get_ciphertext(ciphertext_handle)
            .await?;
        let req = ReencryptionRequest {
            signature: self.reencrypt.signature().into(),
            payload: Some(ReencryptionRequestPayload {
                version: reencrypt.version(),
                client_address: reencrypt.client_address().to_string(),
                enc_key: reencrypt.enc_key().deref().into(),
                fhe_type: reencrypt.fhe_type() as i32,
                key_id: Some(RequestId {
                    request_id: reencrypt.key_id().to_hex(),
                }),
                ciphertext: Some(ciphertext),
                ciphertext_digest: reencrypt.ciphertext_digest().deref().into(),
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

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.reencrypt(request).await.map_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            e
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "Reencrypt")]);

        let g =
            |res: Result<Response<ReencryptionResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let payload: ReencryptionResponsePayload = inner.payload.ok_or_else(||anyhow!("empty decryption payload"))?;
                    Ok(PollerStatus::Done(KmsOperationResponse::ReencryptResponse(
                        ReencryptResponseVal {
                            reencrypt_response: ReencryptResponseValues::builder()
                                .signature(inner.signature)
                                .payload(bincode::serialize(&payload)?)
                                .build(),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
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
            client.get_reencrypt_result(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(Reencrypt)",
            metrics
        );
    }
}

#[async_trait]
impl<S> KmsEventHandler for KeyGenPreprocVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let param_choice_str = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice_string();
        let param_choice = ParamChoice::from_str_name(&param_choice_str).ok_or_else(|| {
            anyhow!(
                "invalid parameter choice string in prep: {}",
                param_choice_str
            )
        })?;

        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoreServiceEndpointClient::new(chan.clone());

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;
        let req = KeyGenPreprocRequest {
            config: Some(Config {}),
            params: param_choice.into(),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.key_gen_preproc(request).await.map_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            e
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "KeyGenPreproc")]);

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
            client.get_preproc_status(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(KeyGenPreproc)",
            metrics
        );
    }
}

#[async_trait]
impl<S> KmsEventHandler for KeyGenVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let param_choice_str = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice_string();
        let param_choice = ParamChoice::from_str_name(&param_choice_str).ok_or_else(|| {
            anyhow!(
                "invalid parameter choice string in keygen: {}",
                param_choice_str
            )
        })?;

        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoreServiceEndpointClient::new(chan.clone());

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;
        let preproc_id = self.keygen.preproc_id().to_hex().try_into()?;
        let req = KeyGenRequest {
            config: Some(Config {}),
            params: param_choice.into(),
            preproc_id: Some(preproc_id),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.key_gen(request).await.map_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            e
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "KeyGen")]);

        let g =
            |res: Result<Response<KeyGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or_else(||anyhow!("empty request_id"))?;
                        let pk_info = inner
                            .key_results
                            .get(&PubDataType::PublicKey.to_string())
                            .ok_or_else(||anyhow!("empty public key info"))?;
                        let ek_info = inner
                            .key_results
                            .get(&PubDataType::ServerKey.to_string())
                            .ok_or_else(||anyhow!("empty evaluation key info"))?;
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
            client.get_key_gen_result(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(KeyGen)",
            metrics
        );
    }
}

#[async_trait]
impl<S> KmsEventHandler for CrsGenVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let param_choice_str = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice_string();
        let param_choice = ParamChoice::from_str_name(&param_choice_str).ok_or_else(|| {
            anyhow!(
                "invalid parameter choice string in crsgen: {}",
                param_choice_str
            )
        })?;

        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoreServiceEndpointClient::new(chan.clone());

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;
        let req = CrsGenRequest {
            config: Some(Config {}),
            params: param_choice.into(),
            request_id: Some(req_id.clone()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.crs_gen(request).await.map_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            e
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "CRS")]);

        let g =
            |res: Result<Response<CrsGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or_else(||anyhow!("empty request_id"))?;
                        let crs_results = inner.crs_results.ok_or_else(||anyhow!("empty crs result"))?;
                        Ok(PollerStatus::Done(KmsOperationResponse::CrsGenResponse(
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
                        )))
                    }
                    Err(_) => Ok(PollerStatus::Poll),
                }
            };

        let timeout_triple = self.operation_val.kms_client.timeout_config.crs.clone();
        poller!(
            client.get_crs_gen_result(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(CRS)",
            metrics
        );
    }
}

#[cfg(test)]
mod test {
    use super::KmsEventHandler as _;
    use crate::{
        conf::{CoreConfig, TimeoutConfig},
        domain::{blockchain::KmsOperationResponse, storage::Storage},
        infrastructure::{core::KmsCore, metrics::OpenTelemetryMetrics},
    };
    use events::kms::{
        CrsGenValues, FheParameter, KeyGenPreprocValues, KmsCoreConf, KmsCoreParty,
        KmsCoreThresholdConf, KmsEvent, TransactionId,
    };
    use events::{
        kms::{DecryptValues, KeyGenValues, OperationValue, ReencryptValues},
        HexVector,
    };
    use kms_lib::{
        client::{test_tools, Client, ParsedReencryptionRequest},
        consts::{
            AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT, DEFAULT_URL, OTHER_CENTRAL_TEST_ID,
            SIGNING_KEY_ID, TEST_CENTRAL_KEY_ID, TEST_PARAM_PATH, TEST_THRESHOLD_KEY_ID, THRESHOLD,
        },
        kms::{
            DecryptionResponsePayload, ReencryptionResponse, ReencryptionResponsePayload, RequestId,
        },
        rpc::rpc_types::{protobuf_to_alloy_domain, Plaintext, CURRENT_FORMAT_VERSION},
        storage::{FileStorage, StorageType},
        threshold::mock_threshold_kms::setup_mock_kms,
        util::key_setup::{
            ensure_central_keys_exist, ensure_central_server_signing_keys_exist,
            ensure_client_keys_exist, ensure_threshold_keys_exist,
            ensure_threshold_server_signing_keys_exist,
            test_tools::{compute_cipher_from_storage, purge},
        },
    };
    use rand::RngCore;
    use std::collections::HashMap;
    use tokio::task::JoinSet;

    const MOCK_CT_HANDLES: &[&[u8]] = &[
        &[0, 0, 0],
        &[1, 1, 1],
        &[2, 2, 2],
        &[3, 3, 3],
        &[4, 4, 4],
        &[5, 5, 5],
    ];

    async fn setup_threshold_keys() {
        let mut threshold_pub_storages = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            threshold_pub_storages
                .push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
        }
        let mut threshold_priv_storages = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            threshold_priv_storages
                .push(FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap());
        }

        ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;
        ensure_threshold_server_signing_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            &SIGNING_KEY_ID,
            true,
            AMOUNT_PARTIES,
        )
        .await;
        ensure_threshold_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            TEST_PARAM_PATH,
            &TEST_THRESHOLD_KEY_ID,
            true,
        )
        .await;
    }

    async fn setup_central_keys() {
        let mut central_pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let mut central_priv_storage =
            FileStorage::new_centralized(None, StorageType::PRIV).unwrap();

        ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;
        ensure_central_server_signing_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;
        ensure_central_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            TEST_PARAM_PATH,
            &TEST_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_TEST_ID,
            true,
            false,
        )
        .await;
    }

    #[derive(Clone)]
    struct MockStorage {
        pub ciphertext: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            MockStorage {
                ciphertext: HashMap::new(),
            }
        }
    }
    #[async_trait::async_trait]
    impl Storage for MockStorage {
        async fn get_ciphertext(&self, ciphertext_handle: Vec<u8>) -> anyhow::Result<Vec<u8>> {
            self.ciphertext
                .get(&ciphertext_handle)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("ciphertext not found"))
        }
    }

    async fn generic_centralized_sunshine_test(
        cts: Vec<Vec<u8>>,
        op: OperationValue,
    ) -> (KmsOperationResponse, TransactionId) {
        assert!(
            cts.len() <= MOCK_CT_HANDLES.len(),
            "Not enough MOCK_CT_HANDLES defined!"
        );

        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let priv_storage = FileStorage::new_centralized(None, StorageType::PRIV).unwrap();
        let join_handle = test_tools::setup_centralized_no_client(pub_storage, priv_storage).await;

        let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
        let config = CoreConfig {
            addresses: vec![url],
            timeout_config: TimeoutConfig::mocking_default(),
        };

        let mut mock_storage = MockStorage::new();

        for (idx, ct) in cts.iter().enumerate() {
            mock_storage
                .ciphertext
                .insert(MOCK_CT_HANDLES[idx].to_vec(), ct.clone());
        }

        let client =
            KmsCore::new(config.clone(), mock_storage, OpenTelemetryMetrics::new()).unwrap();

        let mut txn_buf = vec![0u8; 20];
        rand::thread_rng().fill_bytes(&mut txn_buf);

        let txn_id = TransactionId::from(txn_buf);
        let event = KmsEvent::builder()
            .operation(op.clone())
            .txn_id(txn_id.clone())
            .build();

        let conf = KmsCoreConf::Centralized(FheParameter::Test);

        let result = client
            .create_kms_operation(event, op.clone())
            .unwrap()
            .run_operation(Some(conf))
            .await
            .unwrap();

        join_handle.abort();
        (result, txn_id)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ddec_centralized_sunshine() {
        let msg1 = 110u8;
        let msg2 = 222u16;
        setup_central_keys().await;
        let (ct1, fhe_type1): (Vec<u8>, kms_lib::kms::FheType) =
            compute_cipher_from_storage(None, msg1.into(), &TEST_CENTRAL_KEY_ID.to_string()).await;
        let (ct2, fhe_type2): (Vec<u8>, kms_lib::kms::FheType) =
            compute_cipher_from_storage(None, msg2.into(), &TEST_CENTRAL_KEY_ID.to_string()).await;
        let op = OperationValue::Decrypt(
            DecryptValues::builder()
                .version(CURRENT_FORMAT_VERSION)
                .key_id(HexVector::from_hex(&TEST_CENTRAL_KEY_ID.request_id).unwrap())
                .fhe_types(vec![
                    events::kms::FheType::from(fhe_type1 as u8),
                    events::kms::FheType::from(fhe_type2 as u8),
                ])
                .ciphertext_handles(vec![
                    MOCK_CT_HANDLES[0].to_vec(),
                    MOCK_CT_HANDLES[1].to_vec(),
                ])
                .build(),
        );
        let (result, txn_id) = generic_centralized_sunshine_test(vec![ct1, ct2], op).await;
        match result {
            KmsOperationResponse::DecryptResponse(resp) => {
                let payload: DecryptionResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(resp.decrypt_response.payload()).as_slice(),
                )
                .unwrap();

                assert_eq!(
                    bincode::deserialize::<Plaintext>(&payload.plaintexts[0])
                        .unwrap()
                        .as_u8(),
                    msg1,
                );
                assert_eq!(
                    bincode::deserialize::<Plaintext>(&payload.plaintexts[1])
                        .unwrap()
                        .as_u16(),
                    msg2,
                );
                assert_eq!(payload.version, CURRENT_FORMAT_VERSION);
                assert_eq!(resp.operation_val.tx_id, txn_id);
            }
            _ => {
                panic!("invalid response");
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn keygen_sunshine_central() {
        setup_central_keys().await;

        // the preproc_id can just be some dummy value since
        // the centralized case does not need it
        let op = OperationValue::KeyGen(
            KeyGenValues::builder()
                .preproc_id(
                    HexVector::from_hex("1111111111111111111111111111111111112222").unwrap(),
                )
                .build(),
        );
        let (result, txn_id) = generic_centralized_sunshine_test(vec![], op).await;
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

    #[tokio::test]
    #[serial_test::serial]
    async fn crs_sunshine_central() {
        setup_central_keys().await;
        let op = OperationValue::CrsGen(CrsGenValues {});
        let (result, txn_id) = generic_centralized_sunshine_test(vec![], op).await;
        match result {
            KmsOperationResponse::CrsGenResponse(resp) => {
                assert_eq!(resp.crs_gen_response.request_id(), txn_id.to_hex());
                assert_eq!(resp.crs_gen_response.digest().len(), 40);
                assert_eq!(
                    <&HexVector as Into<Vec<u8>>>::into(resp.crs_gen_response.signature()).len(),
                    72
                );
            }
            _ => {
                panic!("invalid response");
            }
        }
    }

    /// Before running this function, ensure [setup_keys] is executed
    async fn generic_sunshine_test(
        slow: bool,
        cts: Vec<Vec<u8>>,
        op: OperationValue,
    ) -> (Vec<KmsOperationResponse>, TransactionId, Vec<u32>) {
        let txn_id = TransactionId::from(vec![2u8; 20]);
        let core_handles = if slow {
            // Delete potentially existing CRS
            purge(None, None, &txn_id.to_hex()).await;
            let mut pub_storage = Vec::new();
            let mut priv_storage = Vec::new();
            for i in 1..=AMOUNT_PARTIES {
                let cur_pub = FileStorage::new_threshold(None, StorageType::PUB, i).unwrap();
                pub_storage.push(cur_pub);
                let cur_priv = FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap();
                priv_storage.push(cur_priv);
            }
            test_tools::setup_threshold_no_client(THRESHOLD as u8, pub_storage, priv_storage, true)
                .await
        } else {
            setup_mock_kms(AMOUNT_PARTIES).await
        };
        assert_eq!(core_handles.len(), AMOUNT_PARTIES);

        // create configs
        let configs = (0..AMOUNT_PARTIES as u16)
            .map(|i| {
                let port = BASE_PORT + (i + 1) * 100;
                let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
                CoreConfig {
                    addresses: vec![url],
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
            let mut mock_storage = MockStorage::new();
            for (idx, ct) in cts.iter().enumerate() {
                mock_storage
                    .ciphertext
                    .insert(MOCK_CT_HANDLES[idx].to_vec(), ct.clone());
            }
            clients.push(
                KmsCore::new(config.clone(), mock_storage, OpenTelemetryMetrics::new()).unwrap(),
            );
        }

        // create events
        let events = vec![
            KmsEvent::builder()
                .operation(op.clone())
                .txn_id(txn_id.clone())
                .build();
            AMOUNT_PARTIES
        ];

        // each client will make the request
        // but this needs to happen in parallel
        assert_eq!(events.len(), clients.len());
        let mut tasks = JoinSet::new();
        for (i, (event, client)) in events.into_iter().zip(clients).enumerate() {
            let conf = KmsCoreConf::Threshold(KmsCoreThresholdConf {
                parties: vec![KmsCoreParty::default(); AMOUNT_PARTIES],
                response_count_for_majority_vote: 2 * THRESHOLD + 1,
                response_count_for_reconstruction: THRESHOLD + 2,
                degree_for_reconstruction: THRESHOLD,
                param_choice: FheParameter::Test,
            });
            let op = client.create_kms_operation(event, op.clone()).unwrap();
            tasks.spawn(async move { (i as u32 + 1, op.run_operation(Some(conf)).await) });
        }
        let mut results = vec![];
        let mut ids = vec![];
        while let Some(Ok((i, Ok(res)))) = tasks.join_next().await {
            results.push(res);
            ids.push(i);
        }
        assert_eq!(results.len(), AMOUNT_PARTIES);

        for h in core_handles.values() {
            h.abort();
        }
        for (_, handle) in core_handles {
            assert!(handle.await.unwrap_err().is_cancelled());
        }

        (results, txn_id, ids)
    }

    async fn ddec_sunshine(slow: bool) {
        setup_threshold_keys().await;
        let msg1 = 121u8;
        let msg2 = 321u16;
        let (ct1, fhe_type1): (Vec<u8>, kms_lib::kms::FheType) =
            compute_cipher_from_storage(None, msg1.into(), &TEST_THRESHOLD_KEY_ID.to_string())
                .await;
        let (ct2, fhe_type2): (Vec<u8>, kms_lib::kms::FheType) =
            compute_cipher_from_storage(None, msg2.into(), &TEST_THRESHOLD_KEY_ID.to_string())
                .await;
        let op = OperationValue::Decrypt(
            DecryptValues::builder()
                .version(CURRENT_FORMAT_VERSION)
                .key_id(HexVector::from_hex(&TEST_THRESHOLD_KEY_ID.request_id).unwrap())
                .fhe_types(vec![
                    events::kms::FheType::from(fhe_type1 as u8),
                    events::kms::FheType::from(fhe_type2 as u8),
                ])
                .ciphertext_handles(vec![
                    MOCK_CT_HANDLES[0].to_vec(),
                    MOCK_CT_HANDLES[1].to_vec(),
                ])
                .build(),
        );
        let (results, txn_id, _) = generic_sunshine_test(slow, vec![ct1, ct2], op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        for result in results {
            match result {
                KmsOperationResponse::DecryptResponse(resp) => {
                    let payload: DecryptionResponsePayload = bincode::deserialize(
                        <&HexVector as Into<Vec<u8>>>::into(resp.decrypt_response.payload())
                            .as_slice(),
                    )
                    .unwrap();
                    if slow {
                        assert_eq!(
                            bincode::deserialize::<Plaintext>(&payload.plaintexts[0])
                                .unwrap()
                                .as_u8(),
                            msg1,
                        );
                        assert_eq!(
                            bincode::deserialize::<Plaintext>(&payload.plaintexts[1])
                                .unwrap()
                                .as_u16(),
                            msg2,
                        );
                    }
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
        setup_threshold_keys().await;
        let msg = 111u8;
        let (ct, fhe_type): (Vec<u8>, kms_lib::kms::FheType) =
            compute_cipher_from_storage(None, msg.into(), &TEST_THRESHOLD_KEY_ID.to_string()).await;

        // we need a KMS client to simply the boilerplate
        // for setting up the request correctly
        let mut pub_storage = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            pub_storage.push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
        }
        let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
        let mut kms_client = Client::new_client(client_storage, pub_storage, TEST_PARAM_PATH)
            .await
            .unwrap();

        fn dummy_domain() -> alloy_sol_types::Eip712Domain {
            alloy_sol_types::eip712_domain!(
                name: "dummy",
                version: "1",
                chain_id: 1,
                verifying_contract: alloy_primitives::Address::ZERO,
            )
        }

        let request_id = RequestId {
            request_id: "1111000000000000000000000000000000001111".to_string(),
        };
        let key_id = &TEST_THRESHOLD_KEY_ID;
        let (kms_req, enc_pk, enc_sk) = kms_client
            .reencryption_request(ct.clone(), &dummy_domain(), fhe_type, &request_id, key_id)
            .unwrap();
        let payload = kms_req.payload.clone().unwrap();
        let eip712 = kms_req.domain.clone().unwrap();
        let op = OperationValue::Reencrypt(
            ReencryptValues::builder()
                .signature(kms_req.signature.clone())
                .version(payload.version)
                .client_address(payload.client_address)
                .enc_key(payload.enc_key)
                .fhe_type(events::kms::FheType::from(fhe_type as u8))
                .key_id(HexVector::from_hex(payload.key_id.unwrap().request_id.as_str()).unwrap())
                .ciphertext_handle(MOCK_CT_HANDLES[0].to_vec())
                .ciphertext_digest(payload.ciphertext_digest)
                .eip712_name(eip712.name)
                .eip712_version(eip712.version)
                .eip712_chain_id(eip712.chain_id)
                .eip712_verifying_contract(eip712.verifying_contract)
                .eip712_salt(eip712.salt)
                .build(),
        );
        let (results, txn_id, _) = generic_sunshine_test(slow, vec![ct], op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        if slow {
            // process the result using the kms client when we're running in the slow mode
            // i.e., it is an integration test
            let agg_resp: Vec<ReencryptionResponse> = results
                .into_iter()
                .map(|r| {
                    let r = match r {
                        KmsOperationResponse::ReencryptResponse(resp) => resp,
                        _ => panic!("invalid response"),
                    }
                    .reencrypt_response;

                    let payload: ReencryptionResponsePayload = bincode::deserialize(
                        <&HexVector as Into<Vec<u8>>>::into(r.payload()).as_slice(),
                    )
                    .unwrap();
                    ReencryptionResponse {
                        signature: r.signature().to_vec(),
                        payload: Some(payload),
                    }
                })
                .collect();

            let eip712_domain = protobuf_to_alloy_domain(kms_req.domain.as_ref().unwrap()).unwrap();
            let client_request = ParsedReencryptionRequest::try_from(&kms_req).unwrap();
            let pt = kms_client
                .process_reencryption_resp(
                    &client_request,
                    &eip712_domain,
                    &agg_resp,
                    &enc_pk,
                    &enc_sk,
                )
                .unwrap();
            assert_eq!(pt.as_u8(), msg);
        } else {
            // otherwise just check that we're getting dummy values back
            for result in results {
                match result {
                    KmsOperationResponse::ReencryptResponse(resp) => {
                        let resp_value = &resp.reencrypt_response;
                        assert_eq!(resp.operation_val.tx_id, txn_id);
                        let payload: ReencryptionResponsePayload =
                            bincode::deserialize(resp_value.payload().as_slice()).unwrap();
                        assert_eq!(payload.version, CURRENT_FORMAT_VERSION);
                        assert_eq!(payload.digest, "dummy digest".as_bytes().to_vec());
                    }
                    _ => {
                        panic!("invalid response");
                    }
                }
            }
        }
    }

    async fn keygen_sunshine(slow: bool) {
        setup_threshold_keys().await;
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
        let (results, txn_id, _) = generic_sunshine_test(slow, vec![], op).await;
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
        setup_threshold_keys().await;
        let op = OperationValue::KeyGenPreproc(KeyGenPreprocValues {});
        let (results, txn_id, _) = generic_sunshine_test(slow, vec![], op).await;
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
        setup_threshold_keys().await;
        let op = OperationValue::CrsGen(CrsGenValues {});
        let (results, txn_id, _) = generic_sunshine_test(slow, vec![], op).await;
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
    #[tracing_test::traced_test]
    async fn ddec_sunshine_mocked_core() {
        ddec_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn reenc_sunshine_mocked_core() {
        reenc_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn keygen_sunshine_mocked_core() {
        keygen_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn preproc_sunshine_mocked_core() {
        preproc_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn crs_sunshine_mocked_core() {
        crs_sunshine(false).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    #[tracing_test::traced_test]
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
