use super::metrics::OpenTelemetryMetrics;
use crate::conf::TimeoutConfig;
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse, ReencryptResponseVal,
    ZkpResponseVal,
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
    TransactionId, ZkpResponseValues, ZkpValues,
};
use events::HexVector;
use kms_lib::kms::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_lib::kms::{
    Config, CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse,
    DecryptionResponsePayload, Eip712DomainMsg, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenResult, ParamChoice, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse, ReencryptionResponsePayload, TypedCiphertext, ZkVerifyRequest,
    ZkVerifyResponse, ZkVerifyResponsePayload,
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

pub struct ZkpVal<S> {
    pub zkp: ZkpValues,
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
    Decrypt(DecryptVal<S>),
    Reencrypt(ReencryptVal<S>),
    Zkp(ZkpVal<S>),
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
            KmsOperationRequest::Decrypt(decrypt) => decrypt.run_operation(config_contract).await,
            KmsOperationRequest::Reencrypt(reencrypt) => {
                reencrypt.run_operation(config_contract).await
            }
            KmsOperationRequest::Zkp(zkp) => zkp.run_operation(config_contract).await,
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
    pub fn new(
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

    pub fn create_kms_operation(
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
            OperationValue::Zkp(zkp) => KmsOperationRequest::Zkp(ZkpVal { zkp, operation_val }),
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

        let kv_ct_handles = self.decrypt.ciphertext_handles();
        let fhe_types = self.decrypt.fhe_types();
        let external_handles = self.decrypt.external_handles();

        if kv_ct_handles.0.len() != fhe_types.len() {
            return Err(anyhow!(
                "ct_handles and fhe_types must have the same length, but did not: #ct_handles={} - #fhe_types={}",
                kv_ct_handles.0.len(),
                fhe_types.len()
            ));
        }

        // vector of TypedCiphertext to send to kms core to decrypt
        let mut ciphertexts = Vec::new();

        // iterate over ciphertext handles and get actual ciphertext values from storage
        for (idx, ch) in kv_ct_handles.0.iter().enumerate() {
            let kv_ct_handle = ch.0.clone();

            let ciphertext = self
                .operation_val
                .kms_client
                .storage
                .get_ciphertext(kv_ct_handle)
                .await?;
            tracing::info!("FHE Type: {:?}", fhe_types[idx]);

            // add external handle if it exists
            let external_handle = external_handles.as_ref().map(|ehs| ehs.0[idx].0.clone());

            ciphertexts.push(TypedCiphertext {
                ciphertext,
                fhe_type: fhe_types[idx] as i32,
                external_handle,
            });
        }

        // Decryption request for the kms core
        let req = DecryptionRequest {
            version,
            ciphertexts,
            key_id: Some(RequestId { request_id: key_id }),
            request_id: Some(req_id.clone()),
            domain: Some(Eip712DomainMsg {
                name: self.decrypt.eip712_name().to_string(),
                version: self.decrypt.eip712_version().to_string(),
                chain_id: self.decrypt.eip712_chain_id().into(),
                verifying_contract: self.decrypt.eip712_verifying_contract().to_string(),
                salt: self.decrypt.eip712_salt().into(),
            }),
            acl_address: Some(self.decrypt.acl_address().to_string()),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;
        // the response should be empty
        let _resp = client.decrypt(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating decryption to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
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

        let tx_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = tx_id.clone().try_into()?;

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

        let request = make_request(req.clone(), Some(tx_id.clone()))?;

        // the response should be empty
        let _resp = client.reencrypt(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating reencryption to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "Reencrypt")]);

        let g =
            |res: Result<Response<ReencryptionResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let payload: ReencryptionResponsePayload = inner.payload.ok_or_else(||anyhow!("empty reencryption payload"))?;
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
            client.get_reencrypt_result(make_request(req_id.clone(), Some(tx_id.clone()))?),
            g,
            timeout_triple,
            "(Reencrypt)",
            metrics
        );
    }
}

#[async_trait]
impl<S> KmsEventHandler for ZkpVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    async fn run_operation(
        &self,
        _config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoreServiceEndpointClient::new(chan.clone());

        let tx_id = self.operation_val.tx_id.to_hex();
        let req_id: RequestId = tx_id.clone().try_into()?;
        let zkp = &self.zkp;
        let ct_proof_handle: Vec<u8> = zkp.ct_proof_handle().deref().into();
        let ct_proof = self
            .operation_val
            .kms_client
            .storage
            .get_ciphertext(ct_proof_handle)
            .await?;
        let req = ZkVerifyRequest {
            request_id: Some(req_id.clone()),
            key_handle: Some(RequestId {
                request_id: zkp.key_id().to_hex(),
            }),
            crs_handle: Some(RequestId {
                request_id: zkp.crs_id().to_hex(),
            }),
            client_address: zkp.client_address().to_string(),
            contract_address: zkp.contract_address().to_string(),
            ct_bytes: ct_proof,
            acl_address: self.zkp.acl_address().to_string(),
            domain: Some(Eip712DomainMsg {
                name: self.zkp.eip712_name().to_string(),
                version: self.zkp.eip712_version().to_string(),
                chain_id: self.zkp.eip712_chain_id().into(),
                verifying_contract: self.zkp.eip712_verifying_contract().to_string(),
                salt: self.zkp.eip712_salt().into(),
            }),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(tx_id.clone()))?;
        // Response is just empty
        let _resp = client.zk_verify(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!("Error in ZKP verification: {}", err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "Zkp")]);

        let g =
            |res: Result<Response<ZkVerifyResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let payload: ZkVerifyResponsePayload = inner.payload.ok_or_else(||anyhow!("empty decryption payload"))?;
                    Ok(PollerStatus::Done(KmsOperationResponse::ZkpResponse(
                        ZkpResponseVal {
                            zkp_response: ZkpResponseValues::builder()
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
        let timeout_triple = self.operation_val.kms_client.timeout_config.zkp.clone();

        // loop to get response
        poller!(
            client.get_zk_verify_result(make_request(req_id.clone(), Some(tx_id.clone()))?),
            g,
            timeout_triple,
            "(Zkp)",
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
        let _resp = client.key_gen_preproc(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating Keygen Preproc to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
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
        let _resp = client.key_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating Keygen to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "KeyGen")]);

        let g =
            |res: Result<Response<KeyGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or_else(||anyhow!("empty request_id for keygen"))?;
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
            max_num_bits: None, // TODO: this will come in another PR
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.crs_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating CRS generation to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "CRS")]);

        let g =
            |res: Result<Response<CrsGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or_else(||anyhow!("empty request_id for CRS generation"))?;
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
