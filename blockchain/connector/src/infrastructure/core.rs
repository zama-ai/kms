use super::metrics::OpenTelemetryMetrics;
use crate::conf::TimeoutConfig;
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse, ReencryptResponseVal,
    VerifyProvenCtResponseVal,
};
use crate::domain::kms::Kms;
use crate::domain::storage::Storage;
use crate::infrastructure::metrics::{MetricType, Metrics};
use anyhow::anyhow;
use async_trait::async_trait;
use conf_trace::grpc::make_request;
use conf_trace::telemetry::ContextPropagator;
use enum_dispatch::enum_dispatch;
use events::kms::{
    CrsGenValues, DecryptResponseValues, DecryptValues, InsecureCrsGenValues, InsecureKeyGenValues,
    KeyGenPreprocResponseValues, KeyGenResponseValues, KeyGenValues, KmsCoreConf, KmsEvent,
    OperationValue, ReencryptResponseValues, ReencryptValues, TransactionId,
    VerifyProvenCtResponseValues, VerifyProvenCtValues,
};
use events::HexVector;
use kms_lib::kms::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_lib::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Eip712DomainMsg, KeyGenPreprocStatus, KeyGenPreprocStatusEnum, KeyGenResult, ParamChoice,
    ReencryptionRequest, ReencryptionRequestPayload, ReencryptionResponse,
    ReencryptionResponsePayload, TypedCiphertext, VerifyProvenCtRequest, VerifyProvenCtResponse,
    VerifyProvenCtResponsePayload,
};
use kms_lib::kms::{KeyGenPreprocRequest, KeyGenRequest, RequestId};
use kms_lib::rpc::rpc_types::{PubDataType, CURRENT_FORMAT_VERSION};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
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

pub struct VerifyProvenCtVal<S> {
    pub verify_proven_ct: VerifyProvenCtValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct KeyGenPreprocVal<S> {
    pub operation_val: KmsOperationVal<S>,
}

pub struct KeyGenVal<S> {
    pub keygen: KeyGenValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct InsecureKeyGenVal<S> {
    pub insecure_key_gen: InsecureKeyGenValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct CrsGenVal<S> {
    pub crsgen: CrsGenValues,
    pub operation_val: KmsOperationVal<S>,
}

pub struct InsecureCrsGenVal<S> {
    pub insecure_crs_gen: InsecureCrsGenValues,
    pub operation_val: KmsOperationVal<S>,
}

pub enum KmsOperationRequest<S> {
    Decrypt(DecryptVal<S>),
    Reencrypt(ReencryptVal<S>),
    VerifyProvenCt(VerifyProvenCtVal<S>),
    KeyGen(KeyGenVal<S>),
    InsecureKeyGen(InsecureKeyGenVal<S>),
    KeyGenPreproc(KeyGenPreprocVal<S>),
    CrsGen(CrsGenVal<S>),
    InsecureCrsGen(InsecureCrsGenVal<S>),
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
            KmsOperationRequest::VerifyProvenCt(verify_proven_ct) => {
                verify_proven_ct.run_operation(config_contract).await
            }
            KmsOperationRequest::KeyGenPreproc(keygen_preproc) => {
                keygen_preproc.run_operation(config_contract).await
            }
            KmsOperationRequest::KeyGen(keygen) => keygen.run_operation(config_contract).await,
            KmsOperationRequest::InsecureKeyGen(insecure_key_gen) => {
                insecure_key_gen.run_operation(config_contract).await
            }
            KmsOperationRequest::CrsGen(crsgen) => crsgen.run_operation(config_contract).await,
            KmsOperationRequest::InsecureCrsGen(insecure_crs_gen) => {
                insecure_crs_gen.run_operation(config_contract).await
            }
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
            OperationValue::VerifyProvenCt(verify_proven_ct) => {
                KmsOperationRequest::VerifyProvenCt(VerifyProvenCtVal {
                    verify_proven_ct,
                    operation_val,
                })
            }
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
            OperationValue::InsecureKeyGen(insecure_key_gen) => {
                KmsOperationRequest::InsecureKeyGen(InsecureKeyGenVal {
                    insecure_key_gen,
                    operation_val,
                })
            }
            OperationValue::CrsGen(crsgen) => KmsOperationRequest::CrsGen(CrsGenVal {
                crsgen,
                operation_val,
            }),
            OperationValue::InsecureCrsGen(insecure_crs_gen) => {
                KmsOperationRequest::InsecureCrsGen(InsecureCrsGenVal {
                    insecure_crs_gen,
                    operation_val,
                })
            }
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
        tokio::time::sleep(tokio::time::Duration::from_secs(
            $timeout_triple.initial_wait_time,
        ))
        .await;

        // start polling
        let mut cnt = 0u64;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(
                $timeout_triple.retry_interval,
            ))
            .await;
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
                        tracing::error!(err_msg);
                        $metrics.increment(
                            MetricType::CoreResponseError,
                            1,
                            &[("error", &err_msg)],
                        );
                        return Err(anyhow!(err_msg));
                    } else {
                        cnt += 1;
                        tracing::debug!(
                            "Polling core {}, tries: {cnt}, timeout_triple: {:?}",
                            $info,
                            $timeout_triple,
                        );
                    }
                }
                Err(e) => {
                    let err_msg = format!("error while trying to get response {e}");
                    $metrics.increment(MetricType::CoreResponseError, 1, &[("error", &err_msg)]);
                    tracing::error!(err_msg);
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
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        _config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

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
                salt: self.decrypt.eip712_salt().map(|salt| salt.to_vec()),
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
                            decrypt_response: DecryptResponseValues::new(
                                inner.signature,
                                bincode::serialize(&payload)?,
                            ),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
                            },
                        })))
                }
                Err(e) => {
                    tracing::warn!("Decrypt Response Poller error {:?}", e);
                    Ok(PollerStatus::Poll)
                },
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
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        _config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

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
                salt: self.reencrypt.eip712_salt().map(|salt| salt.to_vec()),
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
                            reencrypt_response: ReencryptResponseValues::new(
                                inner.signature,
                                bincode::serialize(&payload)?,
                            ),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
                            },
                        },
                    )))
                }
                Err(e) => {
                    tracing::warn!("Reencrypt Response Poller error {:?}", e);
                    Ok(PollerStatus::Poll)
                },
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
impl<S> KmsEventHandler for VerifyProvenCtVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        _config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

        let tx_id = self.operation_val.tx_id.to_hex();
        let req_id: RequestId = tx_id.clone().try_into()?;
        let verify_proven_ct = &self.verify_proven_ct;
        let ct_proof_handle: Vec<u8> = verify_proven_ct.ct_proof_handle().deref().into();
        let ct_proof = self
            .operation_val
            .kms_client
            .storage
            .get_ciphertext(ct_proof_handle)
            .await?;
        let req = VerifyProvenCtRequest {
            request_id: Some(req_id.clone()),
            key_handle: Some(RequestId {
                request_id: verify_proven_ct.key_id().to_hex(),
            }),
            crs_handle: Some(RequestId {
                request_id: verify_proven_ct.crs_id().to_hex(),
            }),
            client_address: verify_proven_ct.client_address().to_string(),
            contract_address: verify_proven_ct.contract_address().to_string(),
            ct_bytes: ct_proof,
            acl_address: verify_proven_ct.acl_address().to_string(),
            domain: Some(Eip712DomainMsg {
                name: verify_proven_ct.eip712_name().to_string(),
                version: verify_proven_ct.eip712_version().to_string(),
                chain_id: verify_proven_ct.eip712_chain_id().into(),
                verifying_contract: verify_proven_ct.eip712_verifying_contract().to_string(),
                salt: self
                    .verify_proven_ct
                    .eip712_salt()
                    .map(|salt| salt.to_vec()),
            }),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(tx_id.clone()))?;
        // Response is just empty
        let _resp = client.verify_proven_ct(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!("Error in Verify proven ct verification: {}", err_msg);
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "VerifyProvenCt")]);

        let g =
            |res: Result<Response<VerifyProvenCtResponse>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let inner = res.into_inner();
                    let payload: VerifyProvenCtResponsePayload = inner.payload.ok_or_else(||anyhow!("empty decryption payload"))?;
                    Ok(PollerStatus::Done(KmsOperationResponse::VerifyProvenCtResponse(
                        VerifyProvenCtResponseVal {
                            verify_proven_ct_response: VerifyProvenCtResponseValues::new(
                                inner.signature,
                                bincode::serialize(&payload)?,
                            ),
                            operation_val: BlockchainOperationVal {
                                tx_id: self.operation_val.tx_id.clone(),
                            },
                        },
                    )))
                }
                Err(e) => {
                    tracing::warn!("VerifyCt Response Poller error {:?}", e);
                    Ok(PollerStatus::Poll)
                },
            }
        };

        // we wait for a bit before even trying
        let timeout_triple = self
            .operation_val
            .kms_client
            .timeout_config
            .verify_proven_ct
            .clone();

        // loop to get response
        poller!(
            client.get_verify_proven_ct_result(make_request(req_id.clone(), Some(tx_id.clone()))?),
            g,
            timeout_triple,
            "(VerifyProvenCt)",
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
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;
        let req = KeyGenPreprocRequest {
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
        let param_choice = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice();
        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

        let request_id = self.operation_val.tx_id.to_hex();
        let keygen = &self.keygen;

        let req_id: RequestId = request_id.clone().try_into()?;
        let preproc_id = keygen.preproc_id().to_hex().try_into()?;
        let req = KeyGenRequest {
            params: param_choice.into(),
            preproc_id: Some(preproc_id),
            request_id: Some(req_id.clone()),
            domain: Some(Eip712DomainMsg {
                name: keygen.eip712_name().to_string(),
                version: keygen.eip712_version().to_string(),
                chain_id: keygen.eip712_chain_id().into(),
                verifying_contract: keygen.eip712_verifying_contract().to_string(),
                salt: self.keygen.eip712_salt().map(|salt| salt.to_vec()),
            }),
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
                                keygen_response: KeyGenResponseValues::new(
                                    HexVector::from_hex(&request_id.request_id)?,
                                    pk_info.key_handle.clone(),
                                    pk_info.signature.clone(),
                                    ek_info.key_handle.clone(),
                                    ek_info.signature.clone(),
                                    param_choice,
                                ),
                                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                    tx_id: self.operation_val.tx_id.clone(),
                                },
                            },
                        )))
                    }
                    // we ignore all errors and just poll
                    Err(e) => {
                        tracing::warn!("Keygen Response Poller error {:?}", e);
                        Ok(PollerStatus::Poll)
                    },
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
impl<S> KmsEventHandler for InsecureKeyGenVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let param_choice = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice();

        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

        let request_id = self.operation_val.tx_id.to_hex();

        let req_id: RequestId = request_id.clone().try_into()?;
        let keygen = &self.insecure_key_gen;

        tracing::debug!("Insecure Keygen with request ID: {:?}", req_id);
        let req = KeyGenRequest {
            params: param_choice.into(),
            request_id: Some(req_id.clone()),
            preproc_id: None,
            domain: Some(Eip712DomainMsg {
                name: keygen.eip712_name().to_string(),
                version: keygen.eip712_version().to_string(),
                chain_id: keygen.eip712_chain_id().into(),
                verifying_contract: keygen.eip712_verifying_contract().to_string(),
                salt: keygen.eip712_salt().map(|salt| salt.to_vec()),
            }),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.insecure_key_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating insecure keygen to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "InsecureKeyGen")]);

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
                                keygen_response: KeyGenResponseValues::new(
                                    HexVector::from_hex(&request_id.request_id)?,
                                    pk_info.key_handle.clone(),
                                    pk_info.signature.clone(),
                                    ek_info.key_handle.clone(),
                                    ek_info.signature.clone(),
                                    param_choice,
                                ),
                                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                    tx_id: self.operation_val.tx_id.clone(),
                                },
                            },
                        )))
                    }
                    // we ignore all errors and just poll
                    Err(e) => {
                        tracing::warn!("Insecure Keygen Response Poller error {:?}", e);
                        Ok(PollerStatus::Poll)
                    },
                }

            };

        // loop to get response
        let timeout_triple = self
            .operation_val
            .kms_client
            .timeout_config
            .insecure_key_gen
            .clone();

        poller!(
            client.get_key_gen_result(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(InsecureKeyGen)",
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
        let param_choice = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice();

        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

        let request_id = self.operation_val.tx_id.to_hex();
        let crsgen = &self.crsgen;

        let req_id: RequestId = request_id.clone().try_into()?;
        let req = CrsGenRequest {
            params: param_choice.into(),
            request_id: Some(req_id.clone()),
            max_num_bits: Some(self.crsgen.max_num_bits()),
            domain: Some(Eip712DomainMsg {
                name: crsgen.eip712_name().to_string(),
                version: crsgen.eip712_version().to_string(),
                chain_id: crsgen.eip712_chain_id().into(),
                verifying_contract: crsgen.eip712_verifying_contract().to_string(),
                salt: self.crsgen.eip712_salt().map(|salt| salt.to_vec()),
            }),
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
                                crs_gen_response: events::kms::CrsGenResponseValues::new(
                                    request_id.request_id,
                                    crs_results.key_handle,
                                    crs_results.signature,
                                    self.crsgen.max_num_bits(),
                                    param_choice,
                                ),
                                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                    tx_id: self.operation_val.tx_id.clone(),
                                },
                            },
                        )))
                    }
                    Err(e) => {
                        tracing::warn!("CrsGen Response Poller error {:?}", e);
                        Ok(PollerStatus::Poll)
                    },
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

#[async_trait]
impl<S> KmsEventHandler for InsecureCrsGenVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        config_contract: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let param_choice = config_contract
            .ok_or_else(|| anyhow!("config contract missing"))?
            .param_choice();

        let chan = &self.operation_val.kms_client.channel;
        let mut client =
            CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);

        let request_id = self.operation_val.tx_id.to_hex();
        let insecure_crs_gen = &self.insecure_crs_gen;

        let req_id: RequestId = request_id.clone().try_into()?;
        let req = CrsGenRequest {
            params: param_choice.into(),
            request_id: Some(req_id.clone()),
            max_num_bits: Some(self.insecure_crs_gen.max_num_bits()),
            domain: Some(Eip712DomainMsg {
                name: insecure_crs_gen.eip712_name().to_string(),
                version: insecure_crs_gen.eip712_version().to_string(),
                chain_id: insecure_crs_gen.eip712_chain_id().into(),
                verifying_contract: insecure_crs_gen.eip712_verifying_contract().to_string(),
                salt: self
                    .insecure_crs_gen
                    .eip712_salt()
                    .map(|salt| salt.to_vec()),
            }),
        };

        let metrics = self.operation_val.kms_client.metrics.clone();

        let request = make_request(req.clone(), Some(request_id.clone()))?;

        // the response should be empty
        let _resp = client.insecure_crs_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating insecure CRS generation to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "InsecureCRS")]);

        let g =
            |res: Result<Response<CrsGenResult>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
                match res {
                    Ok(response) => {
                        let inner = response.into_inner();
                        let request_id = inner.request_id.ok_or_else(||anyhow!("empty request_id for insecure CRS generation"))?;
                        let crs_results = inner.crs_results.ok_or_else(||anyhow!("empty insecure crs result"))?;
                        Ok(PollerStatus::Done(KmsOperationResponse::CrsGenResponse(
                            crate::domain::blockchain::CrsGenResponseVal {
                                crs_gen_response: events::kms::CrsGenResponseValues::new(
                                    request_id.request_id,
                                    crs_results.key_handle,
                                    crs_results.signature,
                                    self.insecure_crs_gen.max_num_bits(),
                                    param_choice,
                                ),
                                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                                    tx_id: self.operation_val.tx_id.clone(),
                                },
                            },
                        )))
                    }
                    Err(_) => Ok(PollerStatus::Poll),
                }
            };

        let timeout_triple = self
            .operation_val
            .kms_client
            .timeout_config
            .insecure_crs
            .clone();
        poller!(
            client.get_crs_gen_result(make_request(req_id.clone(), Some(request_id.clone()))?),
            g,
            timeout_triple,
            "(InsecureCRS)",
            metrics
        );
    }
}
