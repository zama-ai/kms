use super::metrics::OpenTelemetryMetrics;
use crate::conf::{TimeoutConfig, TimeoutTriple};
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse, ReencryptResponseVal,
    VerifyProvenCtResponseVal,
};
use crate::domain::kms::{CatchupResult, Kms};
use crate::domain::storage::Storage;
use crate::infrastructure::metrics::{MetricType, Metrics};
use anyhow::anyhow;
use async_trait::async_trait;
use conf_trace::grpc::build_request;
use conf_trace::telemetry::ContextPropagator;
use enum_dispatch::enum_dispatch;
use events::kms::{
    CrsGenValues, DecryptResponseValues, DecryptValues, FheParameter, InsecureCrsGenValues,
    InsecureKeyGenValues, KeyGenPreprocResponseValues, KeyGenResponseValues, KeyGenValues,
    KmsEvent, OperationValue, ReencryptResponseValues, ReencryptValues, TransactionId,
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
use tokio::sync::oneshot::Receiver;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Response, Status};
use tracing::Instrument;
use typed_builder::TypedBuilder;

pub struct KmsOperationVal<S> {
    pub kms_client: KmsCore<S>,
    pub tx_id: TransactionId,
}

struct SetupOperationVal {
    client: CoreServiceEndpointClient<InterceptedService<Channel, ContextPropagator>>,
    request_id: String,
    req_id: RequestId,
    tx_id: TransactionId,
    timeout_triple: TimeoutTriple,
    metrics: Arc<OpenTelemetryMetrics>,
}

trait OperationVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S>;
    fn get_timeout_triple(&self) -> TimeoutTriple;
    fn get_setup(&self) -> anyhow::Result<SetupOperationVal> {
        let chan = &self.get_operation_val().kms_client.channel;
        let client = CoreServiceEndpointClient::with_interceptor(chan.clone(), ContextPropagator);
        let metrics = self.get_operation_val().kms_client.metrics.clone();
        let request_id = self.get_operation_val().tx_id.to_hex();
        let req_id: RequestId = request_id.clone().try_into()?;
        let tx_id = self.get_operation_val().tx_id.clone();
        Ok(SetupOperationVal {
            client,
            request_id,
            req_id,
            tx_id,
            timeout_triple: self.get_timeout_triple(),
            metrics,
        })
    }
}

#[derive(Clone)]
struct GenericPollerInput {
    tx_id: TransactionId,
    fhe_params: Option<FheParameter>,
    max_num_bits: Option<u32>,
}
struct GenericMapResponseInput<T> {
    response: Response<T>,
    tx_id: TransactionId,
    fhe_params: Option<FheParameter>,
    max_num_bits: Option<u32>,
}

impl<T> GenericMapResponseInput<T> {
    fn new_from_poller_input(response: Response<T>, input: GenericPollerInput) -> Self {
        Self {
            response,
            tx_id: input.tx_id,
            fhe_params: input.fhe_params,
            max_num_bits: input.max_num_bits,
        }
    }
}

impl<T> GenericMapResponseInput<T> {
    fn get_response_and_id(self) -> (Response<T>, TransactionId) {
        (self.response, self.tx_id)
    }
    fn get_response_id_and_fhe_params(
        self,
    ) -> anyhow::Result<(Response<T>, TransactionId, FheParameter)> {
        let fhe_params = self
            .fhe_params
            .ok_or_else(|| anyhow!("Missing fhe parameters"))?;
        Ok((self.response, self.tx_id, fhe_params))
    }
    fn get_response_id_fhe_params_and_max_num_bits(
        self,
    ) -> anyhow::Result<(Response<T>, TransactionId, FheParameter, u32)> {
        let fhe_params = self
            .fhe_params
            .ok_or_else(|| anyhow!("Missing fhe parameters"))?;
        let max_num_bits = self
            .max_num_bits
            .ok_or_else(|| anyhow!("Missing max num bits"))?;

        Ok((self.response, self.tx_id, fhe_params, max_num_bits))
    }
}

#[async_trait]
trait Poller<T: Send + 'static> {
    fn map_response(input: GenericMapResponseInput<T>) -> anyhow::Result<KmsOperationResponse>;
    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>>;

    /// Returns a mapping between result and [`PollerStatus`].
    ///
    /// Takes as input [`GenericPollerInput`] used to create the [`KmsOperationResponse`]
    /// using [`Self::map_response`] in case of 'Ok'.
    fn res_map_poller(
        description: &str,
        input: GenericPollerInput,
    ) -> impl Fn(Result<Response<T>, Status>) -> Result<PollerStatus<KmsOperationResponse>, anyhow::Error>
    {
        move |res: Result<Response<T>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
            match res {
                Ok(res) => {
                    let input =
                        GenericMapResponseInput::<T>::new_from_poller_input(res, input.clone());
                    Ok(PollerStatus::Done(Self::map_response(input)?))
                }
                Err(e) => {
                    match e.code() {
                        tonic::Code::Unavailable => {
                            // Continue polling, since the result is not ready yet. This is not an actual error, but expected for longer tasks.
                            tracing::info!("{description} Response Poller Unavailable error {:?}. Will continue polling.", e);
                            Ok(PollerStatus::Poll)
                        }
                        tonic::Code::Cancelled => {
                            // TODO(#1529): We currently see grpc timeouts (tonic::Code::Cancelled) from the core from time to time.
                            // In this case we want to retry. We log a warning, as this indicates that we have an issue.
                            // This match arm should be removed and Cancelled should be treated as error once #1529 is closed.
                            let msg = format!(
                                "{description} Response Poller Cancelled error {:?}. Will continue polling.",
                                e
                            );
                            tracing::warn!(msg);
                            Ok(PollerStatus::Poll)
                        }
                        tonic::Code::Internal => {
                            // This indicates an explicit error. We abort polling and log the error.
                            let msg = format!(
                                "{description} Response Poller error {:?}. Will abort polling!",
                                e
                            );
                            tracing::error!(msg);
                            Err(anyhow!(msg))
                        }
                        _ => {
                            // This indicates an unknown/unexpected code, which we treat as error. We abort polling.
                            let msg = format!(
                                "{description} Response Poller error {:?}. Will abort polling!",
                                e
                            );
                            tracing::error!(msg);
                            Err(anyhow!(msg))
                        }
                    }
                }
            }
        }
    }

    /// Decides what to do according to the kind of response received from the Core.
    ///
    /// - `Ok(res)`: The KMS Core directly answered with the response, we can send it back as is to connector
    /// - `Err(e)`: Look at the status of the error:
    ///     - `NotFound`: Request was absent from the Core, we return to Connector
    ///     - `Unavailable`: Core is currently treating the request, keep polling and return a channel in which we will push the answer to the Connector
    ///     - `Internal`: The error code we use on Core to say something wrong happened, just log
    ///     - `_`: Anything else means something very wrong happened
    fn dispatch_catchup_response(
        &self,
        response: Result<Response<T>, Status>,
        setup: SetupOperationVal,
        input_poller: GenericPollerInput,
        description: &str,
    ) -> anyhow::Result<CatchupResult> {
        match response {
            Ok(res) => {
                setup
                    .metrics
                    .increment(MetricType::CoreResponseSuccess, 1, &[("ok", "ok")]);
                let input_map_response =
                    GenericMapResponseInput::<T>::new_from_poller_input(res, input_poller);
                Ok(CatchupResult::Now(Self::map_response(input_map_response)))
            }
            Err(e) => match e.code() {
                Code::NotFound => Ok(CatchupResult::NotFound),
                Code::Unavailable => Ok(CatchupResult::Later(self.poll_for_result(input_poller)?)),
                Code::Internal => {
                    setup.metrics.increment(
                        MetricType::CoreError,
                        1,
                        &[("error", &format!("{:?}", e))],
                    );
                    tracing::error!("KMS Core failed in {description} : {:?}", e);
                    Err(anyhow!("{:?}", e))
                }
                _ => {
                    setup.metrics.increment(
                        MetricType::CoreError,
                        1,
                        &[("error", &format!("{:?}", e))],
                    );
                    tracing::error!(
                        "Something went very wrong querying KMS Core in {description} : {:?}",
                        e
                    );
                    Err(anyhow!("{:?}", e))
                }
            },
        }
    }
}

pub struct DecryptVal<S> {
    pub decrypt: DecryptValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for DecryptVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val
            .kms_client
            .timeout_config
            .decryption
            .clone()
    }
}

pub struct ReencryptVal<S> {
    pub reencrypt: ReencryptValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for ReencryptVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val
            .kms_client
            .timeout_config
            .reencryption
            .clone()
    }
}

pub struct VerifyProvenCtVal<S> {
    pub verify_proven_ct: VerifyProvenCtValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for VerifyProvenCtVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val
            .kms_client
            .timeout_config
            .verify_proven_ct
            .clone()
    }
}

pub struct KeyGenPreprocVal<S> {
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for KeyGenPreprocVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val.kms_client.timeout_config.preproc.clone()
    }
}

pub struct KeyGenVal<S> {
    pub keygen: KeyGenValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for KeyGenVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val.kms_client.timeout_config.keygen.clone()
    }
}

pub struct InsecureKeyGenVal<S> {
    pub insecure_key_gen: InsecureKeyGenValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for InsecureKeyGenVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val
            .kms_client
            .timeout_config
            .insecure_key_gen
            .clone()
    }
}

pub struct CrsGenVal<S> {
    pub crsgen: CrsGenValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for CrsGenVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val.kms_client.timeout_config.crs.clone()
    }
}

pub struct InsecureCrsGenVal<S> {
    pub insecure_crs_gen: InsecureCrsGenValues,
    pub operation_val: KmsOperationVal<S>,
}

impl<S> OperationVal<S> for InsecureCrsGenVal<S> {
    fn get_operation_val(&self) -> &KmsOperationVal<S> {
        &self.operation_val
    }
    fn get_timeout_triple(&self) -> TimeoutTriple {
        self.operation_val
            .kms_client
            .timeout_config
            .insecure_crs
            .clone()
    }
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        match self {
            KmsOperationRequest::Decrypt(decrypt) => decrypt.run_operation(param_choice).await,
            KmsOperationRequest::Reencrypt(reencrypt) => {
                reencrypt.run_operation(param_choice).await
            }
            KmsOperationRequest::VerifyProvenCt(verify_proven_ct) => {
                verify_proven_ct.run_operation(param_choice).await
            }
            KmsOperationRequest::KeyGenPreproc(keygen_preproc) => {
                keygen_preproc.run_operation(param_choice).await
            }
            KmsOperationRequest::KeyGen(keygen) => keygen.run_operation(param_choice).await,
            KmsOperationRequest::InsecureKeyGen(insecure_key_gen) => {
                insecure_key_gen.run_operation(param_choice).await
            }
            KmsOperationRequest::CrsGen(crsgen) => crsgen.run_operation(param_choice).await,
            KmsOperationRequest::InsecureCrsGen(insecure_crs_gen) => {
                insecure_crs_gen.run_operation(param_choice).await
            }
        }
    }

    async fn run_catchup(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        match self {
            KmsOperationRequest::Decrypt(decrypt) => decrypt.run_catchup(param_choice).await,
            KmsOperationRequest::Reencrypt(reencrypt) => reencrypt.run_catchup(param_choice).await,
            KmsOperationRequest::VerifyProvenCt(verify_proven_ct) => {
                verify_proven_ct.run_catchup(param_choice).await
            }
            KmsOperationRequest::KeyGenPreproc(keygen_preproc) => {
                keygen_preproc.run_catchup(param_choice).await
            }
            KmsOperationRequest::KeyGen(keygen) => keygen.run_catchup(param_choice).await,
            KmsOperationRequest::InsecureKeyGen(insecure_key_gen) => {
                insecure_key_gen.run_catchup(param_choice).await
            }
            KmsOperationRequest::CrsGen(crsgen) => crsgen.run_catchup(param_choice).await,
            KmsOperationRequest::InsecureCrsGen(insecure_crs_gen) => {
                insecure_crs_gen.run_catchup(param_choice).await
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let operation = self.create_kms_operation(event, operation_value)?;
        operation.run_operation(param_choice).await
    }

    async fn run_catchup(
        &self,
        event: KmsEvent,
        operation_value: OperationValue,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let operation = self.create_kms_operation(event, operation_value)?;
        operation.run_catchup(param_choice).await
    }
}

// Gen operations (key/crs generation) need to know which parameters to use
// For other operations, `param_choice` should be None and will not be used
#[async_trait]
#[enum_dispatch(KmsOperationRequest)]
pub trait KmsEventHandler {
    async fn run_operation(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>>;

    /// Poll the KMS Core for a potentially existing request.
    /// This __HEAVILY__ rely on the assumption that the KMS Core
    /// will return a [`Code::NotFound`] error if there
    /// has been no request for the given [`RequestId`]
    async fn run_catchup(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult>;
}

#[derive(Clone, TypedBuilder)]
/// This is used by the [`crate::application::kms_core_sync::KmsCoreEventHandler`]
/// to interact with the KMS core upon receiving events
/// from the KMS BC
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
    ($f_to_poll:expr,$res_map:expr,$timeout_triple:expr,$info:expr,$metrics:expr) => {{
        tracing::info!(
            "polling for results using the timeout triple: {:?}",
            $timeout_triple
        );

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
                    break Ok(res);
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
                        break Err(anyhow!(err_msg));
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
                    break Err(anyhow!(err_msg));
                }
            }
        }
    }};
}

#[async_trait]
impl<S> Poller<DecryptionResponse> for DecryptVal<S> {
    /// Maps a [`DecryptionResponse`] sent by the KMS Core
    /// to a [`KmsOperationResponse`] for the BC KMS
    fn map_response(
        input: GenericMapResponseInput<DecryptionResponse>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id) = input.get_response_and_id();
        let inner = response.into_inner();
        let payload: DecryptionResponsePayload = inner
            .payload
            .ok_or_else(|| anyhow!("empty decryption payload"))?;
        Ok(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
            decrypt_response: DecryptResponseValues::new(
                inner.signature,
                bincode::serialize(&payload)?,
            ),
            operation_val: BlockchainOperationVal {
                tx_id: tx_id.clone(),
            },
        }))
    }

    /// Poll the KMS Core for results
    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
            async move {
                let res = poller!(
                    setup.client.get_decrypt_result(
                        //This unwrap is safe cause we just made sure this doesn't error out
                        build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                    ),
                    Self::res_map_poller("Decrypt",input.clone()),
                    setup.timeout_triple,
                    "(Decrypt)",
                    setup.metrics
                );
                if sender.send(res).is_err() {
                    tracing::error!("KMS Connector error in DecryptVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(receiver)
    }
}

#[async_trait]
impl<S> KmsEventHandler for DecryptVal<S>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(
        &self,
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        if CURRENT_FORMAT_VERSION != self.decrypt.version() {
            return Err(anyhow!(
                "version not supported: supported={}, requested={}",
                CURRENT_FORMAT_VERSION,
                self.decrypt.version()
            ));
        }

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
            request_id: Some(setup.req_id.clone()),
            domain: Some(Eip712DomainMsg {
                name: self.decrypt.eip712_name().to_string(),
                version: self.decrypt.eip712_version().to_string(),
                chain_id: self.decrypt.eip712_chain_id().into(),
                verifying_contract: self.decrypt.eip712_verifying_contract().to_string(),
                salt: self.decrypt.eip712_salt().map(|salt| salt.to_vec()),
            }),
            acl_address: Some(self.decrypt.acl_address().to_string()),
        };

        let metrics = setup.metrics.clone();

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;
        // the response should be empty
        let _resp = setup.client.decrypt(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating decryption to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "Decrypt")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: None,
            max_num_bits: None,
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let req = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_decrypt_result(req).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: None,
            max_num_bits: None,
        };

        self.dispatch_catchup_response(response, setup, generic_poller_input, "DecryptVal")
    }
}

impl<S> Poller<ReencryptionResponse> for ReencryptVal<S> {
    fn map_response(
        input: GenericMapResponseInput<ReencryptionResponse>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id) = input.get_response_and_id();
        let inner = response.into_inner();
        let payload: ReencryptionResponsePayload = inner
            .payload
            .ok_or_else(|| anyhow!("empty reencryption payload"))?;
        Ok(KmsOperationResponse::ReencryptResponse(
            ReencryptResponseVal {
                reencrypt_response: ReencryptResponseValues::new(
                    inner.signature,
                    bincode::serialize(&payload)?,
                ),
                operation_val: BlockchainOperationVal {
                    tx_id: tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
            async move {
                let res = poller!(
                    setup.client.get_reencrypt_result(
                        //This unwrap is safe cause we just made sure this doesn't error out
                        build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                    ),
                    Self::res_map_poller("Reencryption", input.clone()),
                    setup.timeout_triple,
                    "(Reencrypt)",
                    setup.metrics
                );
                if sender.send(res).is_err() {
                    tracing::error!("KMS Connector error in ReencryptVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(receiver)
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
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

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
            request_id: Some(setup.req_id.clone()),
        };

        let metrics = setup.metrics.clone();

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;

        // the response should be empty
        let _resp = setup.client.reencrypt(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating reencryption to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "Reencrypt")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: None,
            max_num_bits: None,
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;

        let request = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        let response = setup.client.get_reencrypt_result(request).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: None,
            max_num_bits: None,
        };

        self.dispatch_catchup_response(response, setup, generic_poller_input, "ReencryptVal")
    }
}

impl<S> Poller<VerifyProvenCtResponse> for VerifyProvenCtVal<S> {
    fn map_response(
        input: GenericMapResponseInput<VerifyProvenCtResponse>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id) = input.get_response_and_id();
        let inner = response.into_inner();
        let payload: VerifyProvenCtResponsePayload = inner
            .payload
            .ok_or_else(|| anyhow!("empty verify_ct payload"))?;
        Ok(KmsOperationResponse::VerifyProvenCtResponse(
            VerifyProvenCtResponseVal {
                verify_proven_ct_response: VerifyProvenCtResponseValues::new(
                    inner.signature,
                    bincode::serialize(&payload)?,
                ),
                operation_val: BlockchainOperationVal {
                    tx_id: tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
            async move {
                let res = poller!(
                    setup.client.get_verify_proven_ct_result(
                        //This unwrap is safe cause we just made sure this doesn't error out
                        build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                    ),
                    Self::res_map_poller("VerifyCt", input.clone()),
                    setup.timeout_triple,
                    "(VerifyProvenCt)",
                    setup.metrics
                );
                if sender.send(res).is_err() {
                    tracing::error!("KMS Connector error in VerifyProvenCtVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(receiver)
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
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let verify_proven_ct = &self.verify_proven_ct;
        let ct_proof_handle: Vec<u8> = verify_proven_ct.ct_proof_handle().deref().into();
        let ct_proof = self
            .operation_val
            .kms_client
            .storage
            .get_ciphertext(ct_proof_handle)
            .await?;
        let req = VerifyProvenCtRequest {
            request_id: Some(setup.req_id.clone()),
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

        let metrics = setup.metrics.clone();

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;
        // Response is just empty
        let _resp = setup
            .client
            .verify_proven_ct(request)
            .await
            .inspect_err(|e| {
                let err_msg = e.to_string();
                tracing::error!("Error in Verify proven ct verification: {}", err_msg);
                metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            })?;
        metrics.increment(MetricType::CoreSuccess, 1, &[("ok", "VerifyProvenCt")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: None,
            max_num_bits: None,
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let req = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_verify_proven_ct_result(req).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: None,
            max_num_bits: None,
        };
        self.dispatch_catchup_response(response, setup, generic_poller_input, "VerifyProvenCtVal")
    }
}

impl<S> Poller<KeyGenPreprocStatus> for KeyGenPreprocVal<S> {
    fn map_response(
        input: GenericMapResponseInput<KeyGenPreprocStatus>,
    ) -> anyhow::Result<KmsOperationResponse> {
        Ok(KmsOperationResponse::KeyGenPreprocResponse(
            crate::domain::blockchain::KeyGenPreprocResponseVal {
                keygen_preproc_response: KeyGenPreprocResponseValues {},
                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                    tx_id: input.tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
            async move {
                let res = poller!(
                    setup.client.get_preproc_status(
                        //This unwrap is safe cause we just made sure this doesn't error out
                        build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                    ),
                    Self::res_map_poller("KeyGenPreproc", input.clone()),
                    setup.timeout_triple,
                    "(KeyGenPreproc)",
                    setup.metrics
                );
                if sender.send(res).is_err() {
                    tracing::error!("KMS Connector error in KeyGenPreprocVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(receiver)
    }

    // This res_map_poller doesn't exactly follow the standard template so
    // we have to define it here
    fn res_map_poller(
        description: &str,
        input: GenericPollerInput,
    ) -> impl Fn(
        Result<Response<KeyGenPreprocStatus>, Status>,
    ) -> Result<PollerStatus<KmsOperationResponse>, anyhow::Error> {
        move |res: Result<Response<KeyGenPreprocStatus>, Status>| -> anyhow::Result<PollerStatus<_>, anyhow::Error> {
        match res {
            Ok(res) => {
                let inner = res.into_inner();
                let status = KeyGenPreprocStatusEnum::try_from(inner.result)?;
                match status {
                    KeyGenPreprocStatusEnum::Finished => {
                    let input = GenericMapResponseInput::new_from_poller_input(Response::new(inner), input.clone());
                        Ok(PollerStatus::Done(Self::map_response(input)?))
                    }
                    KeyGenPreprocStatusEnum::InProgress => {
                        Ok(PollerStatus::Poll)
                    }
                    other => {
                        Err(anyhow!("{description} error while getting status: {}", other.as_str_name()))
                    }
                }
            }
            Err(e) => {
                Err(anyhow!(e.to_string()))
            }
        }
    }
    }

    // This dispatch_catchup_response doesn't exactly follow the standard template so
    // we have to define it here
    fn dispatch_catchup_response(
        &self,
        response: Result<Response<KeyGenPreprocStatus>, Status>,
        setup: SetupOperationVal,
        input_poller: GenericPollerInput,
        _description: &str,
    ) -> anyhow::Result<CatchupResult> {
        match response {
            Ok(res) => {
                let inner = res.into_inner();
                let status = KeyGenPreprocStatusEnum::try_from(inner.result)?;
                // NOTE: KeyGenPreproc comes with its own status mechanism,
                // should this be unified with the rest ?
                match status {
                    KeyGenPreprocStatusEnum::Missing => Ok(CatchupResult::NotFound),
                    KeyGenPreprocStatusEnum::InProgress => {
                        Ok(CatchupResult::Later(self.poll_for_result(input_poller)?))
                    }
                    KeyGenPreprocStatusEnum::Finished => {
                        let input_map_response = GenericMapResponseInput::new_from_poller_input(
                            Response::new(inner),
                            input_poller,
                        );
                        Ok(CatchupResult::Now(Self::map_response(input_map_response)))
                    }
                    _ => {
                        setup.metrics.increment(
                            MetricType::CoreError,
                            1,
                            &[("error", "KeyGenPreprocVal error")],
                        );
                        tracing::error!("KMS Core failed in KeyGenPreprocVal");
                        Err(anyhow!("KMS Core failed in KeyGenPreprocVal"))
                    }
                }
            }
            Err(e) => match e.code() {
                Code::NotFound => Ok(CatchupResult::NotFound),
                Code::Unavailable => Ok(CatchupResult::Later(self.poll_for_result(input_poller)?)),
                Code::Internal => {
                    setup.metrics.increment(
                        MetricType::CoreError,
                        1,
                        &[("error", &format!("{:?}", e))],
                    );
                    tracing::error!("KMS Core failed in KeyGenPreprocVal : {:?}", e);
                    Err(anyhow!("{:?}", e))
                }
                _ => {
                    setup.metrics.increment(
                        MetricType::CoreError,
                        1,
                        &[("error", &format!("{:?}", e))],
                    );
                    tracing::error!(
                        "Something went very wrong querying KMS Core in KeyGenPreprocVal : {:?}",
                        e
                    );
                    Err(anyhow!("{:?}", e))
                }
            },
        }
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;
        let param_choice_str = param_choice
            .ok_or_else(|| anyhow!("Param choice is missing"))?
            .to_param_choice_string();
        let param_choice = ParamChoice::from_str_name(&param_choice_str).ok_or_else(|| {
            anyhow!(
                "invalid parameter choice string in prep: {}",
                param_choice_str
            )
        })?;

        let req = KeyGenPreprocRequest {
            params: param_choice.into(),
            request_id: Some(setup.req_id.clone()),
        };

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;

        // the response should be empty
        let _resp = setup
            .client
            .key_gen_preproc(request)
            .await
            .inspect_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(
                "Error communicating Keygen Preproc to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
                setup
                    .metrics
                    .increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            })?;
        setup
            .metrics
            .increment(MetricType::CoreSuccess, 1, &[("ok", "KeyGenPreproc")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: None,
            max_num_bits: None,
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        _param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let req = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_preproc_status(req).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: None,
            max_num_bits: None,
        };

        self.dispatch_catchup_response(response, setup, generic_poller_input, "KeyGenPreprocVal")
    }
}

impl<S> Poller<KeyGenResult> for KeyGenVal<S> {
    fn map_response(
        input: GenericMapResponseInput<KeyGenResult>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id, param_choice) = input.get_response_id_and_fhe_params()?;
        let inner = response.into_inner();
        let request_id = inner
            .request_id
            .ok_or_else(|| anyhow!("empty request_id for keygen"))?;
        let pk_info = inner
            .key_results
            .get(&PubDataType::PublicKey.to_string())
            .ok_or_else(|| anyhow!("empty public key info"))?;
        let ek_info = inner
            .key_results
            .get(&PubDataType::ServerKey.to_string())
            .ok_or_else(|| anyhow!("empty evaluation key info"))?;
        Ok(KmsOperationResponse::KeyGenResponse(
            crate::domain::blockchain::KeyGenResponseVal {
                keygen_response: KeyGenResponseValues::new(
                    HexVector::from_hex(&request_id.request_id)?,
                    pk_info.key_handle.clone(),
                    pk_info.signature.clone(),
                    pk_info.external_signature.clone(),
                    ek_info.key_handle.clone(),
                    ek_info.signature.clone(),
                    ek_info.external_signature.clone(),
                    param_choice,
                ),
                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                    tx_id: tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
            async move {
                let res = poller!(
                    setup.client.get_key_gen_result(
                        //This unwrap is safe cause we just made sure this doesn't error out
                        build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                    ),
                    Self::res_map_poller("KeyGen", input.clone()),
                    setup.timeout_triple,
                    "(KeyGen)",
                    setup.metrics
                );
                if sender.send(res).is_err() {
                    tracing::error!("KMS Connector error in KeyGenVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(receiver)
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;
        let keygen = &self.keygen;
        let preproc_id = keygen.preproc_id().to_hex().try_into()?;

        let req = KeyGenRequest {
            params: param_choice.into(),
            preproc_id: Some(preproc_id),
            request_id: Some(setup.req_id.clone()),
            domain: Some(Eip712DomainMsg {
                name: keygen.eip712_name().to_string(),
                version: keygen.eip712_version().to_string(),
                chain_id: keygen.eip712_chain_id().into(),
                verifying_contract: keygen.eip712_verifying_contract().to_string(),
                salt: self.keygen.eip712_salt().map(|salt| salt.to_vec()),
            }),
        };

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;

        // the response should be empty
        let _resp = setup.client.key_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating Keygen to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            setup
                .metrics
                .increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        setup
            .metrics
            .increment(MetricType::CoreSuccess, 1, &[("ok", "KeyGen")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: Some(param_choice),
            max_num_bits: None,
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;
        let req = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_key_gen_result(req).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: Some(param_choice),
            max_num_bits: None,
        };
        self.dispatch_catchup_response(response, setup, generic_poller_input, "KeyGenVal")
    }
}

impl<S> Poller<KeyGenResult> for InsecureKeyGenVal<S> {
    fn map_response(
        input: GenericMapResponseInput<KeyGenResult>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id, param_choice) = input.get_response_id_and_fhe_params()?;
        let inner = response.into_inner();
        let request_id = inner
            .request_id
            .ok_or_else(|| anyhow!("empty request_id"))?;
        let pk_info = inner
            .key_results
            .get(&PubDataType::PublicKey.to_string())
            .ok_or_else(|| anyhow!("empty public key info"))?;
        let ek_info = inner
            .key_results
            .get(&PubDataType::ServerKey.to_string())
            .ok_or_else(|| anyhow!("empty evaluation key info"))?;
        Ok(KmsOperationResponse::KeyGenResponse(
            crate::domain::blockchain::KeyGenResponseVal {
                keygen_response: KeyGenResponseValues::new(
                    HexVector::from_hex(&request_id.request_id)?,
                    pk_info.key_handle.clone(),
                    pk_info.signature.clone(),
                    pk_info.external_signature.clone(),
                    ek_info.key_handle.clone(),
                    ek_info.signature.clone(),
                    ek_info.external_signature.clone(),
                    param_choice,
                ),
                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                    tx_id: tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
            async move {
                let res = poller!(
                    setup.client.get_key_gen_result(
                        //This unwrap is safe cause we just made sure this doesn't error out
                        build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                    ),
                    Self::res_map_poller("InsecureKeyGen", input.clone()),
                    setup.timeout_triple,
                    "(InsecureKeyGen)",
                    setup.metrics
                );
                if sender.send(res).is_err() {
                    tracing::error!("KMS Connector error in InsecureKeyGenVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(receiver)
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;
        let keygen = &self.insecure_key_gen;

        tracing::debug!("Insecure Keygen with request ID: {:?}", setup.req_id);
        let req = KeyGenRequest {
            params: param_choice.into(),
            request_id: Some(setup.req_id.clone()),
            preproc_id: None,
            domain: Some(Eip712DomainMsg {
                name: keygen.eip712_name().to_string(),
                version: keygen.eip712_version().to_string(),
                chain_id: keygen.eip712_chain_id().into(),
                verifying_contract: keygen.eip712_verifying_contract().to_string(),
                salt: keygen.eip712_salt().map(|salt| salt.to_vec()),
            }),
        };

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;

        // the response should be empty
        let _resp = setup
            .client
            .insecure_key_gen(request)
            .await
            .inspect_err(|e| {
                let err_msg = e.to_string();
                tracing::error!(
                "Error communicating insecure keygen to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
                setup
                    .metrics
                    .increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
            })?;
        setup
            .metrics
            .increment(MetricType::CoreSuccess, 1, &[("ok", "InsecureKeyGen")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: Some(param_choice),
            max_num_bits: None,
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;
        let req = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_key_gen_result(req).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: Some(param_choice),
            max_num_bits: None,
        };
        self.dispatch_catchup_response(response, setup, generic_poller_input, "InsecureKeyGenVal")
    }
}

impl<S> Poller<CrsGenResult> for CrsGenVal<S> {
    fn map_response(
        input: GenericMapResponseInput<CrsGenResult>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id, param_choice, max_num_bits) =
            input.get_response_id_fhe_params_and_max_num_bits()?;
        let inner = response.into_inner();
        let request_id = inner
            .request_id
            .ok_or_else(|| anyhow!("empty request_id for CRS generation"))?;
        let crs_results = inner
            .crs_results
            .ok_or_else(|| anyhow!("empty crs result"))?;
        Ok(KmsOperationResponse::CrsGenResponse(
            crate::domain::blockchain::CrsGenResponseVal {
                crs_gen_response: events::kms::CrsGenResponseValues::new(
                    request_id.request_id,
                    crs_results.key_handle,
                    crs_results.signature,
                    crs_results.external_signature,
                    max_num_bits,
                    param_choice,
                ),
                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                    tx_id: tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
                async move {
                    let res = poller!(
                        setup.client.get_crs_gen_result(
                            //This unwrap is safe cause we just made sure this doesn't error out
                            build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                        ),
                        Self::res_map_poller("CrsGen", input.clone()),
                        setup.timeout_triple,
                        "(CRS)",
                        setup.metrics
                    );
                    if sender.send(res).is_err() {
                        tracing::error!("KMS Connector error in CrsGenVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                    }
                }
                .instrument(tracing::Span::current()),
            );
        Ok(receiver)
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;

        let crsgen = &self.crsgen;

        let req = CrsGenRequest {
            params: param_choice.into(),
            request_id: Some(setup.req_id.clone()),
            max_num_bits: Some(self.crsgen.max_num_bits()),
            domain: Some(Eip712DomainMsg {
                name: crsgen.eip712_name().to_string(),
                version: crsgen.eip712_version().to_string(),
                chain_id: crsgen.eip712_chain_id().into(),
                verifying_contract: crsgen.eip712_verifying_contract().to_string(),
                salt: self.crsgen.eip712_salt().map(|salt| salt.to_vec()),
            }),
        };

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;

        // the response should be empty
        let _resp = setup.client.crs_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating CRS generation to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            setup
                .metrics
                .increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        setup
            .metrics
            .increment(MetricType::CoreSuccess, 1, &[("ok", "CRS")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: Some(param_choice),
            max_num_bits: Some(self.crsgen.max_num_bits()),
        };

        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;
        let max_num_bits = self.crsgen.max_num_bits();
        let req = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_crs_gen_result(req).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: Some(param_choice),
            max_num_bits: Some(max_num_bits),
        };
        self.dispatch_catchup_response(response, setup, generic_poller_input, "CrsGenVal")
    }
}

impl<S> Poller<CrsGenResult> for InsecureCrsGenVal<S> {
    fn map_response(
        input: GenericMapResponseInput<CrsGenResult>,
    ) -> anyhow::Result<KmsOperationResponse> {
        let (response, tx_id, param_choice, max_num_bits) =
            input.get_response_id_fhe_params_and_max_num_bits()?;
        let inner = response.into_inner();
        let request_id = inner
            .request_id
            .ok_or_else(|| anyhow!("empty request_id for insecure CRS generation"))?;
        let crs_results = inner
            .crs_results
            .ok_or_else(|| anyhow!("empty insecure crs result"))?;
        Ok(KmsOperationResponse::CrsGenResponse(
            crate::domain::blockchain::CrsGenResponseVal {
                crs_gen_response: events::kms::CrsGenResponseValues::new(
                    request_id.request_id,
                    crs_results.key_handle,
                    crs_results.signature,
                    crs_results.external_signature,
                    max_num_bits,
                    param_choice,
                ),
                operation_val: crate::domain::blockchain::BlockchainOperationVal {
                    tx_id: tx_id.clone(),
                },
            },
        ))
    }

    fn poll_for_result(
        &self,
        input: GenericPollerInput,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        // A bit of a hack, make sure we can actually do the request
        // so we can unwrap in the macro right after
        let _ = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;
        // loop to get response
        tokio::spawn(
                async move {
                    let res = poller!(
                        setup.client.get_crs_gen_result(
                            //This unwrap is safe cause we just made sure this doesn't error out
                            build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None).unwrap()
                        ),
                        Self::res_map_poller("InsecureCrsGen", input.clone()),
                        setup.timeout_triple,
                        "(InsecureCRS)",
                        setup.metrics
                    );
                    if sender.send(res).is_err() {
                        tracing::error!("KMS Connector error in InsecureCrsGenVal, received response from Core but receiver dropped : {:?}", setup.req_id);
                    }
                }
                .instrument(tracing::Span::current()),
            );
        Ok(receiver)
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
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<Receiver<anyhow::Result<KmsOperationResponse>>> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;

        let insecure_crs_gen = &self.insecure_crs_gen;

        let req = CrsGenRequest {
            params: param_choice.into(),
            request_id: Some(setup.req_id.clone()),
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

        let request = build_request(req.clone(), Some(setup.request_id.clone()), None)?;

        // the response should be empty
        let _resp = setup.client.insecure_crs_gen(request).await.inspect_err(|e| {
            let err_msg = e.to_string();
            tracing::error!(
                "Error communicating insecure CRS generation to core. Error message:\n{}\nRequest:\n{:?}",
                err_msg,
                req,
            );
            setup.metrics.increment(MetricType::CoreError, 1, &[("error", &err_msg)]);
        })?;
        setup
            .metrics
            .increment(MetricType::CoreSuccess, 1, &[("ok", "InsecureCRS")]);

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id,
            fhe_params: Some(param_choice),
            max_num_bits: Some(self.insecure_crs_gen.max_num_bits()),
        };
        self.poll_for_result(generic_poller_input)
    }

    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_catchup(
        &self,
        param_choice: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        let mut setup = self.get_setup()?;
        let param_choice = param_choice.ok_or_else(|| anyhow!("Param choice is missing"))?;
        let max_num_bits = self.insecure_crs_gen.max_num_bits();
        let request = build_request(setup.req_id.clone(), Some(setup.request_id.clone()), None)?;

        let response = setup.client.get_crs_gen_result(request).await;

        let generic_poller_input = GenericPollerInput {
            tx_id: setup.tx_id.clone(),
            fhe_params: Some(param_choice),
            max_num_bits: Some(max_num_bits),
        };
        self.dispatch_catchup_response(response, setup, generic_poller_input, "InsecureCrsGenVal")
    }
}
