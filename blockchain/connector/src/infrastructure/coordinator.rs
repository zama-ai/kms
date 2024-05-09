use super::metrics::OpenTelemetryMetrics;
use crate::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse, ReencryptResponseVal,
};
use crate::domain::kms::KmsOperation;
use crate::infrastructure::metrics::{MetricType, Metrics};
use anyhow::anyhow;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use events::kms::{
    DecryptResponseValues, DecryptValues, KeyGenPreprocResponseValues, KeyGenResponseValues,
    KeyGenValues, KmsEvent, KmsOperationAttribute, ReencryptResponseValues, ReencryptValues,
    TransactionId,
};
use kms_lib::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
use kms_lib::kms::{
    Config, CrsGenRequest, CrsGenResult, KeyGenPreprocStatus, KeyGenPreprocStatusEnum,
    KeyGenResult, ParamChoice,
};
use kms_lib::kms::{KeyGenPreprocRequest, KeyGenRequest, RequestId};
use kms_lib::rpc::rpc_types::PubDataType;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::{Channel, Endpoint};
use tonic::{Response, Status};
use typed_builder::TypedBuilder;

const MAX_CRS_GEN_DURATION_PER_PARTY_SECS: u64 = 60;

pub struct KmsOperationVal {
    pub kms_client: KmsCoordinator,
    pub tx_id: TransactionId,
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
impl KmsOperation for KmsCoordinator {
    async fn run(&self, event: KmsEvent) -> anyhow::Result<KmsOperationResponse> {
        let operation = self.create_kms_operation(event)?;
        operation.run_operation().await
    }
}

#[async_trait]
#[enum_dispatch(KmsOperationRequest)]
pub trait Kms {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse>;
}

#[derive(Clone, TypedBuilder)]
pub struct KmsCoordinator {
    channel: Channel,
    n_parties: u64,
    metrics: Arc<OpenTelemetryMetrics>,
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
            config.coordinator_addresses()
        );
        Ok(KmsCoordinator {
            channel,
            n_parties: config.parties,
            metrics: Arc::new(metrics),
        })
    }

    fn create_kms_operation(&self, event: KmsEvent) -> anyhow::Result<KmsOperationRequest> {
        let operation_val = KmsOperationVal {
            kms_client: self.clone(),
            tx_id: event.txn_id.clone(),
        };
        let request = match event.operation {
            KmsOperationAttribute::Reencrypt(reencrypt) => {
                KmsOperationRequest::Reencrypt(ReencryptVal {
                    reencrypt,
                    operation_val,
                })
            }
            KmsOperationAttribute::Decrypt(decrypt) => KmsOperationRequest::Decrypt(DecryptVal {
                decrypt,
                operation_val,
            }),
            KmsOperationAttribute::KeyGenPreproc(_keygen_preproc) => {
                KmsOperationRequest::KeyGenPreproc(KeyGenPreprocVal { operation_val })
            }
            KmsOperationAttribute::KeyGen(keygen) => KmsOperationRequest::KeyGen(KeyGenVal {
                keygen,
                operation_val,
            }),
            KmsOperationAttribute::CrsGen(_) => {
                KmsOperationRequest::CrsGen(CrsGenVal { operation_val })
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
macro_rules! poller {
    ($f_to_poll:expr,$res_map:expr,$retry_interval:expr,$total_duration:expr,$info:expr,$metrics:expr) => {
        let mut cnt = 0u64;
        loop {
            sleep(Duration::from_secs($retry_interval)).await;
            let resp = $f_to_poll.await;
            match $res_map(resp) {
                Ok(PollerStatus::Done(res)) => {
                    $metrics.increment(MetricType::CoordinatorResponseSuccess, 1, &[("ok", "ok")]);
                    return Ok(res);
                }
                Ok(PollerStatus::Poll) => {
                    if cnt > $total_duration {
                        let err_msg = "time out while trying to get response";
                        $metrics.increment(
                            MetricType::CoordinatorResponseError,
                            1,
                            &[("error", err_msg)],
                        );
                        return Err(anyhow!(err_msg));
                    } else {
                        cnt += 1;
                        tracing::info!(
                            "Polling coordinator {}, tries: {cnt}, interval: {}, max duration: {}",
                            $info,
                            $retry_interval,
                            $total_duration
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
impl Kms for KeyGenPreprocVal {
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

        // TODO: these timeouts are for testing,
        // these need to be configured correctly for production!

        // preprocessing is slow, so we wait for a bit before even trying
        const INITIAL_WAITING_TIME: u64 = 1;
        tokio::time::sleep(Duration::from_secs(INITIAL_WAITING_TIME)).await;

        // NOTE: we can't use the poller macro to help us poll the result since
        // the preproc endpoint is a bit different,
        // it returns Ok(status), instead of an error
        const RETRY_INTERVAL: u64 = 10;
        const MAX_DUR: u64 = 600;

        // loop to get response
        poller!(
            client.get_preproc_status(tonic::Request::new(req.clone())),
            g,
            RETRY_INTERVAL,
            MAX_DUR,
            "(KeyGenPreproc)",
            metrics
        );
    }
}

#[async_trait]
impl Kms for KeyGenVal {
    #[tracing::instrument(skip(self), fields(tx_id = %self.operation_val.tx_id.to_hex()))]
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse> {
        let chan = &self.operation_val.kms_client.channel;
        let mut client = CoordinatorEndpointClient::new(chan.clone());

        let req_id = RequestId {
            request_id: self.operation_val.tx_id.to_hex(),
        };

        let preproc_id = RequestId {
            request_id: self.keygen.preproc_id().to_string(),
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
                                    .request_id(request_id.request_id)
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

        // TODO: these timeouts are for testing,
        // these need to be configured correctly for production!

        // keygen is slow, so we wait for a bit before even trying
        const INITIAL_WAITING_TIME: u64 = 1;
        tokio::time::sleep(Duration::from_secs(INITIAL_WAITING_TIME)).await;

        const RETRY_INTERVAL: u64 = 10;
        const MAX_DUR: u64 = 600;
        // loop to get response
        poller!(
            client.get_key_gen_result(tonic::Request::new(req_id.clone())),
            g,
            RETRY_INTERVAL,
            MAX_DUR,
            "(KeyGen)",
            metrics
        );
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
                                },
                            },
                        )))
                    }
                    Err(_) => Ok(PollerStatus::Poll),
                }
            };

        // loop to get response
        const RETRY_INTERVAL: u64 = 10;
        let max_dur = MAX_CRS_GEN_DURATION_PER_PARTY_SECS * self.operation_val.kms_client.n_parties;
        poller!(
            client.get_crs_gen_result(tonic::Request::new(req_id.clone())),
            g,
            RETRY_INTERVAL,
            max_dur,
            "(CRS)",
            metrics
        );
    }
}

#[cfg(test)]
mod test {
    use super::Kms as _;
    use crate::{
        conf::CoordinatorConfig,
        domain::blockchain::KmsOperationResponse,
        infrastructure::{coordinator::KmsCoordinator, metrics::OpenTelemetryMetrics},
    };
    use events::kms::{
        CrsGenValues, KeyGenPreprocValues, KmsEvent, KmsOperationAttribute, TransactionId,
    };
    use kms_lib::{
        client::test_tools,
        consts::{
            AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT, DEFAULT_URL, TEST_KEY_ID, TEST_PARAM_PATH,
            TEST_THRESHOLD_CT_PATH, TEST_THRESHOLD_KEYS_PATH, THRESHOLD,
        },
        rpc::rpc_types::{PrivDataType, PubDataType},
        storage::{FileStorage, PublicStorage, PublicStorageReader, StorageType},
        threshold::mock_threshold_kms::setup_mock_kms,
        util::{
            file_handling::read_element,
            key_setup::{
                ensure_ciphertext_exist, ensure_dir_exist, ensure_threshold_keys_exist,
                ThresholdTestingKeys,
            },
        },
    };
    use tokio::task::JoinSet;

    async fn generic_sunshine_test(
        slow: bool,
        op: KmsOperationAttribute,
    ) -> (Vec<KmsOperationResponse>, TransactionId) {
        let txn_id = TransactionId::from(vec![2u8; 20]);
        let coordinator_handles = if slow {
            ensure_dir_exist();
            ensure_threshold_keys_exist(
                TEST_PARAM_PATH,
                TEST_THRESHOLD_KEYS_PATH,
                &TEST_KEY_ID.to_string(),
            );
            let threshold_keys: ThresholdTestingKeys =
                read_element(&format!("{TEST_THRESHOLD_KEYS_PATH}-1.bin")).unwrap();
            ensure_ciphertext_exist(TEST_THRESHOLD_CT_PATH, &threshold_keys.fhe_pub);
            let mut pub_storage = FileStorage::new(&StorageType::PUB.to_string());
            // Delete potentially existing CRS
            let _ = pub_storage.delete_data(
                &pub_storage
                    .compute_url(&txn_id.to_hex(), &PubDataType::CRS.to_string())
                    .unwrap(),
            );
            let mut priv_storage = Vec::new();
            for i in 1..=AMOUNT_PARTIES {
                let cur_priv = FileStorage::new(&format!("priv-p{i}"));
                // Delete potentially existing CRS info
                let _ = pub_storage.delete_data(
                    &cur_priv
                        .compute_url(&txn_id.to_hex(), &PrivDataType::CrsInfo.to_string())
                        .unwrap(),
                );
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
                    parties: AMOUNT_PARTIES as u64,
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
            KmsEvent {
                operation: op,
                txn_id: txn_id.clone(),
            };
            AMOUNT_PARTIES
        ];

        // each client will make the crs generation request
        // but this needs to happen in parallel
        assert_eq!(events.len(), clients.len());
        let mut tasks = JoinSet::new();
        for (event, client) in events.into_iter().zip(clients) {
            let op = client.create_kms_operation(event).unwrap();
            tasks.spawn(async move { op.run_operation().await });
        }
        let mut results = vec![];
        while let Some(Ok(Ok(res))) = tasks.join_next().await {
            results.push(res);
        }
        assert_eq!(results.len(), AMOUNT_PARTIES);

        for (_, h) in coordinator_handles {
            h.abort();
        }

        (results, txn_id)
    }

    async fn preproc_sunshine(slow: bool) {
        let op = KmsOperationAttribute::KeyGenPreproc(KeyGenPreprocValues {});
        let (results, txn_id) = generic_sunshine_test(slow, op).await;
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
        let op = KmsOperationAttribute::CrsGen(CrsGenValues {});
        let (results, txn_id) = generic_sunshine_test(slow, op).await;
        assert_eq!(results.len(), AMOUNT_PARTIES);

        // we stop testing the response logic in "fast" mode, which uses a dummy kms
        if !slow {
            return;
        }

        // the digests should all be the same but the signatures are all different
        let mut digest = None;
        let mut signature = None;
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
                    assert_eq!(resp.crs_gen_response.signature().len(), 72);
                    if signature.is_some() {
                        assert_ne!(
                            signature.clone().unwrap(),
                            resp.crs_gen_response.signature()
                        );
                    } else {
                        signature = Some(resp.crs_gen_response.signature().to_vec());
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
    async fn preproc_sunshine_mocked_coordinator() {
        preproc_sunshine(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn crs_sunshine_mocked_coordinator() {
        crs_sunshine(false).await
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
