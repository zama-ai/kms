use crate::infrastructure::coordinator::KmsCoordinator;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use events::kms::{
    DecryptValues, KeyGenValues, KmsEvent, KmsOperationAttribute, ReencryptValues, TransactionId,
};

use super::blockchain::KmsOperationResponse;

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
    KeyGenPreproc(KeyGenPreprocVal),
    KeyGen(KeyGenVal),
    CrsGen(CrsGenVal),
}

pub fn create_kms_operation(
    event: KmsEvent,
    kms_client: KmsCoordinator,
) -> anyhow::Result<KmsOperationRequest> {
    let operation_val = KmsOperationVal {
        kms_client,
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

#[async_trait]
#[enum_dispatch(KmsOperationRequest)]
pub trait Kms {
    async fn run_operation(&self) -> anyhow::Result<KmsOperationResponse>;
}

#[cfg(test)]
mod test {
    use events::kms::{
        CrsGenValues, KeyGenPreprocValues, KmsEvent, KmsOperationAttribute, TransactionId,
    };
    use kms_lib::{
        client::test_tools,
        consts::{
            AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT, DEFAULT_URL, TEST_PARAM_PATH,
            TEST_THRESHOLD_CT_PATH, TEST_THRESHOLD_KEYS_PATH, THRESHOLD,
        },
        util::key_setup::{ensure_dir_exist, ensure_threshold_key_ct_exist},
    };
    use tokio::task::JoinSet;

    use crate::{
        conf::CoordinatorConfig,
        domain::{
            blockchain::KmsOperationResponse,
            kms::{create_kms_operation, Kms},
        },
        infrastructure::{coordinator::KmsCoordinator, metrics::OpenTelemetryMetrics},
    };

    async fn generic_sunshine_test(
        op: KmsOperationAttribute,
    ) -> (Vec<KmsOperationResponse>, TransactionId) {
        ensure_dir_exist();
        let test_param_path = format!("../../coordinator/{}", TEST_PARAM_PATH);
        ensure_threshold_key_ct_exist(
            &test_param_path,
            TEST_THRESHOLD_KEYS_PATH,
            TEST_THRESHOLD_CT_PATH,
        );
        let coordinator_handles = test_tools::setup_threshold_no_client(
            AMOUNT_PARTIES,
            THRESHOLD as u8,
            TEST_THRESHOLD_KEYS_PATH,
        )
        .await;

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
        let txn_id = TransactionId::from(vec![2u8; 20]);
        let events = vec![
            KmsEvent {
                operation: op,
                txn_id: txn_id.clone(),
            };
            AMOUNT_PARTIES
        ];

        // each client will make the crs generation request
        // but this needs to happen in parallel
        let mut tasks = JoinSet::new();
        for (event, client) in events.into_iter().zip(clients) {
            let op = create_kms_operation(event, client).unwrap();
            tasks.spawn(async move { op.run_operation().await });
        }
        let mut results = vec![];
        while let Some(Ok(Ok(res))) = tasks.join_next().await {
            results.push(res);
        }

        for (_, h) in coordinator_handles {
            h.abort();
        }

        (results, txn_id)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn preproc_sunshine() {
        let op = KmsOperationAttribute::KeyGenPreproc(KeyGenPreprocValues {});
        let (results, txn_id) = generic_sunshine_test(op).await;

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

    #[tokio::test]
    #[serial_test::serial]
    async fn crs_sunshine() {
        let op = KmsOperationAttribute::CrsGen(CrsGenValues {});
        let (results, txn_id) = generic_sunshine_test(op).await;

        for result in results {
            match result {
                KmsOperationResponse::CrsGenResponse(resp) => {
                    assert_eq!(resp.crs_gen_response.request_id(), txn_id.to_hex());
                    assert_eq!(resp.crs_gen_response.digest().len(), 40);
                    assert_eq!(resp.crs_gen_response.signature().len(), 72);
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }
}
