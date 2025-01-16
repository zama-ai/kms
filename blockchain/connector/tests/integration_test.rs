use conf_trace::conf::TelemetryConfig;
use conf_trace::telemetry::init_telemetry;
use events::kms::CrsGenValues;
use events::kms::{
    DecryptResponseValues, DecryptValues, FheParameter, FheType, InsecureKeyGenValues,
    KeyGenPreprocValues, KeyGenResponseValues, KmsEvent, KmsMessage, Transaction, TransactionId,
    VerifyProvenCtValues,
};
use events::kms::{KmsOperation, OperationValue};
use events::subscription::TxResponse;
use events::{
    kms::{KeyGenValues, ReencryptValues},
    HexVector,
};
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest, ProtoCoin};
use kms_blockchain_client::query_client::{
    BscQuery, QueryClient, QueryClientBuilder, TransactionQuery,
};
use kms_blockchain_connector::application::kms_core_connector::{
    KmsCoreConnector, KmsCoreEventHandler,
};
use kms_blockchain_connector::application::Connector;
use kms_blockchain_connector::config::{
    BlockchainConfig, ConnectorConfig, ContractFee, CoreConfig, ShardingConfig, SignKeyConfig,
    TimeoutConfig,
};
use kms_blockchain_connector::domain::blockchain::{
    Blockchain, BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse,
};
use kms_blockchain_connector::domain::kms::{CatchupResult, Kms};
use kms_blockchain_connector::domain::storage::Storage;
use kms_blockchain_connector::infrastructure::blockchain::KmsBlockchain;
use kms_blockchain_connector::infrastructure::core::{KmsCore, KmsEventHandler};
use kms_blockchain_connector::infrastructure::metrics::OpenTelemetryMetrics;
use kms_common::retry_loop;
use kms_grpc::kms::v1::{
    DecryptionResponsePayload, ReencryptionResponse, ReencryptionResponsePayload, RequestId,
    VerifyProvenCtResponse, VerifyProvenCtResponsePayload,
};
use kms_grpc::rpc_types::{protobuf_to_alloy_domain, SIGNING_KEY_ID};
use kms_lib::client::assemble_metadata_alloy;
use kms_lib::consts::SAFE_SER_SIZE_LIMIT;
use kms_lib::consts::TEST_PARAM;
use kms_lib::util::key_setup::test_tools::compute_proven_ct_from_stored_key;
use kms_lib::util::key_setup::{
    ensure_central_crs_exists, ensure_threshold_crs_exists, max_threshold,
};
use kms_lib::{
    client::{test_tools, ParsedReencryptionRequest},
    consts::{
        DEFAULT_PROT, DEFAULT_URL, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_CRS_ID, TEST_CENTRAL_KEY_ID,
        TEST_THRESHOLD_CRS_ID_4P, TEST_THRESHOLD_CRS_ID_7P, TEST_THRESHOLD_KEY_ID_4P,
        TEST_THRESHOLD_KEY_ID_7P,
    },
    engine::threshold::service_mock::setup_mock_kms,
    util::key_setup::{
        ensure_central_keys_exist, ensure_central_server_signing_keys_exist,
        ensure_client_keys_exist, ensure_threshold_keys_exist,
        ensure_threshold_server_signing_keys_exist,
        test_tools::{compute_cipher_from_stored_key, purge},
    },
    vault::storage::{file::FileStorage, StorageType},
};
use rand::RngCore;
use std::collections::HashMap;
use std::env::set_var;
use std::sync::Arc;
use test_context::{test_context, AsyncTestContext};
use test_utilities::context::DockerCompose;
use test_utils::integration_test;
use tokio::fs;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};

struct DockerComposeContext {
    cmd: DockerCompose,
}

impl AsyncTestContext for DockerComposeContext {
    async fn setup() -> Self {
        fs::create_dir_all("tests/data").await.unwrap();
        DockerComposeContext {
            cmd: DockerCompose::new("tests/docker-compose.yml"),
        }
    }

    async fn teardown(self) {
        fs::remove_dir_all("tests/data").await.unwrap();
        drop(self.cmd);
    }
}

#[derive(Clone)]
struct KmsMock {
    channel: Arc<Sender<KmsEvent>>,
}

#[async_trait::async_trait]
impl Kms for KmsMock {
    async fn run(
        &self,
        event: KmsEvent,
        _operation_value: OperationValue,
        _fhe_parameter: Option<FheParameter>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<anyhow::Result<KmsOperationResponse>>> {
        self.channel.send(event.clone()).await?;

        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let res = Ok(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
                decrypt_response: DecryptResponseValues::new(
                    vec![1, 2, 3],
                    "Hello World".as_bytes().to_vec(),
                ),
                operation_val: BlockchainOperationVal {
                    tx_id: event.txn_id().clone(),
                },
            }));
            let _ = sender.send(res);
        });
        Ok(receiver)
    }

    async fn run_catchup(
        &self,
        event: KmsEvent,
        _operation_value: OperationValue,
        _fhe_parameter: Option<FheParameter>,
    ) -> anyhow::Result<CatchupResult> {
        self.channel.send(event.clone()).await?;
        Ok(CatchupResult::Now(Ok(
            KmsOperationResponse::DecryptResponse(DecryptResponseVal {
                decrypt_response: DecryptResponseValues::new(
                    vec![1, 2, 3],
                    "Hello World".as_bytes().to_vec(),
                ),
                operation_val: BlockchainOperationVal {
                    tx_id: event.txn_id().clone(),
                },
            }),
        )))
    }
}

/// Wait 1 minute for everything to setup properly
const BOOTSTRAP_TIME_TO_SLEEP: u64 = 60;

#[test_context(DockerComposeContext)]
#[tokio::test]
#[integration_test]
#[serial_test::serial]
async fn test_blockchain_connector(_ctx: &mut DockerComposeContext) {
    option_env!("RUST_LOG")
        .map(|_| ())
        .unwrap_or_else(|| set_var("RUST_LOG", "error"));
    // Initialize tracing if not already initialized
    let _guard = init_telemetry(
        &TelemetryConfig::builder()
            .tracing_service_name("connector_test".to_string())
            .build(),
    );

    let mnemonic = Some("whisper stereo great helmet during hollow nominee skate frown daughter donor pool ozone few find risk cigar practice essay sketch rhythm novel dumb host".to_string());
    let addresses = vec!["http://localhost:9090"];
    let key_id = vec![1, 2, 3];

    // Initialize the query client for checking the blockchain state
    let query_client: QueryClient = QueryClientBuilder::builder()
        .grpc_addresses(addresses.clone())
        .build()
        .try_into()
        .unwrap();

    // Wait for the contract to be deployed
    sleep(Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    // The CSC is the first contract uploaded (see `deploy_contracts.sh`). We therefore
    // get the address for code_id = 1.
    tracing::info!("Fetch CSC address");
    let csc_address = get_contract_address(&query_client, 1).await.unwrap();

    // The BSC is the second contract uploaded (see `deploy_contracts.sh`). We therefore
    // get the address for code_id = 2.
    tracing::info!("Fetch BSC address");
    let bsc_address = get_contract_address(&query_client, 2).await.unwrap();

    let client: RwLock<Client> = RwLock::new(
        ClientBuilder::builder()
            .mnemonic_wallet(mnemonic.as_deref())
            .grpc_addresses(addresses.clone())
            .kv_store_address(None)
            .build()
            .try_into()
            .unwrap(),
    );

    let (tx, mut rc) = channel(1);
    // Start SyncHandler to listen events
    let handler =
        start_sync_handler(addresses.clone(), &bsc_address, &csc_address, mnemonic, tx).await;

    // Wait for the event to be processed and send the response back to the blockchain
    let query_client = Arc::new(query_client);
    let cloned_query_client = Arc::clone(&query_client);
    let cloned_bsc_address = bsc_address.clone();
    let handle = tokio::spawn(async move {
        wait_for_event_response(handler, &cloned_bsc_address, cloned_query_client, &mut rc).await;
    });

    // Execute insecure key generation flow to enable the subsequent decryption request
    let keygen_request_txhash = send_insecure_key_generation_request(&client, &bsc_address).await;
    let keygen_tx_response =
        wait_for_tx_processed(Arc::clone(&query_client), keygen_request_txhash.clone())
            .await
            .unwrap();
    let txn_id = get_event_value_from_response(keygen_tx_response.clone(), "txn_id".to_string())
        .map_err(|e| tracing::error!("{}", e))
        .unwrap();
    let keygen_response_txhash = send_key_generation_response(
        &client,
        &bsc_address,
        TransactionId::from_hex(&txn_id).unwrap(),
        key_id.clone(),
    )
    .await;
    wait_for_tx_processed(Arc::clone(&query_client), keygen_response_txhash.clone())
        .await
        .unwrap();

    // Send decryption request to the blockchain in order to get events after
    let txhash = send_decrypt_request(&client, &bsc_address, key_id).await;

    wait_for_tx_processed(query_client, txhash.clone())
        .await
        .unwrap();

    handle.await.unwrap();
}

async fn wait_for_event_response<T>(
    handler: T,
    bsc_address: &str,
    query_client: Arc<QueryClient>,
    rc: &mut Receiver<KmsEvent>,
) where
    T: Connector + Send + Sync + 'static,
{
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let (timeout_tx, timeout_rx) = oneshot::channel();
    let timeout_task = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        timeout_tx.send(()).unwrap();
    };
    let (tx_response, mut rc_response) = channel(1);
    tokio::spawn(handler.listen_for_events(None));
    tokio::spawn(timeout_task);
    tokio::select! {
        _ = timeout_rx => {
            panic!("Timeout")
        }
        _ = async {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                    }
                    event = rc.recv() => {
                        tokio::spawn(check_event(event.unwrap(), bsc_address.to_string(), query_client.clone(), tx_response.clone()));
                    }
                    _ = rc_response.recv() => {
                        counter.fetch_add(1, std::sync::atomic::Ordering::Release);
                        break;
                    }
                }
            }
        } => { }
    }

    assert_eq!(counter.load(std::sync::atomic::Ordering::Acquire), 1);
}

async fn wait_for_tx_processed(
    query_client: Arc<QueryClient>,
    txhash: String,
) -> anyhow::Result<TxResponse> {
    retry_loop!(
        || async {
            let r = query_client
                .query_tx(txhash.clone())
                .await
                .map_err(|e| anyhow::anyhow!("Transaction error {:?}", e))?;
            if r.is_none() {
                Err(anyhow::anyhow!(
                    "Transaction with hash {} not found.",
                    txhash
                ))
            } else {
                tracing::info!("Tx processed: {:?}", r);
                Ok(r.unwrap())
            }
        },
        5000,
        4
    )
}

/// Check the event status in the blockchain to verify if it was processed and
/// the decryption response was sent back to the blockchain
async fn check_event(
    event: KmsEvent,
    bsc_address: String,
    query_client: Arc<QueryClient>,
    tx_sender: Sender<()>,
) {
    loop {
        let tx: Transaction = query_client
            .query_bsc(
                bsc_address.clone(),
                BscQuery::GetTransaction(TransactionQuery {
                    txn_id: event.txn_id().clone(),
                }),
            )
            .await
            .unwrap();
        if tx.operations().iter().any(|x| {
            <OperationValue as Into<KmsOperation>>::into(x.clone()) == KmsOperation::DecryptResponse
        }) {
            tx_sender.send(()).await.expect("Failed to send response");
            break;
        }
    }
}

/// Get the contract address for a given code ID.
///
/// Code ID are defined by the order of contract upload in `deploy_contracts.sh`, starting from 1.
async fn get_contract_address(client: &QueryClient, code_id: u64) -> anyhow::Result<String> {
    retry_loop!(
        || async {
            tracing::info!("Getting contract address...");
            let result = client.list_contracts(code_id).await.unwrap();
            if !result.contracts.is_empty() {
                tracing::info!("Found {} contracts", result.contracts.len());
                let contract_address = result.contracts[0].clone();
                let contract_metadata = client
                    .get_contract_metadata(contract_address.clone())
                    .await?;
                tracing::info!("Contract metadata {:?}", contract_metadata);
                Ok(contract_address)
            } else {
                Err(anyhow::anyhow!(
                    "Contract with code ID {} not found.",
                    code_id
                ))
            }
        },
        10000,
        12
    )
}

async fn start_sync_handler(
    addresses: Vec<&str>,
    bsc_address: &str,
    csc_address: &str,
    mnemonic: Option<String>,
    tx: Sender<KmsEvent>,
) -> KmsCoreConnector<KmsBlockchain, KmsMock, OpenTelemetryMetrics> {
    let blockchain_config = BlockchainConfig {
        addresses: addresses
            .clone()
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
        bsc_address: bsc_address.to_string(),
        csc_address: csc_address.to_string(),
        fee: ContractFee {
            amount: 250_000u64,
            denom: "ucosm".to_string(),
        },
        signkey: SignKeyConfig {
            mnemonic,
            bip32: None,
        },
        kv_store_address: None,
    };
    let metrics = OpenTelemetryMetrics::new();
    let blockchain = KmsBlockchain::new(blockchain_config.clone(), metrics.clone())
        .await
        .unwrap();
    let connector_config = ConnectorConfig {
        tick_interval_secs: 1,
        blockchain: blockchain_config,
        ..Default::default()
    };
    let my_pk = blockchain.get_public_key().await;
    KmsCoreConnector::builder()
        .kms_connector_handler(
            KmsCoreEventHandler::builder()
                .blockchain(Arc::new(blockchain))
                .kms(KmsMock {
                    channel: Arc::new(tx),
                })
                .observability(Arc::new(metrics))
                .my_pk(my_pk)
                .sharding(ShardingConfig::default())
                .build(),
        )
        .config(connector_config)
        .build()
}

/// Extracts the event value of a specified event key from a transaction response.
fn get_event_value_from_response(
    tx_response: TxResponse,
    event_key: String,
) -> anyhow::Result<String> {
    for event in tx_response.events {
        if let Some(attribute) = event.attributes.iter().find(|attr| attr.key == event_key) {
            return Ok(attribute.value.clone());
        }
    }
    Err(anyhow::anyhow!(
        "Event key <{}> not found in the tx response",
        event_key
    ))
}

async fn send_insecure_key_generation_request(
    client: &RwLock<Client>,
    bsc_address: &str,
) -> String {
    let keygen_request = InsecureKeyGenValues::new(
        "eip712name".to_string(),
        "version".to_string(),
        vec![1; 32],
        "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
        Some(vec![42; 32]),
    )
    .unwrap();
    let operation = events::kms::OperationValue::InsecureKeyGen(keygen_request);
    let request = ExecuteContractRequest::builder()
        .contract_address(bsc_address.to_string())
        .message(KmsMessage::builder().value(operation).build())
        .gas_limit(200000u64)
        .funds(vec![ProtoCoin::builder()
            .denom("ucosm".to_string())
            .amount(100_000u64)
            .build()])
        .build();
    let resp = client.write().await.execute_contract(request).await;
    tracing::info!("Insecure key generation request transaction: {:?}", resp);

    resp.unwrap().txhash
}

async fn send_key_generation_response(
    client: &RwLock<Client>,
    bsc_address: &str,
    txn_id: TransactionId,
    key_id: Vec<u8>,
) -> String {
    let keygen_response = KeyGenResponseValues::new(
        key_id,
        "digest1".to_string(),
        vec![4, 5, 6],
        vec![9, 9, 9],
        "digest2".to_string(),
        vec![7, 8, 9],
        vec![7, 7, 7],
        FheParameter::Test,
    );
    let operation = events::kms::OperationValue::KeyGenResponse(keygen_response);
    let request = ExecuteContractRequest::builder()
        .contract_address(bsc_address.to_string())
        .message(
            KmsMessage::builder()
                .value(operation)
                .txn_id(txn_id)
                .build(),
        )
        .gas_limit(300000u64)
        .funds(vec![ProtoCoin::builder()
            .denom("ucosm".to_string())
            .amount(100_000u64)
            .build()])
        .build();
    let resp = client.write().await.execute_contract(request).await;
    tracing::info!("Key generation response transaction: {:?}", resp);

    resp.unwrap().txhash
}

async fn send_decrypt_request(
    client: &RwLock<Client>,
    bsc_address: &str,
    key_id: Vec<u8>,
) -> String {
    let decrypt = DecryptValues::new(
        key_id,
        vec![[0, 0, 0, 0, 0, 1, 1, 1, 1, 1].to_vec()],
        vec![FheType::Euint8],
        Some(vec![[1, 0, 0, 0, 0, 1, 1, 1, 1, 1].to_vec()]),
        "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
        "some_proof".to_string(),
        "eip712name".to_string(),
        "1".to_string(),
        vec![101; 32],
        "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
        Some(vec![42; 32]),
    )
    .unwrap();

    let operation = events::kms::OperationValue::Decrypt(decrypt);

    let request = ExecuteContractRequest::builder()
        .contract_address(bsc_address.to_string())
        .message(KmsMessage::builder().value(operation).build())
        .gas_limit(200000u64)
        .funds(vec![ProtoCoin::builder()
            .denom("ucosm".to_string())
            .amount(100_000u64)
            .build()])
        .build();

    let resp = client.write().await.execute_contract(request).await;

    tracing::info!("Decryption request transaction: {:?}", resp);

    resp.unwrap().txhash
}

const MOCK_CT_HANDLES: &[&[u8]] = &[
    &[0, 0, 0],
    &[1, 1, 1],
    &[2, 2, 2],
    &[3, 3, 3],
    &[4, 4, 4],
    &[5, 5, 5],
];

const MOCK_EXTERNAL_HANDLES: &[&[u8]] = &[
    &[6, 6, 6],
    &[7, 7, 7],
    &[8, 8, 8],
    &[9, 9, 9],
    &[10, 10, 10],
    &[11, 11, 11],
];

/// Generate keys (if they don't already exist) for a given fhe_key_id. Also generates a CRS with ID TEST_CRS_ID_4P
async fn setup_threshold_keys(fhe_key_id: &RequestId, amount_parties: usize) {
    let mut threshold_pub_storages = Vec::with_capacity(amount_parties);
    for i in 1..=amount_parties {
        threshold_pub_storages.push(FileStorage::new(None, StorageType::PUB, Some(i)).unwrap());
    }
    let mut threshold_priv_storages = Vec::with_capacity(amount_parties);
    for i in 1..=amount_parties {
        threshold_priv_storages.push(FileStorage::new(None, StorageType::PRIV, Some(i)).unwrap());
    }

    ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;
    ensure_threshold_server_signing_keys_exist(
        &mut threshold_pub_storages,
        &mut threshold_priv_storages,
        &SIGNING_KEY_ID,
        true,
        kms_lib::util::key_setup::ThresholdSigningKeyConfig::AllParties(amount_parties),
    )
    .await;
    ensure_threshold_keys_exist(
        &mut threshold_pub_storages,
        &mut threshold_priv_storages,
        TEST_PARAM,
        fhe_key_id,
        true,
    )
    .await;
    ensure_threshold_crs_exists(
        &mut threshold_pub_storages,
        &mut threshold_priv_storages,
        TEST_PARAM,
        &TEST_THRESHOLD_CRS_ID_4P,
        true,
    )
    .await;
}

/// Generate keys (if they don't already exist) and CRS (with ID TEST_CRS_ID) for the centralized case with 2 keys with IDs TEST_CENTRAL_KEY_ID, OTHER_CENTRAL_TEST_ID
async fn setup_central_keys(fhe_key_id: &RequestId, other_fhe_key_id: &RequestId) {
    let mut central_pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    let mut central_priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();

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
        TEST_PARAM,
        fhe_key_id,
        other_fhe_key_id,
        true,
        false,
    )
    .await;
    ensure_central_crs_exists(
        &mut central_pub_storage,
        &mut central_priv_storage,
        TEST_PARAM,
        &TEST_CENTRAL_CRS_ID,
        true,
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

    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    let join_handle =
        test_tools::setup_centralized_no_client(pub_storage, priv_storage, None).await;

    let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", join_handle.port);
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

    let client = KmsCore::new(config.clone(), mock_storage, OpenTelemetryMetrics::new()).unwrap();

    let mut txn_buf = vec![0u8; 20];
    rand::thread_rng().fill_bytes(&mut txn_buf);

    let txn_id = TransactionId::from(txn_buf);
    let event = KmsEvent::builder()
        .operation(op.clone())
        .txn_id(txn_id.clone())
        .build();

    let fhe_parameter = FheParameter::Test;

    let result = client
        .create_kms_operation(event, op.clone())
        .unwrap()
        .run_operation(Some(fhe_parameter))
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap();

    join_handle.assert_shutdown().await;
    (result, txn_id)
}

#[tokio::test]
#[integration_test]
#[serial_test::serial]
async fn ddec_centralized_sunshine() {
    let msg1 = 110u8;
    let msg2 = 222u16;
    setup_central_keys(&TEST_CENTRAL_KEY_ID, &OTHER_CENTRAL_TEST_ID).await;
    let (ct1, fhe_type1): (Vec<u8>, kms_grpc::kms::v1::FheType) =
        compute_cipher_from_stored_key(None, msg1.into(), &TEST_CENTRAL_KEY_ID.to_string()).await;
    let (ct2, fhe_type2): (Vec<u8>, kms_grpc::kms::v1::FheType) =
        compute_cipher_from_stored_key(None, msg2.into(), &TEST_CENTRAL_KEY_ID.to_string()).await;
    let op = OperationValue::Decrypt(
        DecryptValues::new(
            HexVector::from_hex(&TEST_CENTRAL_KEY_ID.request_id).unwrap(),
            vec![MOCK_CT_HANDLES[0].to_vec(), MOCK_CT_HANDLES[1].to_vec()],
            vec![
                events::kms::FheType::from(fhe_type1 as u8),
                events::kms::FheType::from(fhe_type2 as u8),
            ],
            Some(vec![
                MOCK_EXTERNAL_HANDLES[0].to_vec(),
                MOCK_EXTERNAL_HANDLES[1].to_vec(),
            ]),
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "some_proof".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![101; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap(),
    );
    let (result, txn_id) = generic_centralized_sunshine_test(vec![ct1, ct2], op).await;
    match result {
        KmsOperationResponse::DecryptResponse(resp) => {
            let payload: DecryptionResponsePayload = bincode::deserialize(
                <&HexVector as Into<Vec<u8>>>::into(resp.decrypt_response.payload()).as_slice(),
            )
            .unwrap();

            assert_eq!(payload.plaintexts[0].as_u8(), msg1,);
            assert_eq!(payload.plaintexts[1].as_u16(), msg2,);
            assert_eq!(resp.operation_val.tx_id, txn_id);
        }
        _ => {
            panic!("invalid response");
        }
    }
}

#[tokio::test]
#[integration_test]
#[serial_test::serial]
async fn keygen_sunshine_central() {
    setup_central_keys(&TEST_CENTRAL_KEY_ID, &OTHER_CENTRAL_TEST_ID).await;

    // the preproc_id can just be some dummy value since
    // the centralized case does not need it
    let op = OperationValue::KeyGen(
        KeyGenValues::new(
            HexVector::from_hex("1111111111111111111111111111111111112222").unwrap(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap(),
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
#[integration_test]
#[serial_test::serial]
async fn crs_sunshine_central() {
    setup_central_keys(&TEST_CENTRAL_KEY_ID, &OTHER_CENTRAL_TEST_ID).await;
    let op = OperationValue::CrsGen(
        CrsGenValues::new(
            128,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap(),
    );
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
    amount_parties: usize,
) -> (Vec<KmsOperationResponse>, TransactionId, Vec<u32>) {
    let threshold = max_threshold(amount_parties);
    let txn_id = TransactionId::from(vec![2u8; 20]);
    let core_handles = if slow {
        // Delete potentially existing CRS
        purge(None, None, &txn_id.to_hex(), amount_parties).await;
        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        for i in 1..=amount_parties {
            let cur_pub = FileStorage::new(None, StorageType::PUB, Some(i)).unwrap();
            pub_storage.push(cur_pub);
            let cur_priv = FileStorage::new(None, StorageType::PRIV, Some(i)).unwrap();
            priv_storage.push(cur_priv);
        }
        test_tools::setup_threshold_no_client(
            threshold as u8,
            pub_storage,
            priv_storage,
            true,
            None,
        )
        .await
    } else {
        setup_mock_kms(amount_parties).await
    };
    assert_eq!(core_handles.len(), amount_parties);

    // create configs
    let configs = (0..amount_parties as u32)
        .map(|i| {
            let port = core_handles.get(&(i + 1)).as_ref().unwrap().port;
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
        clients
            .push(KmsCore::new(config.clone(), mock_storage, OpenTelemetryMetrics::new()).unwrap());
    }

    // create events
    let events = vec![
        KmsEvent::builder()
            .operation(op.clone())
            .txn_id(txn_id.clone())
            .build();
        amount_parties
    ];

    // each client will make the request
    // but this needs to happen in parallel
    assert_eq!(events.len(), clients.len());
    let mut tasks = JoinSet::new();
    for (i, (event, client)) in events.into_iter().zip(clients).enumerate() {
        let fhe_parameter = FheParameter::Test;
        let op = client.create_kms_operation(event, op.clone()).unwrap();
        tasks.spawn(async move { (i as u32 + 1, op.run_operation(Some(fhe_parameter)).await) });
    }
    let mut results = vec![];
    let mut ids = vec![];

    while let Some(Ok((i, Ok(res)))) = tasks.join_next().await {
        results.push(res.await.unwrap().unwrap());
        ids.push(i);
    }
    assert_eq!(results.len(), amount_parties);

    for h in core_handles.into_values() {
        h.assert_shutdown().await;
    }

    (results, txn_id, ids)
}

async fn ddec_sunshine(key_id: &RequestId, amount_parties: usize, slow: bool) {
    setup_threshold_keys(key_id, amount_parties).await;
    let msg1 = 121u8;
    let msg2 = 321u16;
    let (ct1, fhe_type1): (Vec<u8>, kms_grpc::kms::v1::FheType) =
        compute_cipher_from_stored_key(None, msg1.into(), &key_id.to_string()).await;
    let (ct2, fhe_type2): (Vec<u8>, kms_grpc::kms::v1::FheType) =
        compute_cipher_from_stored_key(None, msg2.into(), &key_id.to_string()).await;
    let op = OperationValue::Decrypt(
        DecryptValues::new(
            HexVector::from_hex(&key_id.request_id).unwrap(),
            vec![MOCK_CT_HANDLES[0].to_vec(), MOCK_CT_HANDLES[1].to_vec()],
            vec![
                events::kms::FheType::from(fhe_type1 as u8),
                events::kms::FheType::from(fhe_type2 as u8),
            ],
            Some(vec![
                MOCK_EXTERNAL_HANDLES[0].to_vec(),
                MOCK_EXTERNAL_HANDLES[1].to_vec(),
            ]),
            "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
            "some_proof".to_string(),
            "eip712name".to_string(),
            "1".to_string(),
            vec![1; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap(),
    );
    let (results, txn_id, _) =
        generic_sunshine_test(slow, vec![ct1, ct2], op, amount_parties).await;
    assert_eq!(results.len(), amount_parties);

    for result in results {
        match result {
            KmsOperationResponse::DecryptResponse(resp) => {
                let payload: DecryptionResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(resp.decrypt_response.payload()).as_slice(),
                )
                .unwrap();
                if slow {
                    assert_eq!(payload.plaintexts[0].as_u8(), msg1,);
                    assert_eq!(payload.plaintexts[1].as_u16(), msg2,);
                }
                assert_eq!(resp.operation_val.tx_id, txn_id);
            }
            _ => {
                panic!("invalid response");
            }
        }
    }
}

/// an Eip-712 domain for testing
fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "dummy",
        version: "1",
        chain_id: 0,
        verifying_contract: alloy_primitives::Address::ZERO,
        // No salt
    )
}

async fn reenc_sunshine(key_id: &RequestId, amount_parties: usize, slow: bool) {
    setup_threshold_keys(key_id, amount_parties).await;
    let msg = 111u8;
    let (ct, fhe_type): (Vec<u8>, kms_grpc::kms::v1::FheType) =
        compute_cipher_from_stored_key(None, msg.into(), &key_id.to_string()).await;

    let mut pub_storage = Vec::with_capacity(amount_parties);
    for i in 1..=amount_parties {
        pub_storage.push(FileStorage::new(None, StorageType::PUB, Some(i)).unwrap());
    }
    let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
    let mut kms_client =
        kms_lib::client::Client::new_client(client_storage, pub_storage, &TEST_PARAM)
            .await
            .unwrap();

    let request_id = RequestId {
        request_id: "1111000000000000000000000000000000001111".to_string(),
    };
    let (kms_req, enc_pk, enc_sk) = kms_client
        .reencryption_request(ct.clone(), &dummy_domain(), fhe_type, &request_id, key_id)
        .unwrap();
    let payload = kms_req.payload.clone().unwrap();
    let eip712 = kms_req.domain.clone().unwrap();
    let dummy_external_ciphertext_handle = vec![0_u8, 32];
    let op = OperationValue::Reencrypt(
        ReencryptValues::new(
            kms_req.signature.clone(),
            payload.client_address,
            payload.enc_key,
            events::kms::FheType::from(fhe_type as u8),
            HexVector::from_hex(payload.key_id.unwrap().request_id.as_str()).unwrap(),
            dummy_external_ciphertext_handle,
            MOCK_CT_HANDLES[0].to_vec(),
            payload.ciphertext_digest,
            "dummy_acl_address".to_string(),
            "some proof".to_string(),
            eip712.name,
            eip712.version,
            eip712.chain_id,
            eip712.verifying_contract,
            eip712.salt,
        )
        .unwrap(),
    );
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![ct], op, amount_parties).await;
    assert_eq!(results.len(), amount_parties);

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
        kms_client.convert_to_addresses();
        let pt = kms_client
            .process_reencryption_resp(&client_request, &eip712_domain, &agg_resp, &enc_pk, &enc_sk)
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
                    assert_eq!(payload.digest, "dummy digest".as_bytes().to_vec());
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }
}

async fn verify_proven_ct_sunshine(
    crs_id: &RequestId,
    key_id: &RequestId,
    amount_parties: usize,
    slow: bool,
) {
    setup_threshold_keys(key_id, amount_parties).await;
    let msg = vec![42u32.into(), 111u8.into()];

    let mut pub_storage = Vec::with_capacity(amount_parties);
    for i in 1..=amount_parties {
        pub_storage.push(FileStorage::new(None, StorageType::PUB, Some(i)).unwrap());
    }
    let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
    let kms_client = kms_lib::client::Client::new_client(client_storage, pub_storage, &TEST_PARAM)
        .await
        .unwrap();

    let request_id = RequestId {
        request_id: "2222000000000000000000000000000000001111".to_string(),
    };

    let dummy_contract_address =
        alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
    let dummy_acl_address = alloy_primitives::address!("ffda6bf26964af9d7eed9e03e53415d37aa96045");

    let metadata = assemble_metadata_alloy(
        &dummy_contract_address,
        &kms_client.get_client_address(),
        &dummy_acl_address,
        &dummy_domain().chain_id.unwrap(),
    );

    let ct_proof = compute_proven_ct_from_stored_key(
        None,
        msg,
        &key_id.to_string(),
        &crs_id.to_string(),
        &metadata,
    )
    .await;

    let kms_req = kms_client
        .verify_proven_ct_request(
            crs_id,
            key_id,
            &dummy_contract_address,
            &ct_proof,
            &dummy_domain(),
            &dummy_acl_address,
            &request_id,
        )
        .unwrap();

    let eip712 = kms_req.domain.clone().unwrap();

    let op = OperationValue::VerifyProvenCt(
        VerifyProvenCtValues::new(
            HexVector::from_hex(kms_req.crs_handle.unwrap().request_id.as_str()).unwrap(),
            HexVector::from_hex(kms_req.key_handle.unwrap().request_id.as_str()).unwrap(),
            kms_req.contract_address,
            kms_req.client_address,
            MOCK_CT_HANDLES[0].to_vec(),
            kms_req.acl_address,
            eip712.name,
            eip712.version,
            eip712.chain_id,
            eip712.verifying_contract,
            eip712.salt,
        )
        .unwrap(),
    );
    let mut ct_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(&ct_proof, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![ct_buf], op, amount_parties).await;
    assert_eq!(results.len(), amount_parties);

    if slow {
        // process the result using the kms client when we're running in the slow mode
        // i.e., it is an integration test
        let agg_resp: Vec<VerifyProvenCtResponse> = results
            .into_iter()
            .map(|r| {
                let r = match r {
                    KmsOperationResponse::VerifyProvenCtResponse(resp) => resp,
                    _ => panic!("invalid response"),
                }
                .verify_proven_ct_response;

                let payload: VerifyProvenCtResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(r.payload()).as_slice(),
                )
                .unwrap();
                VerifyProvenCtResponse {
                    signature: r.signature().to_vec(),
                    payload: Some(payload),
                }
            })
            .collect();
        // Try to check that enough signatures agree
        let _ = kms_client
            .process_verify_proven_ct_resp(&agg_resp, amount_parties as u32)
            .unwrap();
    } else {
        // otherwise just check that we're getting dummy values back
        for result in results {
            match result {
                KmsOperationResponse::VerifyProvenCtResponse(resp) => {
                    let resp_value = &resp.verify_proven_ct_response;
                    assert_eq!(resp.operation_val.tx_id, txn_id);
                    let payload: VerifyProvenCtResponsePayload =
                        bincode::deserialize(resp_value.payload().as_slice()).unwrap();
                    assert_eq!(payload.ct_digest, "dummy digest".as_bytes().to_vec());
                }
                _ => {
                    panic!("invalid response");
                }
            }
        }
    }
}

async fn keygen_sunshine(key_id: &RequestId, amount_parties: usize, slow: bool) {
    setup_threshold_keys(key_id, amount_parties).await;
    if slow {
        panic!("slow/integration test is not supported since there's no preprocessing material")
    }

    let op = OperationValue::KeyGen(
        KeyGenValues::new(
            HexVector::from_hex("1111111111111111111111111111111111112222").unwrap(),
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "contract".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap(),
    );
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![], op, amount_parties).await;
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

async fn preproc_sunshine(key_id: &RequestId, amount_parties: usize, slow: bool) {
    setup_threshold_keys(key_id, amount_parties).await;
    let op = OperationValue::KeyGenPreproc(KeyGenPreprocValues {});
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![], op, amount_parties).await;
    assert_eq!(results.len(), amount_parties);

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

async fn crs_sunshine(key_id: &RequestId, amount_parties: usize, slow: bool) {
    setup_threshold_keys(key_id, amount_parties).await;
    let op = OperationValue::CrsGen(
        CrsGenValues::new(
            256,
            "eip712name".to_string(),
            "version".to_string(),
            vec![1; 32],
            "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
            Some(vec![42; 32]),
        )
        .unwrap(),
    );
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![], op, amount_parties).await;
    assert_eq!(results.len(), amount_parties);

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
                    <&HexVector as Into<Vec<u8>>>::into(resp.crs_gen_response.signature()).len(),
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
#[rstest::rstest]
#[case(&TEST_THRESHOLD_KEY_ID_7P, 10)]
#[case(&TEST_THRESHOLD_KEY_ID_4P, 4)]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn ddec_sunshine_mocked_core(#[case] key_id: &RequestId, #[case] amount_parties: usize) {
    ddec_sunshine(key_id, amount_parties, false).await
}

#[tokio::test]
#[rstest::rstest]
#[case(&TEST_THRESHOLD_KEY_ID_7P, 10)]
#[case(&TEST_THRESHOLD_KEY_ID_4P, 4)]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn reenc_sunshine_mocked_core(#[case] key_id: &RequestId, #[case] amount_parties: usize) {
    reenc_sunshine(key_id, amount_parties, false).await
}

#[tokio::test]
#[rstest::rstest]
#[case(&TEST_THRESHOLD_CRS_ID_7P, &TEST_THRESHOLD_KEY_ID_7P, 10)]
#[case(&TEST_THRESHOLD_CRS_ID_4P, &TEST_THRESHOLD_KEY_ID_4P, 4)]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn verify_proven_ct_sunshine_mocked_core(
    #[case] crs_id: &RequestId,
    #[case] key_id: &RequestId,
    #[case] amount_parties: usize,
) {
    verify_proven_ct_sunshine(crs_id, key_id, amount_parties, false).await
}

#[tokio::test]
#[rstest::rstest]
#[case(&TEST_THRESHOLD_KEY_ID_7P, 10)]
#[case(&TEST_THRESHOLD_KEY_ID_4P, 4)]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn keygen_sunshine_mocked_core(#[case] key_id: &RequestId, #[case] amount_parties: usize) {
    keygen_sunshine(key_id, amount_parties, false).await
}

#[tokio::test]
#[rstest::rstest]
#[case(&TEST_THRESHOLD_KEY_ID_7P, 10)]
#[case(&TEST_THRESHOLD_KEY_ID_4P, 4)]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn preproc_sunshine_mocked_core(#[case] key_id: &RequestId, #[case] amount_parties: usize) {
    preproc_sunshine(key_id, amount_parties, false).await
}

#[tokio::test]
#[rstest::rstest]
#[case(&TEST_THRESHOLD_KEY_ID_7P, 10)]
#[case(&TEST_THRESHOLD_KEY_ID_4P, 4)]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn crs_sunshine_mocked_core(#[case] key_id: &RequestId, #[case] amount_parties: usize) {
    crs_sunshine(key_id, amount_parties, false).await
}

#[cfg(feature = "slow_tests")]
#[tokio::test]
#[serial_test::serial]
#[tracing_test::traced_test]
#[integration_test]
async fn ddec_sunshine_slow() {
    ddec_sunshine(&TEST_THRESHOLD_KEY_ID_4P, 4, true).await
}

#[cfg(feature = "slow_tests")]
#[tokio::test]
#[serial_test::serial]
#[integration_test]
async fn reenc_sunshine_slow() {
    reenc_sunshine(&TEST_THRESHOLD_KEY_ID_4P, 4, true).await
}

#[cfg(feature = "slow_tests")]
#[tokio::test]
#[serial_test::serial]
#[integration_test]
async fn verify_proven_ct_sunshine_slow() {
    verify_proven_ct_sunshine(
        &TEST_THRESHOLD_CRS_ID_4P,
        &TEST_THRESHOLD_KEY_ID_4P,
        4,
        true,
    )
    .await
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[integration_test]
async fn preproc_sunshine_slow() {
    preproc_sunshine(&TEST_THRESHOLD_KEY_ID_4P, 4, true).await
}

#[cfg(feature = "slow_tests")]
#[tokio::test]
#[serial_test::serial]
#[integration_test]
async fn crs_sunshine_slow() {
    crs_sunshine(&TEST_THRESHOLD_KEY_ID_4P, 4, true).await
}
