use conf_trace::conf::Tracing;
use conf_trace::telemetry::init_tracing;
use events::kms::{
    CrsGenValues, FheParameter, KeyGenPreprocValues, KmsCoreConf, KmsCoreParty,
    KmsCoreThresholdConf, KmsEvent, TransactionId, ZkpValues,
};
use events::kms::{DecryptResponseValues, DecryptValues, FheType, KmsMessage, Transaction};
use events::kms::{KmsOperation, OperationValue};
use events::{
    kms::{KeyGenValues, ReencryptValues},
    HexVector,
};
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest, ProtoCoin};
use kms_blockchain_client::query_client::{
    ContractQuery, QueryClient, QueryClientBuilder, QueryContractRequest, TransactionQuery,
};
use kms_blockchain_connector::application::kms_core_sync::{
    KmsCoreEventHandler, KmsCoreSyncHandler,
};
use kms_blockchain_connector::application::SyncHandler;
use kms_blockchain_connector::conf::{
    BlockchainConfig, ConnectorConfig, ContractFee, CoreConfig, SignKeyConfig, TimeoutConfig,
};
use kms_blockchain_connector::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse,
};
use kms_blockchain_connector::domain::kms::Kms;
use kms_blockchain_connector::domain::storage::Storage;
use kms_blockchain_connector::infrastructure::blockchain::KmsBlockchain;
use kms_blockchain_connector::infrastructure::core::{KmsCore, KmsEventHandler};
use kms_blockchain_connector::infrastructure::metrics::OpenTelemetryMetrics;
use kms_lib::client::assemble_metadata_alloy;
use kms_lib::consts::TEST_PARAM;
use kms_lib::consts::{SAFE_SER_SIZE_LIMIT, TEST_CRS_ID};
use kms_lib::kms::{ZkVerifyResponse, ZkVerifyResponsePayload};
use kms_lib::util::key_setup::test_tools::compute_zkp_from_stored_key;
use kms_lib::util::key_setup::{ensure_central_crs_exists, ensure_threshold_crs_exists};
use kms_lib::{
    client::{test_tools, ParsedReencryptionRequest},
    consts::{
        AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT, DEFAULT_URL, OTHER_CENTRAL_TEST_ID,
        SIGNING_KEY_ID, TEST_CENTRAL_KEY_ID, TEST_THRESHOLD_KEY_ID, THRESHOLD,
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
        test_tools::{compute_cipher_from_stored_key, purge},
    },
};
use rand::RngCore;
use retrying::retry;
use std::collections::HashMap;
use std::env::set_var;
use std::sync::Arc;
use std::time::Duration;
use test_context::{test_context, AsyncTestContext};
use test_utilities::context::DockerCompose;
use tokio::fs;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinSet;
use tokio::time::sleep;

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
        _config: Option<KmsCoreConf>,
    ) -> anyhow::Result<KmsOperationResponse> {
        self.channel.send(event.clone()).await?;
        Ok(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
            decrypt_response: DecryptResponseValues::new(
                vec![1, 2, 3],
                "Hello World".as_bytes().to_vec(),
            ),
            operation_val: BlockchainOperationVal {
                tx_id: event.txn_id().clone(),
            },
        }))
    }
}

const BOOTSTRAP_TIME_TO_SLEEP: u64 = 60; // Wait a minute for everything to setup properly

#[test_context(DockerComposeContext)]
#[tokio::test]
async fn test_blockchain_connector(_ctx: &mut DockerComposeContext) {
    option_env!("RUST_LOG")
        .map(|_| ())
        .unwrap_or_else(|| set_var("RUST_LOG", "error"));
    // Ignore in case the tracing has already been initialized
    let _ = init_tracing(Tracing::builder().service_name("connector_test").build());

    let mnemonic = Some("whisper stereo great helmet during hollow nominee skate frown daughter donor pool ozone few find risk cigar practice essay sketch rhythm novel dumb host".to_string());
    let addresses = vec!["http://localhost:9090"];

    // Initialize the query client for checking the blockchain state
    let query_client: QueryClient = QueryClientBuilder::builder()
        .grpc_addresses(addresses.clone())
        .build()
        .try_into()
        .unwrap();

    // Wait for the contract to be deployed
    sleep(Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    // Get the contract address dynamically
    let contract_address = get_contract_address(&query_client).await.unwrap();

    let client: RwLock<Client> = RwLock::new(
        ClientBuilder::builder()
            .mnemonic_wallet(mnemonic.as_deref())
            .grpc_addresses(addresses.clone())
            .contract_address(&contract_address)
            .kv_store_address(None)
            .build()
            .try_into()
            .unwrap(),
    );

    // Send decryption request to the blockchain in order to get events after
    let txhash = send_decrypt_request(&client).await;

    let query_client = Arc::new(query_client);
    wait_for_tx_processed(query_client.clone(), txhash.clone())
        .await
        .unwrap();

    let (tx, mut rc) = channel(1);
    // Start SyncHandler to listen events
    let handler = start_sync_handler(addresses.clone(), &contract_address, mnemonic, tx).await;

    // Wait for the event to be processed and send the response back to the blockchain
    wait_for_event_response(handler, &contract_address, query_client, &mut rc).await;
}

async fn wait_for_event_response<T>(
    handler: T,
    contract_address: &str,
    query_client: Arc<QueryClient>,
    rc: &mut Receiver<KmsEvent>,
) where
    T: SyncHandler + Send + Sync + 'static,
{
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let (timeout_tx, timeout_rx) = oneshot::channel();
    let timeout_task = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        timeout_tx.send(()).unwrap();
    };
    let (tx_response, mut rc_response) = channel(1);
    tokio::spawn(handler.listen_for_events());
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
                        tokio::spawn(check_event(event.unwrap(), contract_address.to_string(), query_client.clone(), tx_response.clone()));
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

#[retry(stop=(attempts(4)|duration(20)),wait=fixed(5))]
async fn wait_for_tx_processed(
    query_client: Arc<QueryClient>,
    txhash: String,
) -> anyhow::Result<()> {
    let r = query_client
        .query_tx(txhash.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Transaction error {:?}", e))?;
    if r.is_none() {
        Err(anyhow::anyhow!("Transaction not found"))
    } else {
        Ok(())
    }
}

/// Check the event status in the blockchain to verify if it was processed and
/// the decryption response was sent back to the blockchain
async fn check_event(
    event: KmsEvent,
    contract_address: String,
    query_client: Arc<QueryClient>,
    tx_sender: Sender<()>,
) {
    let request = QueryContractRequest::builder()
        .contract_address(contract_address)
        .query(ContractQuery::GetTransaction(
            TransactionQuery::builder()
                .txn_id(event.txn_id().clone())
                .build(),
        ))
        .build();
    loop {
        let tx: Transaction = query_client.query_contract(request.clone()).await.unwrap();
        if tx.operations().iter().any(|x| {
            <OperationValue as Into<KmsOperation>>::into(x.clone()) == KmsOperation::DecryptResponse
        }) {
            tx_sender.send(()).await.expect("Failed to send response");
            break;
        }
    }
}

#[retry(stop=(attempts(4)|duration(20)),wait=fixed(5))]
async fn get_contract_address(client: &QueryClient) -> anyhow::Result<String> {
    tracing::info!("Getting contract address....");
    let result = client.list_contracts().await.unwrap();
    if !result.contracts.is_empty() {
        Ok(result.contracts[0].clone())
    } else {
        Err(anyhow::anyhow!("Contract not found"))
    }
}

async fn start_sync_handler(
    addresses: Vec<&str>,
    contract_address: &str,
    mnemonic: Option<String>,
    tx: Sender<KmsEvent>,
) -> KmsCoreSyncHandler<KmsBlockchain, KmsMock, OpenTelemetryMetrics> {
    let blockchain_config = BlockchainConfig {
        addresses: addresses
            .clone()
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
        contract: contract_address.to_string(),
        fee: ContractFee {
            amount: 200_000u64,
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
        storage_path: "tests/data/events.toml".to_string(),
        blockchain: blockchain_config,
        ..Default::default()
    };
    KmsCoreSyncHandler::builder()
        .kms_connector_handler(
            KmsCoreEventHandler::builder()
                .blockchain(blockchain)
                .kms(KmsMock {
                    channel: Arc::new(tx),
                })
                .observability(metrics)
                .build(),
        )
        .config(connector_config)
        .build()
}

async fn send_decrypt_request(client: &RwLock<Client>) -> String {
    let decrypt = DecryptValues::new(
        vec![1, 2, 3],
        vec![[0, 0, 0, 0, 0, 1, 1, 1, 1, 1].to_vec()],
        vec![FheType::Euint8],
        Some(vec![[1, 0, 0, 0, 0, 1, 1, 1, 1, 1].to_vec()]),
        CURRENT_FORMAT_VERSION,
        "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
        "eip712name".to_string(),
        "1".to_string(),
        vec![101; 32],
        "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
        vec![],
    );

    let operation = events::kms::OperationValue::Decrypt(decrypt);

    let request = ExecuteContractRequest::builder()
        .message(KmsMessage::builder().value(operation).build())
        .gas_limit(200000u64)
        .funds(vec![ProtoCoin::builder()
            .denom("ucosm".to_string())
            .amount(100_000u64)
            .build()])
        .build();

    let resp = client.write().await.execute_contract(request).await;

    tracing::info!("Transaction: {:?}", resp);

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

async fn setup_threshold_keys() {
    let mut threshold_pub_storages = Vec::with_capacity(AMOUNT_PARTIES);
    for i in 1..=AMOUNT_PARTIES {
        threshold_pub_storages.push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
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
        TEST_PARAM,
        &TEST_THRESHOLD_KEY_ID,
        true,
    )
    .await;
    ensure_threshold_crs_exists(
        &mut threshold_pub_storages,
        &mut threshold_priv_storages,
        TEST_PARAM,
        &TEST_CRS_ID,
        true,
    )
    .await;
}

async fn setup_central_keys() {
    let mut central_pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
    let mut central_priv_storage = FileStorage::new_centralized(None, StorageType::PRIV).unwrap();

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
        &TEST_CENTRAL_KEY_ID,
        &OTHER_CENTRAL_TEST_ID,
        true,
        false,
    )
    .await;
    ensure_central_crs_exists(
        &mut central_pub_storage,
        &mut central_priv_storage,
        TEST_PARAM,
        &TEST_CRS_ID,
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

    let client = KmsCore::new(config.clone(), mock_storage, OpenTelemetryMetrics::new()).unwrap();

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
        compute_cipher_from_stored_key(None, msg1.into(), &TEST_CENTRAL_KEY_ID.to_string()).await;
    let (ct2, fhe_type2): (Vec<u8>, kms_lib::kms::FheType) =
        compute_cipher_from_stored_key(None, msg2.into(), &TEST_CENTRAL_KEY_ID.to_string()).await;
    let op = OperationValue::Decrypt(DecryptValues::new(
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
        CURRENT_FORMAT_VERSION,
        "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
        "eip712name".to_string(),
        "1".to_string(),
        vec![101; 32],
        "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
        vec![],
    ));
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

    let op = OperationValue::KeyGen(KeyGenValues::new(
        HexVector::from_hex("1111111111111111111111111111111111112222").unwrap(),
    ));
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
        clients
            .push(KmsCore::new(config.clone(), mock_storage, OpenTelemetryMetrics::new()).unwrap());
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
        compute_cipher_from_stored_key(None, msg1.into(), &TEST_THRESHOLD_KEY_ID.to_string()).await;
    let (ct2, fhe_type2): (Vec<u8>, kms_lib::kms::FheType) =
        compute_cipher_from_stored_key(None, msg2.into(), &TEST_THRESHOLD_KEY_ID.to_string()).await;
    let op = OperationValue::Decrypt(DecryptValues::new(
        HexVector::from_hex(&TEST_THRESHOLD_KEY_ID.request_id).unwrap(),
        vec![MOCK_CT_HANDLES[0].to_vec(), MOCK_CT_HANDLES[1].to_vec()],
        vec![
            events::kms::FheType::from(fhe_type1 as u8),
            events::kms::FheType::from(fhe_type2 as u8),
        ],
        Some(vec![
            MOCK_EXTERNAL_HANDLES[0].to_vec(),
            MOCK_EXTERNAL_HANDLES[1].to_vec(),
        ]),
        CURRENT_FORMAT_VERSION,
        "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
        "eip712name".to_string(),
        "1".to_string(),
        vec![101; 32],
        "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
        vec![],
    ));
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![ct1, ct2], op).await;
    assert_eq!(results.len(), AMOUNT_PARTIES);

    for result in results {
        match result {
            KmsOperationResponse::DecryptResponse(resp) => {
                let payload: DecryptionResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(resp.decrypt_response.payload()).as_slice(),
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

/// an Eip-712 domain for testing
fn dummy_domain() -> alloy_sol_types::Eip712Domain {
    alloy_sol_types::eip712_domain!(
        name: "dummy",
        version: "1",
        chain_id: 1,
        verifying_contract: alloy_primitives::Address::ZERO,
    )
}

async fn reenc_sunshine(slow: bool) {
    setup_threshold_keys().await;
    let msg = 111u8;
    let (ct, fhe_type): (Vec<u8>, kms_lib::kms::FheType) =
        compute_cipher_from_stored_key(None, msg.into(), &TEST_THRESHOLD_KEY_ID.to_string()).await;

    let mut pub_storage = Vec::with_capacity(AMOUNT_PARTIES);
    for i in 1..=AMOUNT_PARTIES {
        pub_storage.push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
    }
    let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
    let mut kms_client =
        kms_lib::client::Client::new_client(client_storage, pub_storage, &TEST_PARAM)
            .await
            .unwrap();

    let request_id = RequestId {
        request_id: "1111000000000000000000000000000000001111".to_string(),
    };
    let key_id = &TEST_THRESHOLD_KEY_ID;
    let (kms_req, enc_pk, enc_sk) = kms_client
        .reencryption_request(ct.clone(), &dummy_domain(), fhe_type, &request_id, key_id)
        .unwrap();
    let payload = kms_req.payload.clone().unwrap();
    let eip712 = kms_req.domain.clone().unwrap();
    let op = OperationValue::Reencrypt(ReencryptValues::new(
        kms_req.signature.clone(),
        payload.version,
        payload.client_address,
        payload.enc_key,
        events::kms::FheType::from(fhe_type as u8),
        HexVector::from_hex(payload.key_id.unwrap().request_id.as_str()).unwrap(),
        MOCK_CT_HANDLES[0].to_vec(),
        payload.ciphertext_digest,
        "dummy_acl_address".to_string(),
        eip712.name,
        eip712.version,
        eip712.chain_id,
        eip712.verifying_contract,
        eip712.salt,
    ));
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

async fn zkp_sunshine(slow: bool) {
    setup_threshold_keys().await;

    println!("test CRS {:?}", TEST_CRS_ID.to_string());
    let msg = vec![42u32.into(), 111u8.into()];

    let mut pub_storage = Vec::with_capacity(AMOUNT_PARTIES);
    for i in 1..=AMOUNT_PARTIES {
        pub_storage.push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
    }
    let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
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

    let ct_proof = compute_zkp_from_stored_key(
        None,
        msg,
        &TEST_THRESHOLD_KEY_ID.to_string(),
        &TEST_CRS_ID.to_string(),
        &metadata,
    )
    .await;

    let key_id = &TEST_THRESHOLD_KEY_ID;
    let crs_id = &TEST_CRS_ID;
    let kms_req = kms_client
        .zk_verify_request(
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

    let op = OperationValue::Zkp(ZkpValues::new(
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
    ));
    let mut ct_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(&ct_proof, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();
    let (results, txn_id, _) = generic_sunshine_test(slow, vec![ct_buf], op).await;
    assert_eq!(results.len(), AMOUNT_PARTIES);

    if slow {
        // process the result using the kms client when we're running in the slow mode
        // i.e., it is an integration test
        let agg_resp: Vec<ZkVerifyResponse> = results
            .into_iter()
            .map(|r| {
                let r = match r {
                    KmsOperationResponse::ZkpResponse(resp) => resp,
                    _ => panic!("invalid response"),
                }
                .zkp_response;

                let payload: ZkVerifyResponsePayload = bincode::deserialize(
                    <&HexVector as Into<Vec<u8>>>::into(r.payload()).as_slice(),
                )
                .unwrap();
                ZkVerifyResponse {
                    signature: r.signature().to_vec(),
                    payload: Some(payload),
                }
            })
            .collect();
        // Try to check that enough signatures agree
        let _ = kms_client
            .process_zk_verify_resp(&agg_resp, AMOUNT_PARTIES as u32)
            .unwrap();
    } else {
        // otherwise just check that we're getting dummy values back
        for result in results {
            match result {
                KmsOperationResponse::ZkpResponse(resp) => {
                    let resp_value = &resp.zkp_response;
                    assert_eq!(resp.operation_val.tx_id, txn_id);
                    let payload: ZkVerifyResponsePayload =
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

async fn keygen_sunshine(slow: bool) {
    setup_threshold_keys().await;
    if slow {
        panic!("slow/integration test is not supported since there's no preprocessing material")
    }

    let op = OperationValue::KeyGen(KeyGenValues::new(
        HexVector::from_hex("1111111111111111111111111111111111112222").unwrap(),
    ));
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
async fn zkp_sunshine_mocked_core() {
    zkp_sunshine(false).await
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
#[tokio::test]
#[serial_test::serial]
async fn zkp_sunshine_slow() {
    zkp_sunshine(true).await
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
