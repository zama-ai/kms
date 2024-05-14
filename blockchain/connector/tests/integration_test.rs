use events::kms::{
    DecryptResponseValues, DecryptValues, FheType, KmsEvent, Transaction, TransactionId,
};
use events::subscription::handler::EventsMode;
use kms_blockchain_client::client::{Client, ClientBuilder};
use kms_blockchain_client::query_client::{QueryClient, QueryClientBuilder};
use kms_blockchain_connector::application::sync_handler::{KmsConnectorEventHandler, SyncHandler};
use kms_blockchain_connector::conf::telemetry::init_tracing;
use kms_blockchain_connector::conf::{
    BlockchainConfig, ConnectorConfig, ContractFee, SignKeyConfig, Tracing,
};
use kms_blockchain_connector::domain::blockchain::{
    BlockchainOperationVal, DecryptResponseVal, KmsOperationResponse,
};
use kms_blockchain_connector::domain::kms::KmsOperation;
use kms_blockchain_connector::infrastructure::blockchain::KmsBlockchain;
use kms_blockchain_connector::infrastructure::metrics::OpenTelemetryMetrics;
use kms_lib::rpc::rpc_types::CURRENT_FORMAT_VERSION;
use retrying::retry;
use serde_json::json;
use std::env::set_var;
use std::sync::Arc;
use std::time::Duration;
use test_context::{test_context, AsyncTestContext};
use test_utilities::context::DockerCompose;
use tokio::fs;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
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
impl KmsOperation for KmsMock {
    async fn run(&self, event: KmsEvent) -> anyhow::Result<KmsOperationResponse> {
        self.channel.send(event.clone()).await?;
        Ok(KmsOperationResponse::DecryptResponse(DecryptResponseVal {
            decrypt_response: DecryptResponseValues::builder()
                .signature(vec![1, 2, 3])
                .payload("Hello World".as_bytes().to_vec())
                .build(),
            operation_val: BlockchainOperationVal {
                tx_id: event.txn_id,
            },
        }))
    }
}

#[test_context(DockerComposeContext)]
#[tokio::test]
async fn test_blockchain_connector(_ctx: &mut DockerComposeContext) {
    option_env!("RUST_LOG")
        .map(|_| ())
        .unwrap_or_else(|| set_var("RUST_LOG", "error"));
    init_tracing(Some(Tracing::default())).unwrap();
    let mnemonic = Some("feel wife neither never floor volume express actor initial year throw hawk pink gaze deny prevent helmet clump hurt hour river behind employ ribbon".to_string());
    let addresses = vec!["http://localhost:9090"];

    // Initialize the query client for checking the blockchain state
    let query_client: QueryClient = QueryClientBuilder::builder()
        .grpc_addresses(addresses.clone())
        .build()
        .try_into()
        .unwrap();

    // Wait for the contract to be deployed
    sleep(Duration::from_secs(5)).await;
    // Get the contract address dynamically
    let contract_address = get_contract_address(&query_client).await.unwrap();

    // Send decryption request to the blockchain in order to get events after
    let txhash = send_decrypt_request(mnemonic.clone(), addresses.clone(), &contract_address).await;

    let query_client = Arc::new(query_client);
    wait_for_tx_processed(query_client.clone(), txhash.clone())
        .await
        .unwrap();

    let (tx, mut rc) = channel(1);
    // Start SyncHandler to listen events
    let handler = start_handler(addresses.clone(), &contract_address, mnemonic, tx).await;

    // Wait for the event to be processed and send the response back to the blockchain
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
    query_client
        .query_tx(txhash.clone())
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Transaction error {:?}", e))
}

/// Check the event status in the blockchain to verify if it was processed and
/// the decryption response was sent back to the blockchain
async fn check_event(
    event: KmsEvent,
    contract_address: String,
    query_client: Arc<QueryClient>,
    tx_sender: Sender<()>,
) {
    let json_msg = json!({
        "transactions": {
         "txn_id": event.txn_id,
        }
    });
    loop {
        let resp = query_client
            .query_contract(
                contract_address.to_string(),
                json_msg.to_string().as_bytes(),
            )
            .await
            .unwrap();
        let tx = serde_json::from_slice::<Transaction>(&resp).unwrap();
        let transaction_response = query_client
            .query_tx_by_block_and_index(tx.block_height, tx.transaction_index)
            .await;

        if let Ok(tx_resp) = transaction_response {
            if tx_resp.code == 0 {
                tx_sender.send(()).await.expect("Failed to send response");
                break;
            }
        }
    }
}

#[retry(stop=(attempts(4)|duration(20)),wait=fixed(5))]
async fn get_contract_address(client: &QueryClient) -> anyhow::Result<String> {
    let result = client.list_contracts().await.unwrap();
    if !result.contracts.is_empty() {
        Ok(result.contracts[0].clone())
    } else {
        Err(anyhow::anyhow!("Contract not found"))
    }
}

async fn start_handler(
    addresses: Vec<&str>,
    contract_address: &str,
    mnemonic: Option<String>,
    tx: Sender<KmsEvent>,
) -> SyncHandler<KmsBlockchain, KmsMock, OpenTelemetryMetrics> {
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
    };
    let metrics = OpenTelemetryMetrics::new();
    let blockchain = KmsBlockchain::new(blockchain_config.clone(), metrics.clone())
        .await
        .unwrap();
    let connector_config = ConnectorConfig {
        tick_interval_secs: 1,
        storage_path: "tests/data/events.toml".to_string(),
        mode: Some(EventsMode::Request),
        blockchain: blockchain_config,
        ..Default::default()
    };
    SyncHandler::builder()
        .kms_connector_handler(
            KmsConnectorEventHandler::builder()
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

async fn send_decrypt_request(
    mnemonic: Option<String>,
    addresses: Vec<&str>,
    contract_address: &str,
) -> String {
    // Send decryption request to the blockchain
    let mut client: Client = ClientBuilder::builder()
        .mnemonic_wallet(mnemonic.as_deref())
        .grpc_addresses(addresses)
        .contract_address(contract_address)
        .build()
        .try_into()
        .unwrap();

    let operation = events::kms::KmsOperationAttribute::Decrypt(
        DecryptValues::builder()
            .version(CURRENT_FORMAT_VERSION)
            .servers_needed(2)
            .key_id("kid".as_bytes().to_vec())
            .ciphertext(vec![1, 2, 3, 4, 5])
            .randomness(vec![6, 7, 8, 9, 0])
            .fhe_type(FheType::Euint8)
            .build(),
    );

    let request = KmsEvent::builder()
        .txn_id(<Vec<u8> as Into<TransactionId>>::into(vec![1]))
        .operation(operation)
        .build()
        .to_json()
        .unwrap()
        .to_string();

    let resp = client
        .execute_contract(request.as_bytes(), 200_000u64)
        .await
        .unwrap();

    resp.txhash
}
