use crate::config::GatewayConfig;
use crate::config::KmsMode;
use crate::util::conversion::TokenizableFrom;
use crate::util::conversion::U4;
use anyhow::anyhow;
use async_trait::async_trait;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::DecryptValues;
use events::kms::KmsEvent;
use events::kms::KmsOperation;
use events::kms::OperationValue;
use events::kms::TransactionId;
use events::kms::{FheType, KmsMessage};
use events::HexVector;
use kms_blockchain_client::client::Client;
use kms_blockchain_client::client::ClientBuilder;
use kms_blockchain_client::client::ExecuteContractRequest;
use kms_blockchain_client::query_client::ContractQuery;
use kms_blockchain_client::query_client::OperationQuery;
use kms_blockchain_client::query_client::QueryClient;
use kms_blockchain_client::query_client::QueryClientBuilder;
use kms_blockchain_client::query_client::QueryContractRequest;
use kms_blockchain_connector::application::oracle_sync::OracleSyncHandler;
use kms_blockchain_connector::application::SyncHandler;
use kms_blockchain_connector::conf::ConnectorConfig;
use kms_blockchain_connector::conf::Settings;
use kms_blockchain_connector::domain::oracle::Oracle;
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::rpc::rpc_types::CURRENT_FORMAT_VERSION;
use std::collections::HashMap;
use std::sync::Arc;
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::OnceCell;
use tokio::sync::RwLock;
use tracing::info;

async fn setup_decryption_strategy(
    config: &GatewayConfig,
) -> anyhow::Result<Arc<dyn DecryptionStrategy>> {
    let debug = config.debug;
    let strategy: Arc<dyn DecryptionStrategy> = match debug {
        true => {
            tracing::info!("🐛 Running in debug mode with a mocked KMS backend 🐛");
            Arc::new(Mockchain)
        }
        false => Arc::new(KmsBlockchain::default(config.clone())),
    };

    Ok(strategy)
}

static DECRYPTION_STRATEGY: Lazy<OnceCell<Arc<dyn DecryptionStrategy>>> = Lazy::new(OnceCell::new);

pub(super) async fn get_decryption_strategy(config: &GatewayConfig) -> Arc<dyn DecryptionStrategy> {
    DECRYPTION_STRATEGY
        .get_or_init(|| async {
            setup_decryption_strategy(config)
                .await
                .expect("Failed to set up decryption strategy")
        })
        .await
        .clone()
}

#[async_trait]
pub(crate) trait DecryptionStrategy: Send + Sync {
    async fn decrypt(&self, ctxt: Bytes, fhe_type: FheType) -> anyhow::Result<Token>;
}

struct Mockchain;

#[async_trait]
impl DecryptionStrategy for Mockchain {
    async fn decrypt(&self, _ctxt: Bytes, fhe_type: FheType) -> anyhow::Result<Token> {
        let res = match fhe_type {
            FheType::Ebool => true.to_token(),
            FheType::Euint4 => U4::new(3_u8).unwrap().to_token(),
            FheType::Euint8 => 33_u8.to_token(),
            FheType::Euint16 => 33_u16.to_token(),
            FheType::Euint32 => 33_u32.to_token(),
            FheType::Euint64 => 33_u64.to_token(),
            FheType::Euint128 => 33_u128.to_token(),
            FheType::Euint160 => Address::zero().to_token(),
            FheType::Unknown => anyhow::bail!("Invalid ciphertext type"),
        };
        info!("🍊 plaintext: {:#?}", res);
        Ok(res)
    }
}

#[derive(Clone)]
struct KmsBlockchain {
    client: Arc<RwLock<Client>>,
    query_client: Arc<QueryClient>,
    responders: Arc<RwLock<HashMap<TransactionId, oneshot::Sender<KmsEvent>>>>,
    event_sender: mpsc::Sender<KmsEvent>,
    config: GatewayConfig,
}

impl KmsBlockchain {
    pub fn default(config: GatewayConfig) -> Self {
        let mnemonic = Some(config.kms.mnemonic.to_string());
        let binding = config.kms.address.to_string();
        let addresses = vec![binding.as_str()];
        let contract_address = &config.kms.contract_address;
        Self::new(
            mnemonic,
            addresses,
            contract_address.to_string().as_str(),
            config,
        )
    }
}

#[async_trait]
impl DecryptionStrategy for KmsBlockchain {
    async fn decrypt(&self, ctxt: Bytes, fhe_type: FheType) -> anyhow::Result<Token> {
        tracing::info!(
            "🔒 Decrypting ciphertext: {:?}",
            hex::encode(ctxt.to_vec().clone())
        );
        let ptxt = self.decrypt_request(ctxt.to_vec(), fhe_type).await?;
        tracing::debug!("decrypted ptxt: {:?}", ptxt);

        let res = match fhe_type {
            FheType::Ebool => ptxt.as_bool().to_token(),
            FheType::Euint4 => ptxt.as_u4().to_token(),
            FheType::Euint8 => ptxt.as_u8().to_token(),
            FheType::Euint16 => ptxt.as_u16().to_token(),
            FheType::Euint32 => ptxt.as_u32().to_token(),
            FheType::Euint64 => ptxt.as_u64().to_token(),
            FheType::Euint128 => ptxt.as_u128().to_token(),
            FheType::Euint160 => {
                let mut cake = vec![0u8; 20];
                ptxt.as_u160().copy_to_be_byte_slice(cake.as_mut_slice());
                Address::from_slice(&cake).to_token()
            }
            FheType::Unknown => anyhow::bail!("Invalid ciphertext type"),
        };

        info!("🍊 plaintext: {:#?}", res);
        Ok(res)
    }
}

impl<'a> KmsBlockchain {
    fn new(
        mnemonic: Option<String>,
        addresses: Vec<&'a str>,
        contract_address: &'a str,
        config: GatewayConfig,
    ) -> Self {
        let (event_sender, mut event_receiver): (mpsc::Sender<KmsEvent>, mpsc::Receiver<KmsEvent>) =
            mpsc::channel(100);
        let responders = Arc::new(RwLock::new(HashMap::<
            TransactionId,
            oneshot::Sender<KmsEvent>,
        >::new()));
        let responders_clone = responders.clone();

        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if let Some(tx) = responders_clone.write().await.remove(event.txn_id()) {
                    let _ = tx.send(event);
                }
            }
        });

        let kms_blockchain = KmsBlockchain {
            client: Arc::new(RwLock::new(
                ClientBuilder::builder()
                    .mnemonic_wallet(mnemonic.as_deref())
                    .grpc_addresses(addresses.clone())
                    .contract_address(contract_address)
                    .build()
                    .try_into()
                    .unwrap(),
            )),
            query_client: Arc::new(
                QueryClientBuilder::builder()
                    .grpc_addresses(addresses.clone())
                    .build()
                    .try_into()
                    .unwrap(),
            ),
            responders,
            event_sender,
            config,
        };

        // Initialize the listener
        tokio::spawn(Self::listen(kms_blockchain.clone()));
        kms_blockchain
    }

    pub async fn listen<T>(oracle: T) -> anyhow::Result<()>
    where
        T: Oracle + Send + Sync + Clone + 'static,
    {
        let settings = Settings::builder()
            .path(Some("config/default.toml"))
            .build();
        let config: ConnectorConfig = settings
            .init_conf()
            .map_err(|e| anyhow::anyhow!("Error on initializing config {:?}", e))?;

        OracleSyncHandler::new_with_config_and_listener(config, oracle)
            .await?
            .listen_for_events()
            .await
    }

    async fn decrypt_request(&self, ctxt: Vec<u8>, fhe_type: FheType) -> anyhow::Result<Plaintext> {
        let operation = events::kms::OperationValue::Decrypt(
            DecryptValues::builder()
                .version(CURRENT_FORMAT_VERSION)
                .key_id(hex::decode(self.config.kms.key_id.as_str()).unwrap())
                .ciphertext(ctxt)
                .randomness(vec![6, 7, 8, 9, 0])
                .fhe_type(fhe_type)
                .build(),
        );

        // TODO: Proof should be generated by the client
        let proof = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let request = ExecuteContractRequest::builder()
            .message(KmsMessage::builder().value(operation).proof(proof).build())
            .gas_limit(10_000_000u64)
            .build();

        let response = self.client.write().await.execute_contract(request).await?;

        let resp;
        loop {
            let query_response = self.query_client.query_tx(response.txhash.clone()).await?;
            if let Some(qr) = query_response {
                resp = qr;
                break;
            } else {
                tracing::warn!("Waiting for transaction to be included in a block");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        }
        let evs: Vec<KmsEvent> = resp
            .events
            .iter()
            .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
            .map(to_event)
            .map(<cosmwasm_std::Event as TryInto<KmsEvent>>::try_into)
            .collect::<Result<Vec<KmsEvent>, _>>()?;

        let ev = evs[0].clone();

        tracing::info!(
            "✉️ TxId: {:?} - Proof: {:?}",
            ev.txn_id().to_hex(),
            ev.proof().to_hex()
        );

        println!("🍊🍊🍊🍊🍊🍊 event: {:?}", ev.txn_id().to_hex());
        let event = self.wait_for_callback(ev.txn_id()).await?;
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.contract_address.to_string())
            .query(ContractQuery::GetOperationsValue(
                OperationQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;
        let payload_response = match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::DecryptResponse(decrypt_response) => {
                    let payload: DecryptionResponsePayload = serde_asn1_der::from_bytes(
                        <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload()).as_slice(),
                    )
                    .unwrap();

                    tracing::info!(
                        "🍇🥐🍇🥐🍇🥐 Centralized Gateway results payload: {:?}",
                        hex::encode(payload.plaintext)
                    );

                    Plaintext::from_u8(7_u8)
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                // loop through the vector of results and print them
                for value in results.iter() {
                    match value {
                        OperationValue::DecryptResponse(decrypt_response) => {
                            let payload: DecryptionResponsePayload = serde_asn1_der::from_bytes(
                                <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload())
                                    .as_slice(),
                            )
                            .unwrap();
                            tracing::info!(
                                "🥐🥐🥐🥐🥐🥐 Threshold Gateway results payload: {:?}",
                                hex::encode(payload.plaintext)
                            );
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ))
                        }
                    };
                }
                Plaintext::from_u8(21_u8)
            }
        };

        // let payload_response = Plaintext::from_u8(47_u8);
        Ok(payload_response)
    }

    async fn wait_for_callback(&self, txn_id: &TransactionId) -> anyhow::Result<KmsEvent> {
        let (tx, rx) = oneshot::channel();
        self.responders.write().await.insert(txn_id.clone(), tx);

        match tokio::time::timeout(tokio::time::Duration::from_secs(100), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(anyhow!("Failed to receive response")),
            Err(_) => Err(anyhow!("Request timed out")),
        }
    }

    async fn receive_response(&self, event: KmsEvent) -> anyhow::Result<()> {
        self.event_sender
            .send(event)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }
}

#[async_trait]
impl Oracle for KmsBlockchain {
    async fn respond(&self, event: KmsEvent) -> anyhow::Result<()> {
        info!("🚀🚀🚀🚀🚀🚀 Oracle event: {:?}", event.txn_id());
        self.receive_response(event).await
    }
}

fn to_event(event: &cosmos_proto::messages::tendermint::abci::Event) -> cosmwasm_std::Event {
    let mut result = cosmwasm_std::Event::new(event.r#type.clone());
    for attribute in event.attributes.iter() {
        let key = attribute.key.clone();
        let value = attribute.value.clone();
        result = result.add_attribute(key, value);
    }
    result
}
