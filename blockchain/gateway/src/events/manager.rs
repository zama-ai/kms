use crate::blockchain::blockchain_impl;
use crate::blockchain::handlers::handle_event_decryption;
use crate::blockchain::handlers::handle_reencryption_event;
use crate::blockchain::Blockchain;
use crate::common::provider::EventDecryptionFilter;
use crate::config::init_conf_with_trace_connector;
use crate::config::GatewayConfig;
use crate::events::manager::k256::ecdsa::SigningKey;
use crate::util::height::AtomicBlockHeight;
use actix_web::App;
use actix_web::HttpServer;
use actix_web::{post, web, HttpResponse};
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::U256;
use events::kms::KmsEvent;
use events::kms::ReencryptResponseValues;
use events::HexVector;
use kms_blockchain_connector::application::oracle_sync::OracleSyncHandler;
use kms_blockchain_connector::application::SyncHandler;
use kms_blockchain_connector::conf::ConnectorConfig;
use kms_blockchain_connector::domain::oracle::Oracle;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct DecryptionEvent {
    pub(crate) filter: EventDecryptionFilter,
    pub(crate) block_number: u64,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct ApiReencryptValues {
    pub(crate) signature: HexVector,
    pub(crate) user_address: HexVector,
    pub(crate) enc_key: HexVector,
    pub(crate) ciphertext_handle: HexVector,
    pub(crate) eip712_verifying_contract: String,
}

#[derive(Debug)]
pub struct ReencryptionEvent {
    pub(crate) values: ApiReencryptValues,
    pub(crate) sender: oneshot::Sender<Vec<ReencryptResponseValues>>,
}

// Define different event types
pub enum GatewayEvent {
    Decryption(DecryptionEvent),
    Reencryption(ReencryptionEvent),
    KmsEvent(KmsEvent),
}

// Define a trait for publishers
#[async_trait]
pub trait Publisher<E> {
    async fn run(&self) -> anyhow::Result<()>;
    fn publish(&self, event: E);
}

// Publisher for DecryptionEvent events
#[derive(Clone)]
pub struct DecryptionEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
    provider: Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
    atomic_height: Arc<AtomicBlockHeight>,
    config: GatewayConfig,
}

impl DecryptionEventPublisher {
    pub async fn new(
        sender: mpsc::Sender<GatewayEvent>,
        provider: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        atomic_height: &Arc<AtomicBlockHeight>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            sender,
            provider: Arc::clone(provider),
            atomic_height: Arc::clone(atomic_height),
            config,
        }
    }
}

#[async_trait]
impl Publisher<DecryptionEvent> for DecryptionEventPublisher {
    fn publish(&self, event: DecryptionEvent) {
        self.sender
            .try_send(GatewayEvent::Decryption(event))
            .unwrap();
    }

    async fn run(&self) -> anyhow::Result<()> {
        let mut last_block = self
            .provider
            .get_block(BlockNumber::Latest)
            .await
            .unwrap_or_else(|e| {
                error!("Failed to get latest block: {:?}", e);
                std::process::exit(1);
            })
            .unwrap()
            .number
            .unwrap();
        info!("last_block: {last_block}");

        debug!("last_block: {last_block}");
        let mut last_request_id = U256::zero();
        debug!("last_request_id: {last_request_id}");
        let mut stream = self.provider.subscribe_blocks().await.unwrap();
        while let Some(block) = stream.next().await {
            info!("🧱 block number: {}", block.number.unwrap());

            // process any EventDecryption logs
            let events = self
                .provider
                .get_logs(
                    &Filter::new()
                        .from_block(last_block)
                        .address(self.config.ethereum.oracle_predeploy_address)
                        .event("EventDecryption(uint256,uint256[],address,bytes4,uint256,uint256,bool)"),
                )
                .await
                .unwrap();

            for log in events {
                let block_number = log.block_number.unwrap().as_u64();
                debug!("Block: {:?}", block_number);
                let _ = self.atomic_height.try_update(block_number);
                let event_decryption: EventDecryptionFilter =
                    EthLogDecode::decode_log(&log.clone().into()).unwrap();
                if event_decryption.request_id > last_request_id {
                    last_request_id = event_decryption.request_id;
                    info!("⭐ event_decryption: {:?}", event_decryption.request_id);
                    debug!("EventDecryptionFilter: {:?}", event_decryption);

                    self.publish(DecryptionEvent {
                        filter: event_decryption.clone(),
                        block_number: log.block_number.unwrap().as_u64(),
                    });

                    info!(
                        "Handled event decryption: {:?}",
                        event_decryption.request_id
                    );
                }
            }

            last_block = block.number.unwrap();
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct KmsEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
}

#[async_trait]
impl Oracle for KmsEventPublisher {
    async fn respond(&self, event: KmsEvent) -> anyhow::Result<()> {
        debug!("🚀🚀🚀🚀🚀🚀 Oracle event: {:?}", event.txn_id());
        self.publish(event);
        Ok(())
    }
}

impl KmsEventPublisher {
    pub async fn new(sender: mpsc::Sender<GatewayEvent>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl Publisher<KmsEvent> for KmsEventPublisher {
    fn publish(&self, event: KmsEvent) {
        self.sender.try_send(GatewayEvent::KmsEvent(event)).unwrap();
    }

    async fn run(&self) -> anyhow::Result<()> {
        let config: ConnectorConfig = init_conf_with_trace_connector("config/default.toml")?;

        let _ = OracleSyncHandler::new_with_config_and_listener(config, self.clone())
            .await?
            .listen_for_events()
            .await;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ReencryptionEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
    config: GatewayConfig,
}

impl ReencryptionEventPublisher {
    pub async fn new(sender: mpsc::Sender<GatewayEvent>, config: GatewayConfig) -> Self {
        Self { sender, config }
    }
}

#[async_trait]
impl Publisher<ReencryptionEvent> for ReencryptionEventPublisher {
    fn publish(&self, event: ReencryptionEvent) {
        self.sender
            .try_send(GatewayEvent::Reencryption(event))
            .unwrap();
    }

    async fn run(&self) -> anyhow::Result<()> {
        let publisher = Arc::new(self.clone());
        let api_url = self.config.api_url.clone();
        let payload_limit = 10 * 1024 * 1024; // 10 MB
        let _handle = HttpServer::new(move || {
            App::new()
                .app_data(web::PayloadConfig::new(payload_limit))
                .app_data(web::Data::new(publisher.clone()))
                .service(reencrypt_payload)
        })
        .workers(20)
        .bind(api_url)
        .unwrap()
        .run()
        .await;

        Ok(())
    }
}

#[post("/reencrypt")]
async fn reencrypt_payload(
    payload: web::Json<ApiReencryptValues>,
    publisher: web::Data<Arc<ReencryptionEventPublisher>>,
) -> HttpResponse {
    info!("🍓🍓🍓 => Received reencryption request");

    let (sender, receiver) = oneshot::channel();

    publisher.publish(ReencryptionEvent {
        values: payload.into_inner(),
        sender,
    });
    info!("🍓🍓🍓 Published reencryption request");

    match receiver.await {
        Ok(reencryption_response) => {
            info!("🍓🍓🍓 <= Received reencryption response");
            HttpResponse::Ok()
                .json(json!({ "status": "success", "response": reencryption_response }))
        }
        Err(_) => HttpResponse::InternalServerError().json(json!({ "status": "failure" })),
    }
}

// Subscriber
pub struct GatewaySubscriber {
    config: GatewayConfig,
    receiver: Arc<Mutex<mpsc::Receiver<GatewayEvent>>>,
    kms: Arc<dyn Blockchain>,
}

impl GatewaySubscriber {
    pub async fn new(
        receiver: Arc<Mutex<mpsc::Receiver<GatewayEvent>>>,
        config: GatewayConfig,
    ) -> Self {
        let blockchain_instance = blockchain_impl(&config).await;
        Self {
            receiver,
            config,
            kms: blockchain_instance,
        }
    }

    pub fn listen(&self) {
        let receiver = Arc::clone(&self.receiver);
        let config = self.config.clone();
        let kms = Arc::clone(&self.kms);
        tokio::spawn(async move {
            loop {
                let event = receiver.lock().await.recv().await.unwrap();
                let config = config.clone();
                let kms = Arc::clone(&kms);

                tokio::task::spawn(async move {
                    let start = std::time::Instant::now();
                    match event {
                        GatewayEvent::Decryption(msg_event) => {
                            debug!("🫐🫐🫐 Received Decryption Event");
                            if let Err(e) =
                                handle_event_decryption(&Arc::new(msg_event.clone()), &config).await
                            {
                                error!("Error handling event decryption: {:?}", e);
                            }
                            debug!("Received Message: {:?}", msg_event);
                        }
                        GatewayEvent::Reencryption(reencrypt_event) => {
                            debug!("🫐🫐🫐 Received Reencryption Event");
                            let reencrypt_response =
                                handle_reencryption_event(&reencrypt_event.values, &config)
                                    .await
                                    .unwrap();
                            let _ = reencrypt_event.sender.send(reencrypt_response);
                        }
                        GatewayEvent::KmsEvent(kms_event) => {
                            debug!("🫐🫐🫐 Received KmsEvent: {:?}", kms_event);
                            kms.receive(kms_event).await.unwrap();
                        }
                    }
                    let duration = start.elapsed();
                    info!("⏱️ E2E Event Time elapsed: {:?}", duration);
                });
            }
        });
    }
}

// write a test for serialization and deserialization of the ApiReencryptValues struct
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        let values = ApiReencryptValues {
            signature: HexVector::from(vec![1, 2, 3]),
            user_address: HexVector::from(vec![4, 5, 6]),
            enc_key: HexVector::from(vec![7, 8, 9]),
            ciphertext_handle: HexVector::from(vec![10, 11, 12]),
            eip712_verifying_contract: "0x1234567890abcdef".to_string(),
        };

        let serialized = serde_json::to_string_pretty(&values).unwrap();
        // make the output more readable
        println!("serialized = {}", serialized);
        let deserialized: ApiReencryptValues = serde_json::from_str(&serialized).unwrap();

        assert_eq!(values, deserialized);
    }
}
