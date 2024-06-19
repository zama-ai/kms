use crate::blockchain::blockchain_impl;
use crate::blockchain::decrypt::handler::handle_event_decryption;
use crate::blockchain::Blockchain;
use crate::common::provider::EventDecryptionFilter;
use crate::config::GatewayConfig;
use crate::config::Settings;
use crate::events::manager::k256::ecdsa::SigningKey;
use crate::util::height::AtomicBlockHeight;
use actix_web::rt::System;
use actix_web::App;
use actix_web::HttpServer;
use actix_web::{post, web, HttpResponse};
use anyhow::Ok;
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::U256;
use events::kms::KmsEvent;
use events::kms::ReencryptValues;
use kms_blockchain_connector::application::oracle_sync::OracleSyncHandler;
use kms_blockchain_connector::application::SyncHandler;
use kms_blockchain_connector::conf::ConnectorConfig;
use kms_blockchain_connector::domain::oracle::Oracle;
use serde_json::json;
use std::sync::Arc;
use std::thread;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct DecryptionEvent {
    pub(crate) filter: EventDecryptionFilter,
    pub(crate) block_number: u64,
}
#[derive(Debug, Clone)]
pub struct ReencryptionEvent {
    pub(crate) values: ReencryptValues,
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

    async fn event_loop(&self) -> anyhow::Result<()> {
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
            let events = self.provider
            .get_logs(
                &Filter::new()
                    .from_block(last_block)
                    .address(self.config.ethereum.oracle_predeploy_address)
                    .event("EventDecryption(uint256,(uint256,uint8)[],address,bytes4,uint256,uint256)"),
            )
            .await.unwrap();

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

                    tracing::info!(
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

#[async_trait]
impl Publisher<DecryptionEvent> for DecryptionEventPublisher {
    fn publish(&self, event: DecryptionEvent) {
        self.sender
            .try_send(GatewayEvent::Decryption(event))
            .unwrap();
    }

    async fn run(&self) -> anyhow::Result<()> {
        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.event_loop().await.unwrap_or_else(|e| {
                error!("Error in DecryptionEventPublisher: {:?}", e);
                std::process::exit(1);
            });
        });
        handle.await.unwrap();
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
        info!("🚀🚀🚀🚀🚀🚀 Oracle event: {:?}", event.txn_id());
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
        let cloned = self.clone();
        tokio::spawn(async move {
            let settings = Settings::builder()
                .path(Some("config/default.toml"))
                .build();
            let config: ConnectorConfig = settings
                .init_conf()
                .map_err(|e| anyhow::anyhow!("Error on initializing config {:?}", e))?;

            OracleSyncHandler::new_with_config_and_listener(config, cloned)
                .await?
                .listen_for_events()
                .await
        });
        Ok(())
    }
}

#[derive(Clone)]
pub struct ReencryptionEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
}

impl ReencryptionEventPublisher {
    pub async fn new(sender: mpsc::Sender<GatewayEvent>) -> Self {
        Self { sender }
    }
}

#[post("/reencrypt")]
async fn reencrypt_payload(
    payload: web::Json<ReencryptValues>,
    publisher: web::Data<Arc<ReencryptionEventPublisher>>,
) -> HttpResponse {
    publisher.publish(ReencryptionEvent {
        values: payload.into_inner(),
    });

    HttpResponse::Ok().json(json!({"status": "success"}))
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
        // Spawn the Actix-web server in a new thread
        thread::spawn(move || {
            let sys = System::new();
            sys.block_on(async {
                HttpServer::new(move || {
                    App::new()
                        .app_data(web::Data::new(publisher.clone()))
                        .service(reencrypt_payload)
                })
                .bind("127.0.0.1:8888")?
                .run()
                .await
            })
            .unwrap();
        });
        Ok(())
    }
}

// Subscriber
pub struct GatewaySubscriber {
    provider: Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
    config: GatewayConfig,
    receiver: Arc<Mutex<mpsc::Receiver<GatewayEvent>>>,
    kms: Arc<dyn Blockchain>,
}

impl GatewaySubscriber {
    pub async fn new(
        receiver: Arc<Mutex<mpsc::Receiver<GatewayEvent>>>,
        provider: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        config: GatewayConfig,
    ) -> Self {
        let blockchain_instance = blockchain_impl(&config).await;
        Self {
            receiver,
            provider: Arc::clone(provider),
            config,
            kms: blockchain_instance,
        }
    }

    pub fn listen(&self) {
        let receiver = Arc::clone(&self.receiver);
        let provider = Arc::clone(&self.provider);
        let config = self.config.clone();
        let kms = Arc::clone(&self.kms);
        tokio::spawn(async move {
            loop {
                let event = receiver.lock().await.recv().await.unwrap();
                match event {
                    GatewayEvent::Decryption(msg_event) => {
                        if let Err(e) = handle_event_decryption(
                            &provider,
                            &Arc::new(msg_event.clone()),
                            &config,
                        )
                        .await
                        {
                            error!("Error handling event decryption: {:?}", e);
                        }
                        println!("Received Message: {:?}", msg_event);
                    }
                    GatewayEvent::Reencryption(reencrypt_event) => {
                        tracing::info!("Received Reencryption: {:?}", reencrypt_event.clone());
                        let values = reencrypt_event.values;
                        kms.reencrypt(
                            values.signature().to_vec(),
                            values.version(),
                            values.verification_key().to_vec(),
                            values.randomness().to_vec(),
                            values.enc_key().to_vec(),
                            values.fhe_type(),
                            values.key_id().to_vec(),
                            values.ciphertext().to_vec(),
                            values.ciphertext_digest().to_vec(),
                            values.eip712_name().to_string(),
                            values.eip712_version().to_string(),
                            values.eip712_chain_id().to_vec(),
                            values.eip712_verifying_contract().to_string(),
                            values.eip712_salt().to_vec(),
                        )
                        .await
                        .unwrap();
                    }
                    GatewayEvent::KmsEvent(kms_event) => {
                        println!("🤠 Received KmsEvent: {:?}", kms_event);
                        kms.receive(kms_event).await.unwrap();
                    }
                }
            }
        });
    }
}
