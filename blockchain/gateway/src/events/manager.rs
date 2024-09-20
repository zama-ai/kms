use crate::blockchain::blockchain_impl;
use crate::blockchain::handlers::handle_event_decryption;
use crate::blockchain::handlers::handle_reencryption_event;
use crate::blockchain::handlers::handle_zkp_event;
use crate::blockchain::Blockchain;
use crate::common::provider::EventDecryptionFilter;
use crate::config::init_conf_with_trace_connector;
use crate::config::GatewayConfig;
use crate::events::manager::k256::ecdsa::SigningKey;
use crate::util::height::AtomicBlockHeight;
use actix_cors::Cors;
use actix_web::http::Method;
use actix_web::middleware::Logger;
use actix_web::App;
use actix_web::HttpServer;
use actix_web::Responder;
use actix_web::{web, HttpResponse};
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::U256;
use events::kms::KmsEvent;
use events::kms::ReencryptResponseValues;
use events::kms::ZkpResponseValues;
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

// Example payload:
// {
//     signature: '15a4f9a8eb61459cfba7d103d8f911fb04ce91ecf841b34c49c0d56a70b896d20cbc31986188f91efc3842b7df215cee8acb40178daedb8b63d0ba5d199bce121c',
//     client_address: '0x17853A630aAe15AED549B2B874de08B73C0F59c5',
//     enc_key: '2000000000000000df2fcacb774f03187f3802a27259f45c06d33cefa68d9c53426b15ad531aa822',
//     ciphertext_digest: '0748b542afe2353c86cb707e3d21044b0be1fd18efc7cbaa6a415af055bfb358',
//     eip712_verifying_contract: '0x66f9664f97F2b50F62D13eA064982f936dE76657'
// }
// Note that `client_address` and `eip712_verifying_contract`
// are encoded using EIP-55.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct ApiReencryptValues {
    pub(crate) signature: HexVector,
    pub(crate) client_address: String,
    pub(crate) enc_key: HexVector,
    pub(crate) ciphertext_handle: HexVector,
    pub(crate) eip712_verifying_contract: String,
}

#[derive(Debug)]
pub struct ReencryptionEvent {
    pub(crate) values: ApiReencryptValues,
    pub(crate) sender: oneshot::Sender<Vec<ReencryptResponseValues>>,
}

// Note that `client_address` and `eip712_verifying_contract`
// are encoded using EIP-55.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct ApiZkpValues {
    pub(crate) client_address: String,
    pub(crate) caller_address: String,
    pub(crate) ct_proof: HexVector,
    pub(crate) max_num_bits: u32,
}

#[derive(Debug)]
pub struct ZkpEvent {
    pub(crate) values: ApiZkpValues,
    pub(crate) sender: oneshot::Sender<Vec<ZkpResponseValues>>,
}

// Define different event types
pub enum GatewayEvent {
    Decryption(DecryptionEvent),
    Reencryption(ReencryptionEvent),
    Zkp(ZkpEvent),
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
            let cors = Cors::default()
                .allow_any_origin()
                .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                .allowed_headers(vec!["Content-Type"])
                .max_age(3600);

            App::new()
                .wrap(Logger::default())
                .wrap(cors)
                .app_data(web::PayloadConfig::new(payload_limit))
                .app_data(web::Data::new(publisher.clone()))
                .route("/reencrypt", web::post().to(reencrypt_payload))
                .route(
                    "/reencrypt",
                    web::method(Method::OPTIONS).to(|| async {
                        HttpResponse::Ok()
                            .append_header(("Allow", "OPTIONS, POST"))
                            .append_header(("Access-Control-Allow-Origin", "*"))
                            .append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
                            .append_header(("Access-Control-Allow-Headers", "Content-Type"))
                            .finish()
                    }),
                )
                .route("/health", web::get().to(health_check)) // Add health check endpoint
        })
        .workers(20)
        .bind(api_url)
        .unwrap()
        .run()
        .await;

        Ok(())
    }
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("Gateway is listening for reencryption requests")
}

async fn reencrypt_payload(
    payload: web::Json<ApiReencryptValues>,
    publisher: web::Data<Arc<ReencryptionEventPublisher>>,
) -> impl Responder {
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
        Err(e) => {
            error!("Error receiving reencryption response: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "status": "failure" }))
        }
    }
}

#[derive(Clone)]
pub struct ZkpEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
    config: GatewayConfig,
}

impl ZkpEventPublisher {
    pub async fn new(sender: mpsc::Sender<GatewayEvent>, config: GatewayConfig) -> Self {
        Self { sender, config }
    }
}

#[async_trait]
impl Publisher<ZkpEvent> for ZkpEventPublisher {
    fn publish(&self, event: ZkpEvent) {
        self.sender.try_send(GatewayEvent::Zkp(event)).unwrap();
    }

    async fn run(&self) -> anyhow::Result<()> {
        let publisher = Arc::new(self.clone());
        let api_url = self.config.api_url.clone();
        let payload_limit = 10 * 1024 * 1024; // 10 MB
        let _handle = HttpServer::new(move || {
            let cors = Cors::default()
                .allow_any_origin()
                .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                .allowed_headers(vec!["Content-Type"])
                .max_age(3600);

            App::new()
                .wrap(Logger::default())
                .wrap(cors)
                .app_data(web::PayloadConfig::new(payload_limit))
                .app_data(web::Data::new(publisher.clone()))
                .route("/zkp", web::post().to(zkp_payload))
                .route(
                    "/zkp",
                    web::method(Method::OPTIONS).to(|| async {
                        HttpResponse::Ok()
                            .append_header(("Allow", "OPTIONS, POST"))
                            .append_header(("Access-Control-Allow-Origin", "*"))
                            .append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
                            .append_header(("Access-Control-Allow-Headers", "Content-Type"))
                            .finish()
                    }),
                )
                .route("/health", web::get().to(health_check)) // Add health check endpoint
        })
        .workers(20)
        .bind(api_url)
        .unwrap()
        .run()
        .await;

        Ok(())
    }
}

async fn zkp_payload(
    payload: web::Json<ApiZkpValues>,
    publisher: web::Data<Arc<ZkpEventPublisher>>,
) -> HttpResponse {
    info!("🍓🍓🍓 => Received ZKP request");

    let (sender, receiver) = oneshot::channel();

    publisher.publish(ZkpEvent {
        values: payload.into_inner(),
        sender,
    });
    info!("🍓🍓🍓 Published ZKP request");

    match receiver.await {
        Ok(reencryption_response) => {
            info!("🍓🍓🍓 <= Received ZKP response");
            HttpResponse::Ok()
                .json(json!({ "status": "success", "response": reencryption_response }))
        }
        Err(e) => {
            error!("Error receiving ZKP response: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "status": "failure" }))
        }
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
                        GatewayEvent::Zkp(zkp_event) => {
                            debug!("🫐🫐🫐 Received Zkp Event");
                            let zkp_response =
                                handle_zkp_event(&zkp_event.values, &config).await.unwrap();
                            let _ = zkp_event.sender.send(zkp_response);
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
            client_address: "0x1234567890abcdef".to_string(),
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
