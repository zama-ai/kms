use crate::blockchain::blockchain_impl;
use crate::blockchain::ciphertext_provider::CiphertextProvider;
use crate::blockchain::ciphertext_provider::DummyCiphertextProvider;
use crate::blockchain::ciphertext_provider::InternalMiddleware;
use crate::blockchain::handlers::answer_event_decryption;
use crate::blockchain::handlers::handle_event_decryption;
use crate::blockchain::handlers::handle_keyurl_event;
use crate::blockchain::handlers::handle_reencryption_event;
use crate::blockchain::handlers::handle_verify_proven_ct_event;
use crate::blockchain::Blockchain;
use crate::common::provider::get_provider;
use crate::common::provider::EventDecryptionFilter;
use crate::config::init_conf_with_trace_connector;
use crate::config::GatewayConfig;
use crate::config::KeyUrlResponseValues;
use crate::config::VerifyProvenCtResponseToClient;
use crate::events::manager::k256::ecdsa::SigningKey;
use crate::state::file_state::GatewayState;
use crate::state::GatewayEventState;
use crate::state::GatewayInnerEvent;
use actix_cors::Cors;
use actix_web::http::Method;
use actix_web::App;
use actix_web::HttpServer;
use actix_web::Responder;
use actix_web::Route;
use actix_web::{web, HttpResponse};
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use events::kms::KmsEvent;
use events::kms::ReencryptResponseValues;
use events::HexVector;
use kms_blockchain_connector::application::gateway_connector::GatewayConnector;
use kms_blockchain_connector::application::Connector;
use kms_blockchain_connector::config::ConnectorConfig;
use kms_blockchain_connector::domain::oracle::Oracle;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::{mpsc, Mutex};
use tracing::warn;
use tracing::{debug, error, info, trace_span, Instrument};
use tracing_actix_web::TracingLogger;

pub const HTTP_PAYLOAD_LIMIT: usize = 10 * 1024 * 1024; // 10 MB
pub const HTTP_WORKERS: usize = 20;

pub fn get_cors() -> Cors {
    Cors::default()
        .allow_any_origin()
        .allowed_methods(vec!["GET", "POST", "OPTIONS"])
        .allowed_headers(vec!["Content-Type"])
        .max_age(3600)
}

pub fn get_options() -> Route {
    web::method(Method::OPTIONS).to(|| async {
        HttpResponse::Ok()
            .append_header(("Allow", "OPTIONS, GET, POST"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .append_header(("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
            .append_header(("Access-Control-Allow-Headers", "Content-Type"))
            .finish()
    })
}

/// Starts an http server on the gateway with support for all the REST endpoints.
/// For now this includes health, reencryption, keyurl and verify_proven_ct.
pub async fn start_http_server(api_url: String, sender: mpsc::Sender<GatewayEvent>) {
    let _handle = HttpServer::new(move || {
        let reencrypt_publisher = ReencryptionEventPublisher::new(sender.clone());
        let verify_proven_ct_publisher = VerifyProvenCtEventPublisher::new(sender.clone());
        let keyurl_publisher = KeyUrlEventPublisher::new(sender.clone());
        App::new()
            .wrap(TracingLogger::default())
            .wrap(get_cors())
            .route("/health", web::get().to(health_check)) // Add health endpoint
            .app_data(web::PayloadConfig::new(HTTP_PAYLOAD_LIMIT))
            .app_data(web::Data::new(Arc::new(reencrypt_publisher)))
            .route(
                &ReencryptionEventPublisher::path(),
                web::post().to(reencrypt_payload),
            )
            .route(&ReencryptionEventPublisher::path(), get_options())
            .app_data(web::Data::new(Arc::new(verify_proven_ct_publisher)))
            .route(
                &VerifyProvenCtEventPublisher::path(),
                web::post().to(verify_proven_ct_payload),
            )
            .route(&VerifyProvenCtEventPublisher::path(), get_options())
            .app_data(web::Data::new(Arc::new(keyurl_publisher)))
            .route(&KeyUrlEventPublisher::path(), web::get().to(keyurl_payload))
            .route(&KeyUrlEventPublisher::path(), get_options())
    })
    .workers(HTTP_WORKERS)
    .bind(api_url)
    .unwrap()
    .run()
    .await;
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("Gateway is listening for reencryption requests")
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionEvent {
    pub(crate) filter: EventDecryptionFilter,
    pub(crate) block_number: u64,
}

// Example payload:
// {
//     signature: '15a4f9a8eb61459cfba7d103d8f911fb04ce91ecf841b34c49c0d56a70b896d20cbc31986188f91efc3842b7df215cee8acb40178daedb8b63d0ba5d199bce121c',
//     client_address: '0x17853A630aAe15AED549B2B874de08B73C0F59c5',
//     enc_key: '2000000000000000df2fcacb774f03187f3802a27259f45c06d33cefa68d9c53426b15ad531aa822',
//     ciphertext_handle: '0748b542afe2353c86cb707e3d21044b0be1fd18efc7cbaa6a415af055bfb358',
//     eip712_verifying_contract: '0x66f9664f97F2b50F62D13eA064982f936dE76657'
// }
// Note that `client_address` and `eip712_verifying_contract`
// are encoded using EIP-55.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct ApiReencryptValues {
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

#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct ApiVerifyProvenCtValues {
    pub(crate) contract_address: String,
    pub(crate) caller_address: String,
    pub(crate) key_id: String,
    pub(crate) crs_id: String,
    pub(crate) ct_proof: HexVector,
}

#[derive(Debug)]
pub struct VerifyProvenCtEvent {
    pub(crate) values: ApiVerifyProvenCtValues,
    pub(crate) sender: oneshot::Sender<anyhow::Result<VerifyProvenCtResponseToClient>>,
}

#[derive(Debug)]
pub struct KeyUrlEvent {
    pub(crate) sender: oneshot::Sender<KeyUrlResponseValues>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KmsEventWithHeight {
    pub event: KmsEvent,
    pub height: u64,
}

impl KmsEventWithHeight {
    pub fn new(event: KmsEvent, height: u64) -> Self {
        Self { event, height }
    }
}

// Define different event types
pub enum GatewayEvent {
    Decryption(DecryptionEvent),
    Reencryption(ReencryptionEvent),
    VerifyProvenCt(VerifyProvenCtEvent),
    KeyUrl(KeyUrlEvent),
    //KmsEvents come with their height
    KmsEvent(KmsEventWithHeight),
}

// Define a trait for all publishers
pub trait Publisher<Event> {
    fn publish(&self, event: Event);
}

// Define a trait for runnable publishers
#[async_trait]
pub trait RunnablePublisher<Event>: Publisher<Event> {
    async fn run(&self) -> anyhow::Result<()>;
}

// Define a trait for HTTP publishers
pub trait HttpPublisher<Event>: Publisher<Event> {
    fn path() -> String;
}

// Publisher for DecryptionEvent events
#[derive(Clone)]
pub struct DecryptionEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
    provider: Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
    config: GatewayConfig,
    state: GatewayState,
}

impl DecryptionEventPublisher {
    pub async fn new(
        sender: mpsc::Sender<GatewayEvent>,
        provider: &Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>,
        config: GatewayConfig,
        state: GatewayState,
    ) -> Self {
        Self {
            sender,
            provider: Arc::clone(provider),
            config,
            state,
        }
    }
}

impl Publisher<DecryptionEvent> for DecryptionEventPublisher {
    fn publish(&self, event: DecryptionEvent) {
        self.sender
            .try_send(GatewayEvent::Decryption(event))
            .unwrap();
    }
}

#[async_trait]
impl RunnablePublisher<DecryptionEvent> for DecryptionEventPublisher {
    async fn run(&self) -> anyhow::Result<()> {
        // Run from the block height provided by the state or current height
        let mut last_block = if let Some(height) = self.state.get_main_chain_height().await {
            height
        } else {
            self.provider
                .get_block(BlockNumber::Latest)
                .await
                .unwrap_or_else(|e| {
                    error!("Failed to get latest block: {:?}", e);
                    std::process::exit(1);
                })
                .unwrap()
                .number
                .unwrap()
                .as_u64()
        };

        let mut last_request_id = None;
        let mut stream = self.provider.subscribe_blocks().await.unwrap();

        // NOTE: It seems we use this stream only to wake up
        // when new blocks are published, BUT we re-query
        // inside of this loop to get the logs
        while let Some(block) = stream.next().await {
            info!("(DecryptionEventPublisher) 🧱 block number: {}", last_block);

            // process any EventDecryption logs
            let events = self
                .provider
                .get_logs(
                    &Filter::new()
                        // from_block includes the given block height but we don't care about the last block
                        // seen as we already saw it
                        .from_block(last_block)
                        .address(self.config.ethereum.oracle_predeploy_address)
                        .event("EventDecryption(uint256,uint256[],address,bytes4,uint256,uint256,bool)"),
                )
                .await
                .unwrap();

            for log in events {
                let block_number = log.block_number.unwrap().as_u64();
                last_block = std::cmp::max(last_block, block_number);
                info!("Received event at Block: {:?}", block_number);
                let event_decryption: EventDecryptionFilter =
                    EthLogDecode::decode_log(&log.clone().into()).unwrap();

                //TODO: This check seems incompatible with potential reorg,
                //see https://github.com/zama-ai/kms-core/issues/1245

                //Counting on lazy evaluation of the or to have never failing unwraps
                if last_request_id.is_none()
                    || event_decryption.request_id > last_request_id.unwrap()
                {
                    last_request_id = Some(event_decryption.request_id);
                    info!("⭐ event_decryption: {:?}", event_decryption.request_id);
                    debug!("EventDecryptionFilter: {:?}", event_decryption);

                    //Before publishing we add the event to the state
                    let decryption_event = DecryptionEvent {
                        filter: event_decryption.clone(),
                        block_number: log.block_number.unwrap().as_u64(),
                    };
                    if self
                        .state
                        .add_event(GatewayInnerEvent::Decryption(decryption_event.clone()))
                        .await
                    {
                        self.publish(decryption_event);

                        info!(
                            "Handled event decryption: {:?}",
                            event_decryption.request_id
                        );
                    } else {
                        warn!("Trying to add a Decryption event that's already in the state. Not handling it here.")
                    }
                }
            }
            // This update also triggers a save of the state
            let _ = self.state.update_main_chain_height(last_block).await;

            last_block = block.number.unwrap().as_u64();
        }
        Ok(())
    }
}

/// Picks up decryption events from the L1 and publish them to our GW
pub async fn start_decryption_publisher(
    sender: Sender<GatewayEvent>,
    config: GatewayConfig,
    state: GatewayState,
) {
    let provider = get_provider(&config.ethereum).await.unwrap_or_else(|e| {
        tracing::error!("Failed to set up provider: {:?}", e);
        std::process::exit(1);
    });

    let decryption_publisher =
        DecryptionEventPublisher::new(sender.clone(), &provider, config.clone(), state).await;
    tokio::spawn(async move {
        if let Err(e) = decryption_publisher.run().await {
            tracing::error!("Failed to run DecryptionEventPublisher: {:?}", e);
            std::process::exit(1);
        }
    });
    tracing::info!("DecryptionEventPublisher created");
}

#[derive(Clone)]
pub struct KmsEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
    starting_block: Option<usize>,
}

#[async_trait]
impl Oracle for KmsEventPublisher {
    async fn respond(&self, event: KmsEvent, height_of_event: u64) -> anyhow::Result<()> {
        debug!("🚀🚀🚀🚀🚀🚀 Oracle event: {:?}", event.txn_id());
        self.publish(KmsEventWithHeight::new(event, height_of_event));
        Ok(())
    }
}

impl KmsEventPublisher {
    pub async fn new(sender: mpsc::Sender<GatewayEvent>, starting_block: Option<usize>) -> Self {
        Self {
            sender,
            starting_block,
        }
    }
}

impl Publisher<KmsEventWithHeight> for KmsEventPublisher {
    fn publish(&self, event: KmsEventWithHeight) {
        self.sender.try_send(GatewayEvent::KmsEvent(event)).unwrap();
    }
}

#[async_trait]
impl RunnablePublisher<KmsEventWithHeight> for KmsEventPublisher {
    async fn run(&self) -> anyhow::Result<()> {
        let config: ConnectorConfig = init_conf_with_trace_connector(
            std::env::var("CONNECTOR_CONFIG")
                .unwrap_or_else(|_| "config/connector.toml".to_string())
                .as_str(),
        )?;

        let _ = GatewayConnector::new_with_config_and_listener(config, self.clone())
            .await?
            .listen_for_events(self.starting_block)
            .await;
        Ok(())
    }
}

/// Picks up events from the KMS BC and publish them to our GW
///
/// Internally uses some form of the _connector_
pub async fn start_kms_event_publisher(
    sender: Sender<GatewayEvent>,
    starting_block: Option<usize>,
) {
    let kms_publisher = KmsEventPublisher::new(sender.clone(), starting_block).await;
    tokio::spawn(async move {
        if let Err(e) = kms_publisher.run().await {
            tracing::error!("Failed to run KmsEventPublisher: {:?}", e);
            std::process::exit(1);
        }
    });
    tracing::info!("KmsEventPublisher created");
}

#[derive(Clone)]
pub struct ReencryptionEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
}

impl ReencryptionEventPublisher {
    pub fn new(sender: mpsc::Sender<GatewayEvent>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl Publisher<ReencryptionEvent> for ReencryptionEventPublisher {
    fn publish(&self, event: ReencryptionEvent) {
        self.sender
            .try_send(GatewayEvent::Reencryption(event))
            .unwrap();
    }
}

impl HttpPublisher<ReencryptionEvent> for ReencryptionEventPublisher {
    fn path() -> String {
        "/reencrypt".to_string()
    }
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
pub struct VerifyProvenCtEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
}

impl VerifyProvenCtEventPublisher {
    pub fn new(sender: mpsc::Sender<GatewayEvent>) -> Self {
        Self { sender }
    }
}

impl HttpPublisher<VerifyProvenCtEvent> for VerifyProvenCtEventPublisher {
    fn path() -> String {
        "/verify_proven_ct".to_string()
    }
}

#[async_trait]
impl Publisher<VerifyProvenCtEvent> for VerifyProvenCtEventPublisher {
    fn publish(&self, event: VerifyProvenCtEvent) {
        self.sender
            .try_send(GatewayEvent::VerifyProvenCt(event))
            .unwrap();
    }
}

pub(crate) async fn verify_proven_ct_payload(
    payload: web::Json<ApiVerifyProvenCtValues>,
    publisher: web::Data<Arc<VerifyProvenCtEventPublisher>>,
) -> HttpResponse {
    info!("🍓🍓🍓 => Received verify proven ct request");

    let (sender, receiver) = oneshot::channel();

    publisher.publish(VerifyProvenCtEvent {
        values: payload.into_inner(),
        sender,
    });
    info!("🍓🍓🍓 Published verify proven ct request");

    match receiver.await {
        Ok(Ok(verify_proven_ct_response)) => {
            info!("🍓🍓🍓 <= Received verify proven ct response");
            HttpResponse::Ok()
                .json(json!({ "status": "success", "response": verify_proven_ct_response }))
        }
        Ok(Err(e)) => {
            error!("Error receiving verify proven ct response: {:?}", e);
            HttpResponse::BadRequest()
                .json(json!({ "status": "failure", "response": e.to_string() }))
        }
        Err(e) => {
            error!("Error receiving verify proven ct response: {:?}", e);
            HttpResponse::InternalServerError()
                .json(json!({ "status": "failure", "response": e.to_string() }))
        }
    }
}

#[derive(Clone)]
pub struct KeyUrlEventPublisher {
    sender: mpsc::Sender<GatewayEvent>,
}

impl KeyUrlEventPublisher {
    pub fn new(sender: mpsc::Sender<GatewayEvent>) -> Self {
        Self { sender }
    }
}

impl HttpPublisher<KeyUrlEvent> for KeyUrlEventPublisher {
    fn path() -> String {
        "/keyurl".to_string()
    }
}

#[async_trait]
impl Publisher<KeyUrlEvent> for KeyUrlEventPublisher {
    fn publish(&self, event: KeyUrlEvent) {
        self.sender.try_send(GatewayEvent::KeyUrl(event)).unwrap();
    }
}

async fn keyurl_payload(publisher: web::Data<Arc<KeyUrlEventPublisher>>) -> HttpResponse {
    info!("🍓🍓🍓 => Received KeyUrl request");
    let (sender, receiver) = oneshot::channel();

    publisher.publish(KeyUrlEvent { sender });
    info!("🍓🍓🍓 Published KeyUrl request");
    match receiver.await {
        Ok(keyurl_response) => {
            info!("🍓🍓🍓 <= Received KeyUrl response");
            HttpResponse::Ok().json(json!({ "status": "success", "response": keyurl_response }))
        }
        Err(e) => {
            error!("Error receiving KeyUrl response: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "status": "failure" }))
        }
    }
}

// Gateway subscriber that subscribes to events,
// events from multiple publishers will come into the `receiver` channel.
pub struct GatewaySubscriber {
    config: GatewayConfig,
    receiver: Arc<Mutex<mpsc::Receiver<GatewayEvent>>>,
    kms_blockchain: Arc<dyn Blockchain>,
    ct_provider: Arc<Box<dyn CiphertextProvider>>,
    middleware: Arc<Box<dyn InternalMiddleware>>,
    state: GatewayState,
}

impl GatewaySubscriber {
    pub(crate) async fn new(
        receiver: Arc<Mutex<mpsc::Receiver<GatewayEvent>>>,
        config: GatewayConfig,
        state: GatewayState,
    ) -> anyhow::Result<(Self, Option<MockProvider>)> {
        let blockchain_instance = blockchain_impl(&config, state.clone()).await;
        let ct_provider = if config.debug {
            Box::new(DummyCiphertextProvider)
        } else {
            <crate::config::EthereumConfig as Into<Box<dyn CiphertextProvider>>>::into(
                config.ethereum.clone(),
            )
        };

        let (middleware, mock): (Arc<Box<dyn InternalMiddleware>>, _) = if config.debug {
            let (mw, mk) = crate::blockchain::handlers::mock_provider(&config).await?;
            (
                Arc::new(Box::new(
                    crate::blockchain::ciphertext_provider::MockMiddleware { inner: mw },
                )),
                Some(mk),
            )
        } else {
            (
                Arc::new(Box::new(
                    crate::blockchain::ciphertext_provider::RealMiddleware {
                        inner: crate::blockchain::handlers::http_provider(&config).await?,
                    },
                )),
                None,
            )
        };

        Ok((
            GatewaySubscriber {
                receiver,
                config,
                kms_blockchain: blockchain_instance,
                ct_provider: ct_provider.into(),
                middleware,
                state,
            },
            mock,
        ))
    }

    pub fn listen(&self) {
        let receiver = Arc::clone(&self.receiver);
        let config = self.config.clone();
        let kms = Arc::clone(&self.kms_blockchain);
        let ct_provider = Arc::clone(&self.ct_provider);
        let middleware = Arc::clone(&self.middleware);
        let state = self.state.clone();

        tokio::spawn(async move {
            loop {
                // This receiver has senders ends that listen on
                // - The KMS BC (for Response events)
                // - The L1 BC (for Decryption Request events)
                // - The HTTP server (for Verifiy/Reenc Request events)
                let gateway_event = receiver.lock().await.recv().await.unwrap();
                let config = config.clone();
                let kms_blockchain = Arc::clone(&kms);
                let ct_provider = Arc::clone(&ct_provider);
                let middleware = Arc::clone(&middleware);
                let state = state.clone();
                tokio::task::spawn(
                    async move {
                        let start = tokio::time::Instant::now();
                        match gateway_event {
                            GatewayEvent::Decryption(decryption_event) => {
                                let span = trace_span!("decrypt");
                                let _guard = span.enter();
                                debug!("🫐🫐🫐 Received Decryption Event");
                                let gateway_inner_event =
                                    GatewayInnerEvent::Decryption(decryption_event.clone());
                                if let Err(e) = handle_event_decryption(
                                    decryption_event,
                                    &config,
                                    kms_blockchain,
                                    middleware,
                                )
                                .await
                                {
                                    error!("Error handling event decryption: {:?}", e);
                                } else if let Err(e) =
                                    state.remove_event(&gateway_inner_event).await
                                {
                                    error!("Error removing event from state : {:?}", e);
                                }
                            }
                            GatewayEvent::Reencryption(reencrypt_event) => {
                                let span = trace_span!("re-encrypt");
                                let _guard = span.enter();
                                debug!("🫐🫐🫐 Received Reencryption Event");
                                match handle_reencryption_event(
                                    &reencrypt_event.values,
                                    &config,
                                    ct_provider,
                                    middleware,
                                    kms_blockchain,
                                )
                                .await
                                {
                                    Ok(resp) => {
                                        let _ = reencrypt_event.sender.send(resp);
                                    }
                                    Err(e) => {
                                        error!("failed to handle reencryption with error {e}");
                                    }
                                }
                            }
                            GatewayEvent::VerifyProvenCt(verify_proven_ct_event) => {
                                let span = trace_span!("verify-proven-ct");
                                let _guard = span.enter();
                                debug!("🫐🫐🫐 Received VerifyProvenCt Event");
                                let result = handle_verify_proven_ct_event(
                                    &verify_proven_ct_event.values,
                                    &config,
                                    middleware,
                                    kms_blockchain,
                                    ct_provider,
                                )
                                .await;
                                let sended = verify_proven_ct_event.sender.send(result);
                                if let Err(_result) = sended {
                                    error!("failed to send message back");
                                }
                            }
                            GatewayEvent::KeyUrl(keyurl_event) => {
                                let span = trace_span!("key-url");
                                let _guard = span.enter();
                                debug!("🫐🫐🫐 Received KeyUrl Event");
                                match handle_keyurl_event(kms_blockchain).await {
                                    Ok(keyurl_response) => {
                                        let _ = keyurl_event.sender.send(keyurl_response);
                                    }
                                    Err(e) => {
                                        error!("failed to handle keyurl request with error {e}");
                                    }
                                }
                            }
                            // If we receive a KmsEvent that is not a Request (i.e. that is a Respone)
                            // We forward it to the kms_blockchain that will filter hit and try to hit one
                            // of the event we are waiting for in wait_for_transaction
                            GatewayEvent::KmsEvent(kms_event) => {
                                debug!("🫐🫐🫐 Received KmsEvent: {:?}", kms_event);
                                if let Err(e) = kms_blockchain.receive(kms_event).await {
                                    error!("failed to handle kms request with error {e}");
                                }
                            }
                        }
                        let duration = start.elapsed();
                        info!("⏱️ E2E Event Time elapsed: {:?}", duration);
                    }
                    .instrument(tracing::info_span!("process event")),
                );
            }
        });
    }

    // For now we only support catching up on Decryption request
    // All other requests will be treated as if they had never been seen
    pub(crate) fn catchup(&self, old_state: HashMap<GatewayInnerEvent, GatewayEventState>) {
        let state = self.state.clone();
        let kms = Arc::clone(&self.kms_blockchain);
        let middleware = Arc::clone(&self.middleware);
        tracing::info!("Catching up on {} values from old state", old_state.len());
        for (event, event_state) in old_state {
            match event {
                GatewayInnerEvent::Decryption(decryption_event) => {
                    let state = state.clone();
                    let config = self.config.clone();
                    let kms = kms.clone();
                    let middleware = middleware.clone();

                    tokio::spawn(async move {
                        Self::handle_decryption_catchup(
                            decryption_event,
                            event_state,
                            state.clone(),
                            &config,
                            kms.clone(),
                            middleware.clone(),
                        )
                        .await;
                    });
                }
                GatewayInnerEvent::Reencryption(_api_reencrypt_values) => todo!(),
                GatewayInnerEvent::VerifyProvenCt(_api_verify_proven_ct_values) => todo!(),
            }
        }
    }

    async fn handle_decryption_catchup(
        decryption_event: DecryptionEvent,
        event_state: GatewayEventState,
        state: GatewayState,
        config: &GatewayConfig,
        kms_blockchain: Arc<dyn Blockchain>,
        middleware: Arc<Box<dyn InternalMiddleware>>,
    ) {
        let request_id = decryption_event.filter.request_id;
        info!(
            "Catching up on a request with id {} with state {:?}",
            request_id, event_state
        );
        let gateway_inner_event = GatewayInnerEvent::Decryption(decryption_event.clone());
        let res = if let GatewayEventState::Received = event_state {
            // If we've just received the request and nothing else, treat it as a new request
            if let Err(e) =
                handle_event_decryption(decryption_event, config, kms_blockchain, middleware).await
            {
                error!("Error handling event decryption: {:?}", e);
            }
            None
        } else {
            // If we had already sent the request to KMS BC,
            // get result from kms_blockchain
            match kms_blockchain
                .decrypt_catchup(decryption_event, event_state)
                .await
            {
                Ok(res) => Some(res),
                Err(e) => {
                    error!("Error trying to catchup event decryption: {:?}", e);
                    None
                }
            }
        };

        //If we have some res, need to compete the tx
        if let Some((tokens, signatures)) = res {
            if let Err(e) = answer_event_decryption(tokens, signatures, config, request_id).await {
                error!("Error trying to fullfill transaction : {:?}", e);
            }
        }

        //Finished catching up, remove the event from the state
        if let Err(e) = state.remove_event(&gateway_inner_event).await {
            error!("Error removing event from state : {:?}", e);
        }
        info!("Succesfully caught up on request with id {}", request_id);
    }
}

/// Start the GW which subscribes to events emitted
/// on the sender end of the provider receiver by:
/// - The L1 blockchain for decryption events through [`start_decryption_publisher`]
/// - The http_server through [`start_http_server`]
/// - The KMS blockchain through [`start_kms_event_publisher`]
///
/// The usual logic for the gateway is to:
/// - (1) catch an event comming from L1 or http_sever
/// - (2) forward it to the KMS BC
/// - (3) poll the KMS BC for the answer to (2)
/// - (4) send back the answer to the emitter of (1)
pub async fn start_gateway(
    receiver: Receiver<GatewayEvent>,
    config: GatewayConfig,
    state: GatewayState,
    old_state: Option<HashMap<GatewayInnerEvent, GatewayEventState>>,
) -> anyhow::Result<Option<MockProvider>> {
    //Load state from file
    let (subscriber, mock) = GatewaySubscriber::new(Arc::new(Mutex::new(receiver)), config, state)
        .await
        .unwrap();
    if let Some(old_state) = old_state {
        subscriber.catchup(old_state);
    }
    subscriber.listen();
    tracing::info!("GatewaySubscriber started");
    Ok(mock)
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
