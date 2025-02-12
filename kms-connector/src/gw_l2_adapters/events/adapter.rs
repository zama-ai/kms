use alloy::{
    network::Ethereum,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    transports::ws::WsConnect,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::sleep};
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use crate::{error::Result, gw_l2_contracts::decryption::IDecryptionManager};

/// Maximum number of reconnection attempts before backing off
const MAX_QUICK_RETRIES: u32 = 3;
/// Initial retry delay in seconds
const INITIAL_RETRY_DELAY: u64 = 5;
/// Maximum retry delay in seconds
const MAX_RETRY_DELAY: u64 = 60;

/// Events that can be processed by the KMS Core
#[derive(Debug, Clone)]
pub enum KmsCoreEvent {
    /// Public decryption request
    PublicDecryption(IDecryptionManager::PublicDecryptionRequest),
    /// User decryption request
    UserDecryption(IDecryptionManager::UserDecryptionRequest),
}

/// Adapter for handling L2 events
#[derive(Debug)]
pub struct EventsAdapter {
    rpc_url: String,
    decryption_manager: Address,
    #[allow(dead_code)] // TODO: remove once HTTPZ SC is finished
    httpz: Address,
    event_tx: mpsc::Sender<KmsCoreEvent>,
    running: Arc<AtomicBool>,
}

impl EventsAdapter {
    /// Create a new events adapter
    pub fn new(
        rpc_url: String,
        decryption_manager: Address,
        httpz: Address,
        event_tx: mpsc::Sender<KmsCoreEvent>,
    ) -> Self {
        Self {
            rpc_url,
            decryption_manager,
            httpz,
            event_tx,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Initialize event subscriptions
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing event subscriptions...");

        let rpc_url = self.rpc_url.clone();
        let decryption_manager = self.decryption_manager;
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut retry_count = 0;
            let mut retry_delay = INITIAL_RETRY_DELAY;

            while running.load(Ordering::SeqCst) {
                info!("Attempting to connect to {}", rpc_url);

                match Self::attempt_connection(
                    &rpc_url,
                    decryption_manager,
                    event_tx.clone(),
                    running.clone(),
                )
                .await
                {
                    Ok(_) => {
                        // Reset retry counters on successful connection
                        retry_count = 0;
                        retry_delay = INITIAL_RETRY_DELAY;

                        if running.load(Ordering::SeqCst) {
                            warn!("Event subscription ended, will reconnect...");
                        } else {
                            info!("Event subscription stopped gracefully");
                            break;
                        }
                    }
                    Err(e) => {
                        retry_count += 1;
                        error!(
                            "Connection attempt {} failed: {}, retrying in {}s...",
                            retry_count, e, retry_delay
                        );

                        // Implement exponential backoff if we've had too many quick retries
                        if retry_count > MAX_QUICK_RETRIES {
                            retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                        }
                    }
                }

                if running.load(Ordering::SeqCst) {
                    sleep(Duration::from_secs(retry_delay)).await;
                } else {
                    info!("Shutting down event subscription gracefully");
                    break;
                }
            }
        });

        Ok(())
    }

    /// Attempt to establish a connection and subscribe to events
    async fn attempt_connection(
        rpc_url: &str,
        decryption_manager: Address,
        event_tx: mpsc::Sender<KmsCoreEvent>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        // Create new provider for each attempt
        let ws = WsConnect::new(rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;
        let provider = Arc::new(provider);

        info!("Connected to RPC endpoint");

        // Subscribe to decryption events
        Self::subscribe_to_decryption_events(provider, decryption_manager, event_tx, running).await
    }

    /// Stop event subscriptions
    pub fn stop(&self) {
        info!("Stopping event subscriptions...");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Subscribe to decryption events
    async fn subscribe_to_decryption_events<P: Provider<Ethereum>>(
        provider: Arc<P>,
        address: Address,
        event_tx: mpsc::Sender<KmsCoreEvent>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let contract = IDecryptionManager::new(address, provider);

        let public_filter = contract.PublicDecryptionRequest_filter().watch().await?;
        info!("Subscribed to PublicDecryptionRequest events");

        let user_filter = contract.UserDecryptionRequest_filter().watch().await?;
        info!("Subscribed to UserDecryptionRequest events");

        let mut public_stream = public_filter.into_stream();
        let mut user_stream = user_filter.into_stream();

        loop {
            if !running.load(Ordering::SeqCst) {
                info!("Event subscription stopping due to shutdown signal");
                break;
            }

            tokio::select! {
                result = public_stream.next() => match result {
                    Some(Ok((event, _))) => {
                        if let Err(e) = event_tx.send(KmsCoreEvent::PublicDecryption(event)).await {
                            error!("Failed to send public decryption event: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("Public decryption stream error: {}", e);
                        break;
                    }
                    None => {
                        error!("Public decryption stream ended unexpectedly");
                        break;
                    }
                },
                result = user_stream.next() => match result {
                    Some(Ok((event, _))) => {
                        if let Err(e) = event_tx.send(KmsCoreEvent::UserDecryption(event)).await {
                            error!("Failed to send user decryption event: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("User decryption stream error: {}", e);
                        break;
                    }
                    None => {
                        error!("User decryption stream ended unexpectedly");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}
