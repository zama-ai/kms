use alloy::{
    network::Ethereum,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    transports::ws::WsConnect,
};
use alloy_rpc_types_eth::Log;
use anyhow::{anyhow, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use crate::gw_l2_contracts::{decryption::IDecryptionManager, httpz::IHTTPZ};

/// Maximum number of reconnection attempts before backing off
const MAX_QUICK_RETRIES: u32 = 3;
/// Initial retry delay in seconds
const INITIAL_RETRY_DELAY: u64 = 1;
/// Maximum retry delay in seconds
const MAX_RETRY_DELAY: u64 = 60;
/// Default event processing timeout
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Events that can be processed by the KMS Core
#[derive(Debug, Clone)]
pub enum KmsCoreEvent {
    /// Public decryption request
    PublicDecryptionRequest(IDecryptionManager::PublicDecryptionRequest),
    /// Public decryption response
    PublicDecryptionResponse(IDecryptionManager::PublicDecryptionResponse),
    /// User decryption request
    UserDecryptionRequest(IDecryptionManager::UserDecryptionRequest),
    /// User decryption response
    UserDecryptionResponse(IDecryptionManager::UserDecryptionResponse),
    /// Preprocess keygen request
    PreprocessKeygenRequest(IHTTPZ::PreprocessKeygenRequest),
    /// Preprocess keygen response
    PreprocessKeygenResponse(IHTTPZ::PreprocessKeygenResponse),
    /// Preprocess kskgen request
    PreprocessKskgenRequest(IHTTPZ::PreprocessKskgenRequest),
    /// Preprocess kskgen response
    PreprocessKskgenResponse(IHTTPZ::PreprocessKskgenResponse),
    /// Keygen request
    KeygenRequest(IHTTPZ::KeygenRequest),
    /// Keygen response
    KeygenResponse(IHTTPZ::KeygenResponse),
    /// CRS generation request
    CrsgenRequest(IHTTPZ::CrsgenRequest),
    /// CRS generation response
    CrsgenResponse(IHTTPZ::CrsgenResponse),
    /// KSK generation request
    KskgenRequest(IHTTPZ::KskgenRequest),
    /// KSK generation response
    KskgenResponse(IHTTPZ::KskgenResponse),
}

/// Adapter for handling L2 events
#[derive(Debug)]
pub struct EventsAdapter {
    rpc_url: String,
    decryption_manager: Address,
    httpz: Address,
    event_tx: mpsc::Sender<KmsCoreEvent>,
    running: Arc<AtomicBool>,
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
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
            handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Initialize event subscriptions
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing event subscriptions...");

        let rpc_url = self.rpc_url.clone();
        let decryption_manager = self.decryption_manager;
        let httpz = self.httpz;
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();

        let handle = tokio::spawn(async move {
            let mut retry_count = 0;
            let mut retry_delay = INITIAL_RETRY_DELAY;

            while running.load(Ordering::SeqCst) {
                info!("Attempting to connect to {}", rpc_url);

                match Self::attempt_connection(
                    &rpc_url,
                    decryption_manager,
                    httpz,
                    event_tx.clone(),
                    running.clone(),
                )
                .await
                {
                    Ok(_) => {
                        info!("Connection successful");
                        retry_count = 0;
                        retry_delay = INITIAL_RETRY_DELAY;
                    }
                    Err(e) => {
                        error!("Connection failed: {}", e);
                        retry_count += 1;

                        if retry_count >= MAX_QUICK_RETRIES {
                            retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                        }

                        warn!(
                            "Retrying in {} seconds (attempt {})...",
                            retry_delay, retry_count
                        );
                        sleep(Duration::from_secs(retry_delay)).await;
                    }
                }
            }

            info!("Connection loop terminated");
        });

        self.store_handle(handle);
        Ok(())
    }

    /// Attempt to establish a connection and subscribe to events
    async fn attempt_connection(
        rpc_url: &str,
        decryption_manager: Address,
        httpz: Address,
        event_tx: mpsc::Sender<KmsCoreEvent>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let ws = WsConnect::new(rpc_url);
        let provider = Arc::new(ProviderBuilder::new().on_ws(ws).await?);

        info!("Connected to Gateway L2RPC endpoint");

        let mut tasks = vec![
            tokio::spawn(Self::subscribe_to_decryption_events(
                provider.clone(),
                decryption_manager,
                event_tx.clone(),
                running.clone(),
            )),
            tokio::spawn(Self::subscribe_to_httpz_events(
                provider,
                httpz,
                event_tx,
                running.clone(),
            )),
        ];

        // Create a stream from the running flag for graceful shutdown
        let mut shutdown = tokio::time::interval(Duration::from_millis(100));
        let running_check = running.clone();

        // Wait for any task to complete or fail, or for shutdown signal
        while !tasks.is_empty() {
            tokio::select! {
                _ = shutdown.tick() => {
                    if !running_check.load(Ordering::SeqCst) {
                        debug!("Received shutdown signal, stopping tasks");
                        for task in &tasks {
                            task.abort();
                        }
                        return Ok(());
                    }
                }
                result = futures::future::select_all(tasks.iter_mut()) => {
                    let (result, idx, _) = result;
                    match result {
                        Ok(Ok(_)) => {
                            tasks.remove(idx);
                            if !tasks.is_empty() {
                                info!("One task completed, {} remaining", tasks.len());
                            }
                        }
                        Ok(Err(e)) => {
                            // Abort other tasks
                            for task in &tasks {
                                task.abort();
                            }
                            return Err(anyhow!("Task {} failed: {}", idx, e));
                        }
                        Err(e) => {
                            // Abort other tasks
                            for task in &tasks {
                                task.abort();
                            }
                            return Err(anyhow!("Task {} panicked: {}", idx, e));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Stop event subscriptions and clean up resources
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping event subscriptions...");

        // 1. Signal stop to all running tasks
        self.running.store(false, Ordering::SeqCst);

        // 2. Take all handles first to avoid holding MutexGuard across await points
        let handles = {
            if let Ok(mut handles) = self.handles.lock() {
                handles.drain(..).collect::<Vec<_>>()
            } else {
                error!("Failed to acquire lock for subscription handles");
                return Ok(()); // Return OK since we've signaled shutdown
            }
        };

        // 3. Wait for all tasks with timeout
        let mut errors = Vec::new();
        for handle in handles {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(result) => {
                    if let Err(e) = result {
                        errors.push(format!("Task failed: {}", e));
                    }
                }
                Err(_) => {
                    errors.push("Task timed out".to_string());
                }
            }
        }

        // Log any errors that occurred during shutdown
        if !errors.is_empty() {
            error!(
                "Errors during event subscription shutdown: {}",
                errors.join(", ")
            );
        }

        info!("Event subscriptions stopped");
        Ok(())
    }

    /// Store a subscription handle for cleanup
    fn store_handle(&self, handle: JoinHandle<()>) {
        if let Ok(mut handles) = self.handles.lock() {
            handles.push(handle);
        }
    }

    /// Subscribe to decryption events
    async fn subscribe_to_decryption_events<P: Provider<Ethereum>>(
        provider: Arc<P>,
        address: Address,
        event_tx: mpsc::Sender<KmsCoreEvent>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let contract = IDecryptionManager::new(address, provider);

        info!("Starting IDecryptionManager event subscriptions...");

        let public_filter = contract.PublicDecryptionRequest_filter().watch().await?;
        info!("✓ Subscribed to PublicDecryptionRequest events");

        let user_filter = contract.UserDecryptionRequest_filter().watch().await?;
        info!("✓ Subscribed to UserDecryptionRequest events");

        let mut public_stream = public_filter.into_stream();
        let mut user_stream = user_filter.into_stream();

        info!("Successfully subscribed to all IDecryptionManager events");

        loop {
            if !running.load(Ordering::SeqCst) {
                info!("Event subscription stopping due to shutdown signal");
                break;
            }

            tokio::select! {
                result = public_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::PublicDecryptionRequest, "PublicDecryptionRequest".to_string()).await?,
                result = user_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::UserDecryptionRequest, "UserDecryptionRequest".to_string()).await?,
            }
        }

        Ok(())
    }

    /// Subscribe to HTTPZ events
    async fn subscribe_to_httpz_events<P: Provider<Ethereum>>(
        provider: Arc<P>,
        address: Address,
        event_tx: mpsc::Sender<KmsCoreEvent>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let contract = IHTTPZ::new(address, provider);

        info!("Starting IHttpz event subscriptions...");

        let preprocess_keygen_request_filter =
            contract.PreprocessKeygenRequest_filter().watch().await?;
        info!("✓ Subscribed to PreprocessKeygenRequest event");

        let preprocess_kskgen_request_filter =
            contract.PreprocessKskgenRequest_filter().watch().await?;
        info!("✓ Subscribed to PreprocessKskgenRequest event");

        let keygen_request_filter = contract.KeygenRequest_filter().watch().await?;
        info!("✓ Subscribed to KeygenRequest event");

        let crsgen_request_filter = contract.CrsgenRequest_filter().watch().await?;
        info!("✓ Subscribed to CrsgenRequest event");

        let kskgen_request_filter = contract.KskgenRequest_filter().watch().await?;
        info!("✓ Subscribed to KskgenRequest event");

        // Convert filters to streams
        let mut preprocess_keygen_request_stream = preprocess_keygen_request_filter.into_stream();
        let mut preprocess_kskgen_request_stream = preprocess_kskgen_request_filter.into_stream();
        let mut keygen_request_stream = keygen_request_filter.into_stream();
        let mut crsgen_request_stream = crsgen_request_filter.into_stream();
        let mut kskgen_request_stream = kskgen_request_filter.into_stream();

        info!("Successfully subscribed to all IHttpz events");

        loop {
            if !running.load(Ordering::SeqCst) {
                info!("HTTPZ event subscription stopping due to shutdown signal");
                break;
            }

            tokio::select! {
                result = preprocess_keygen_request_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::PreprocessKeygenRequest, "PreprocessKeygenRequest".to_string()).await?,
                result = preprocess_kskgen_request_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::PreprocessKskgenRequest, "PreprocessKskgenRequest".to_string()).await?,
                result = keygen_request_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::KeygenRequest, "KeygenRequest".to_string()).await?,
                result = crsgen_request_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::CrsgenRequest, "CrsgenRequest".to_string()).await?,
                result = kskgen_request_stream.next() => Self::handle_event(result, event_tx.clone(), KmsCoreEvent::KskgenRequest, "KskgenRequest".to_string()).await?,
            }
        }

        Ok(())
    }

    /// Helper function to handle event stream results
    async fn handle_event<T>(
        result: Option<Result<(T, Log), alloy_sol_types::Error>>,
        event_tx: mpsc::Sender<KmsCoreEvent>,
        event_constructor: fn(T) -> KmsCoreEvent,
        event_name: String,
    ) -> Result<()> {
        let event = match result {
            Some(Ok((event, _))) => event_constructor(event),
            Some(Err(e)) => {
                return Err(anyhow!("Failed to decode {}: {}", event_name, e));
            }
            None => {
                return Err(anyhow!("Event stream ended for {}", event_name));
            }
        };

        // Simple timeout for event sending
        match tokio::time::timeout(EVENT_TIMEOUT, event_tx.send(event)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(anyhow!("Failed to send {}: {}", event_name, e)),
            Err(_) => Err(anyhow!("Event send timeout for {}", event_name)),
        }
    }
}

impl Drop for EventsAdapter {
    fn drop(&mut self) {
        // Set running to false to signal all tasks to stop
        self.running.store(false, Ordering::SeqCst);

        // Abort all handles immediately without trying to create a runtime
        if let Ok(handles) = self.handles.lock() {
            for handle in handles.iter() {
                handle.abort();
            }
        }
    }
}

impl EventsAdapter {
    /// Graceful shutdown with timeout
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<()> {
        // Signal shutdown
        self.running.store(false, Ordering::SeqCst);

        // Take handles out to avoid deadlock with Drop
        let handles = {
            if let Ok(mut handles) = self.handles.lock() {
                handles.drain(..).collect::<Vec<_>>()
            } else {
                return Err(anyhow!(
                    "Failed to acquire lock for handles during shutdown"
                ));
            }
        };

        if handles.is_empty() {
            return Ok(());
        }

        // Create a future that completes when all handles are done
        let shutdown_future = async {
            for handle in handles {
                if let Err(e) = handle.await {
                    warn!("Task failed during shutdown: {}", e);
                }
            }
        };

        // Wait for handles with timeout
        match tokio::time::timeout(timeout, shutdown_future).await {
            Ok(_) => {
                debug!("All event handlers shut down gracefully");
                Ok(())
            }
            Err(_) => {
                warn!("Shutdown timed out, forcing abort");
                // No need to abort handles here as Drop will handle it
                Err(anyhow!("Shutdown timed out"))
            }
        }
    }
}
