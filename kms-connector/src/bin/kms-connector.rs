use alloy::providers::Provider;
use alloy_provider::{ProviderBuilder, WsConnect};
use kms_connector::{
    core::{config::Config, connector::KmsCoreConnector, wallet::KmsWallet},
    error::Result,
    kms_core_adapter::service::KmsServiceImpl,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::broadcast,
};
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Default WebSocket connection URL
const DEFAULT_GWL2_URL: &str = "ws://localhost:8545";
const DEFAULT_KMS_CORE_URL: &str = "http://localhost:8080";
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Keep trying to connect to the RPC endpoint indefinitely
async fn connect_with_retry(rpc_url: &str) -> Arc<impl Provider + Clone + 'static> {
    loop {
        info!(
            "Attempting to connect to Gateway L2 RPC endpoint: {}",
            rpc_url
        );
        let ws = WsConnect::new(rpc_url);
        match ProviderBuilder::new().on_ws(ws).await {
            Ok(provider) => {
                info!("Connected to Gateway L2 RPC endpoint");
                return Arc::new(provider);
            }
            Err(e) => {
                error!(
                    "Failed to connect to Gateway L2 RPC endpoint: {}, retrying in {:?}...",
                    e, RETRY_DELAY
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}

/// Run the connector with automatic reconnection
async fn run_connector(
    config: Config,
    gw_provider: Arc<impl Provider + Clone + 'static>,
    shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    // Initialize wallet
    let wallet = KmsWallet::from_mnemonic(&config.mnemonic, Some(config.chain_id))?;
    info!(
        "Wallet created successfully with address: {:#x}",
        wallet.address()
    );

    info!(
        "Using contracts:\n\tIDecryptionManager: {}\n\tIHttpz: {}",
        config.decryption_manager_address, config.httpz_address
    );

    // Initialize KMS service
    let kms_core_endpoint = config
        .kms_core_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_KMS_CORE_URL.to_string());
    info!("Connecting to KMS-core at {}", kms_core_endpoint);
    let kms_provider = Arc::new(KmsServiceImpl::new(&kms_core_endpoint));

    // Create and start connector
    let (mut connector, event_rx) = KmsCoreConnector::new(
        gw_provider.clone(),
        wallet.clone(),
        config,
        kms_provider.clone(),
        shutdown_rx.resubscribe(),
    );

    // Start the connector
    connector.start(event_rx).await?;

    // Stop the connector gracefully
    connector.stop().await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: substitute with existing KMS-Core implementation
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("Starting KMS Connector...");

    // Load config
    let config = Config::from_file("./kms-connector/config.toml")?;

    // Get RPC URL with default
    let gw_endpoint = config
        .gwl2_url
        .clone()
        .unwrap_or_else(|| DEFAULT_GWL2_URL.to_string());

    // Initialize WebSocket connection with retry
    let provider = connect_with_retry(&gw_endpoint).await;

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel(16);

    // Spawn signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let shutdown_tx_sig = shutdown_tx.clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM signal");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT signal");
            }
        }
        let _ = shutdown_tx_sig.send(());
    });

    // Run the connector with automatic reconnection
    let connector_handle = tokio::spawn(run_connector(config, provider, shutdown_rx));

    // Wait for connector to finish
    match connector_handle.await {
        Ok(Ok(())) => info!("Connector shutdown successfully"),
        Ok(Err(e)) => error!("Connector error during shutdown: {}", e),
        Err(e) => error!("Failed to join connector task: {}", e),
    }

    info!("KMS Connector stopped successfully");
    Ok(())
}
