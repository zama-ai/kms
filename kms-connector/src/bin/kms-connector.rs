use alloy::{primitives::Address, providers::ProviderBuilder, transports::ws::WsConnect};
use kms_connector::{
    core::{config::Config, connector::KmsCoreConnector, wallet::KmsWallet},
    error::Result,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Default WebSocket connection URL
const DEFAULT_WS_URL: &str = "ws://localhost:8545";
const DEFAULT_CHANNEL_SIZE: usize = 1000;
const RETRY_DELAY: Duration = Duration::from_secs(5);

async fn connect_with_retry(rpc_url: &str) -> Result<Arc<impl alloy::providers::Provider + Clone>> {
    loop {
        info!("Attempting to connect to {}", rpc_url);
        let ws = WsConnect::new(rpc_url);
        match ProviderBuilder::new().on_ws(ws).await {
            Ok(provider) => {
                info!("Connected to RPC endpoint");
                return Ok(Arc::new(provider));
            }
            Err(e) => {
                error!(
                    "Failed to connect to RPC endpoint: {}, retrying in {:?}...",
                    e, RETRY_DELAY
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
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
    let config = Config::from_file("config.example.toml")?;

    // Get RPC URL with default
    let rpc_url = config.rpc_url.clone().unwrap_or(DEFAULT_WS_URL.to_string());

    // Initialize WebSocket connection with retry
    let provider = connect_with_retry(&rpc_url).await?;

    // Initialize wallet
    let wallet = KmsWallet::from_mnemonic(&config.mnemonic, Some(config.chain_id))?;

    info!("Wallet created successfully");

    // Get contract addresses
    let decryption_manager_address = Address::from_str(&config.decryption_manager_address)
        .map_err(|e| {
            kms_connector::error::Error::Config(format!(
                "Invalid decryption manager address: {}",
                e
            ))
        })?;
    let httpz_address = Address::from_str(&config.httpz_address).map_err(|e| {
        kms_connector::error::Error::Config(format!("Invalid HTTPZ address: {}", e))
    })?;

    info!(
        "Using contracts:\n\tDecryption Manager: {}\n\tHTTPZ: {}",
        decryption_manager_address, httpz_address
    );

    // Create and start connector
    let (mut connector, event_rx) = KmsCoreConnector::new(
        provider,
        wallet,
        decryption_manager_address,
        httpz_address,
        config.channel_size.unwrap_or(DEFAULT_CHANNEL_SIZE),
        rpc_url,
    );

    // Start the connector
    connector.start(event_rx).await?;

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down KMS Connector...");
    connector.stop().await?;

    info!("KMS Connector stopped successfully");
    Ok(())
}
