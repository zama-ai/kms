use ethers::prelude::*;
use ethers::utils::to_checksum;
use gateway::config::{init_conf_with_trace_gateway, GatewayConfig};
use gateway::events::manager::start_decryption_publisher;
use gateway::events::manager::start_http_server;
use gateway::events::manager::{start_gateway, start_kms_event_publisher};
use gateway::util::wallet::WalletManager;
use tokio::signal;
use tokio::sync::mpsc::{self};

#[tokio::main]
/// The main entry point for the gateway application.
///
/// This function sets up the gateway configuration, creates communication channels,
/// and starts the necessary components like the decryption event publisher, KMS
/// event publisher, and the HTTP server. It also handles graceful shutdown
/// when a shutdown signal (SIGINT or SIGTERM) is received.
async fn main() -> anyhow::Result<()> {
    // Load gateway configuration
    let config: GatewayConfig = init_conf_with_trace_gateway(
        std::env::var("GATEWAY_CONFIG")
            .unwrap_or_else(|_| "config/gateway.toml".to_string())
            .as_str(),
    )
    .await?;
    // Some starting logs
    print_intro(&config);
    // Channel for communication
    let (sender, receiver) = mpsc::channel(100);
    start_decryption_publisher(sender.clone(), config.clone()).await;
    start_kms_event_publisher(sender.clone()).await;
    let url_server = config.api_url.clone();
    let http_handle =
        tokio::spawn(async move { start_http_server(url_server, sender.clone()).await });
    let gateway_handle = tokio::spawn(async move { start_gateway(receiver, config).await });

    // Handle SIGINT and SIGTERM signals for graceful shutdown
    let shutdown_signal = signal::ctrl_c();
    shutdown_signal.await?;
    tracing::info!("Received shutdown signal, exiting...");
    http_handle.abort();
    gateway_handle.abort();
    Ok(())
}

fn print_intro(config: &GatewayConfig) {
    // Welcome message
    tracing::info!("🚀 ZAMA Gateway Service 🚀");
    tracing::info!("🔥 Initializing gateway service...");
    tracing::info!("📡 Connecting to Ethereum and KMS networks...");
    let width = 30;

    tracing::info!("{:<width$}{}", "🌐 Mode:", config.mode, width = width);

    tracing::info!(
        "{:<width$}{}",
        "🔗 Ethereum network URL:",
        config.ethereum.wss_url,
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "⭐ KMS ASC address:",
        config.kms.asc_address,
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "⭐ KMS CSC address:",
        config.kms.csc_address,
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "🔐 FHE library address:",
        to_checksum(&config.ethereum.fhe_lib_address, None),
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "🎉 Oracle predeploy address:",
        to_checksum(&config.ethereum.oracle_predeploy_address, None),
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "🎉 Coprocessor URL:",
        &config.ethereum.coprocessor_url,
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "🤝 Relayer address:",
        to_checksum(&WalletManager::default().wallet.address(), None),
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "🤝 Storage URL:",
        &config.storage.url,
        width = width
    );
    if config.ethereum.gas_limit.is_some() {
        tracing::info!(
            "{:<width$}{:?}",
            "⛽ Ethereum gas limit:",
            &config.ethereum.gas_limit,
            width = width
        );
    }
    if config.ethereum.gas_price.is_some() {
        tracing::info!(
            "{:<width$}{:?}",
            "⛽ Ethereum gas price:",
            &config.ethereum.gas_price,
            width = width
        );
    } else {
        tracing::info!(
            "{:<width$}{:?}",
            "⛽ Ethereum base gas:",
            &config.ethereum.base_gas,
            width = width
        );
        tracing::info!(
            "{:<width$}{:?}",
            "⛽ Ethereum escalator %:",
            &config.ethereum.gas_escalator_increase,
            width = width
        );
    }
}
