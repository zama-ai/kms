use ethers::prelude::*;
use ethers::utils::to_checksum;
use gateway::common::provider::get_provider;
use gateway::config::telemetry::init_tracing;
use gateway::config::{GatewayConfig, Settings};
use gateway::events::manager::DecryptionEventPublisher;
use gateway::events::manager::GatewaySubscriber;
use gateway::events::manager::KmsEventPublisher;
use gateway::events::manager::Publisher;
use gateway::events::manager::ReencryptionEventPublisher;
use gateway::util::height::AtomicBlockHeight;
use gateway::util::wallet::WalletManager;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: GatewayConfig = Settings::builder()
        .path(Some("config/gateway"))
        .build()
        .init_conf()
        .unwrap();
    init_tracing(config.tracing.to_owned()).unwrap();
    intro(&config);
    let provider = get_provider(&config.ethereum).await.unwrap_or_else(|e| {
        tracing::error!("Failed to set up provider: {:?}", e);
        std::process::exit(1);
    });

    let atomic_height = Arc::new(
        AtomicBlockHeight::new(
            &Provider::<Ws>::connect(config.ethereum.wss_url.to_string())
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to connect to provider for atomic height: {:?}", e);
                    std::process::exit(1);
                }),
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to initialize atomic height: {:?}", e);
            std::process::exit(1);
        }),
    );

    // Channel for communication
    let (sender, receiver) = mpsc::channel(100);

    // Create and run DecryptionEventPublisher
    let decryption_publisher =
        DecryptionEventPublisher::new(sender.clone(), &provider, &atomic_height, config.clone())
            .await;
    tokio::spawn(async move {
        if let Err(e) = decryption_publisher.run().await {
            tracing::error!("Failed to run DecryptionEventPublisher: {:?}", e);
        }
    });
    tracing::info!("DecryptionEventPublisher created");

    // Create and run ReencryptionEventPublisher
    let reencrypt_publisher = ReencryptionEventPublisher::new(sender.clone(), config.clone()).await;
    tokio::spawn(async move {
        if let Err(e) = reencrypt_publisher.run().await {
            tracing::error!("Failed to run ReencryptionEventPublisher: {:?}", e);
        }
    });
    tracing::info!("ReencryptionEventPublisher created");

    // Create and run KmsEventPublisher
    let kms_publisher = KmsEventPublisher::new(sender.clone()).await;
    tokio::spawn(async move {
        if let Err(e) = kms_publisher.run().await {
            tracing::error!("Failed to run KmsEventPublisher: {:?}", e);
        }
    });
    tracing::info!("KmsEventPublisher created");

    // Create and run GatewaySubscriber
    let subscriber =
        GatewaySubscriber::new(Arc::new(Mutex::new(receiver)), &provider, config.clone()).await;
    subscriber.listen();
    tracing::info!("GatewaySubscriber started");

    // Handle SIGINT and SIGTERM signals for graceful shutdown
    let shutdown_signal = signal::ctrl_c();
    shutdown_signal.await?;
    tracing::info!("Received shutdown signal, exiting...");

    Ok(())
}

fn intro(config: &GatewayConfig) {
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
        "⭐ KMS ASC contract address:",
        config.kms.contract_address,
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
        "🎉 Ethereum chain ID:",
        &config.ethereum.chain_id,
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
}
