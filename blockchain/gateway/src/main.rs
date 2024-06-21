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
use std::sync::Arc;
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
    let (tx, rx) = mpsc::channel(100);

    // Create DecryptionEventPublisher
    let decryption_publisher =
        DecryptionEventPublisher::new(tx.clone(), &provider, &atomic_height, config.clone()).await;
    tracing::info!("DecryptionEventPublisher created");

    // Create KmsEventPublisher
    let kms_publisher = KmsEventPublisher::new(tx.clone()).await;
    tracing::info!("KmsEventPublisher created");

    // Create ReencryptionEventPublisher
    let reencryption_publisher = ReencryptionEventPublisher::new(tx.clone()).await;
    tracing::info!("ReencryptionEventPublisher created");

    // Create and start GatewaySubscriber
    let subscriber = GatewaySubscriber::new(Arc::new(Mutex::new(rx)), &provider, config).await;
    subscriber.listen();
    tracing::info!("GatewaySubscriber started");

    // Start the KmsEventPublisher
    kms_publisher.run().await?;
    tracing::info!("KmsEventPublisher started");

    // Start the ReencryptionEventPublisher
    reencryption_publisher.run().await?;
    tracing::info!("ReencryptionEventPublisher started");

    // Start the DecryptionEventPublisher
    decryption_publisher.run().await?;
    tracing::info!("DecryptionEventPublisher started");

    /*
    let event_manager = EventManager::new(&provider, &atomic_height, config);
    Arc::new(event_manager).run().await.unwrap_or_else(|e| {
        error!("Failed to run event manager: {:?}", e);
        std::process::exit(1);
    });
     */

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
        "🤝 Relayer address:",
        to_checksum(&config.ethereum.relayer_address, None),
        width = width
    );
    tracing::info!(
        "{:<width$}{}",
        "🤝 Storage URL:",
        &config.storage.url,
        width = width
    );
}
