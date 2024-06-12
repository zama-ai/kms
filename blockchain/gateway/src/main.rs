use ethers::prelude::*;
use ethers::utils::to_checksum;
use eyre::Result;
use gateway::common::provider::get_provider;
use gateway::config::telemetry::init_tracing;
use gateway::config::{GatewayConfig, Settings};
use gateway::events::manager::EventManager;
use gateway::util::height::AtomicBlockHeight;
use std::sync::Arc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    let config: GatewayConfig = Settings::builder()
        .path(Some("config/gateway"))
        .build()
        .init_conf()
        .unwrap();
    init_tracing(config.tracing.to_owned()).unwrap();
    intro(&config);
    let provider = get_provider(&config.ethereum).await.unwrap_or_else(|e| {
        error!("Failed to set up provider: {:?}", e);
        std::process::exit(1);
    });

    let atomic_height = Arc::new(
        AtomicBlockHeight::new(
            &Provider::<Ws>::connect(config.ethereum.wss_url.to_string())
                .await
                .unwrap_or_else(|e| {
                    error!("Failed to connect to provider for atomic height: {:?}", e);
                    std::process::exit(1);
                }),
        )
        .await
        .unwrap_or_else(|e| {
            error!("Failed to initialize atomic height: {:?}", e);
            std::process::exit(1);
        }),
    );

    let event_manager = EventManager::new(&provider, &atomic_height, config);
    Arc::new(event_manager).run().await.unwrap_or_else(|e| {
        error!("Failed to run event manager: {:?}", e);
        std::process::exit(1);
    });

    Ok(())
}

fn intro(config: &GatewayConfig) {
    // Welcome message
    info!("🚀 ZAMA Gateway Service 🚀");
    info!("🔥 Initializing gateway service...");
    info!("📡 Connecting to Ethereum and KMS networks...");
    let width = 30;

    info!("{:<width$}{}", "🌐 Mode:", config.mode, width = width);

    info!(
        "{:<width$}{}",
        "🔗 Ethereum network URL:",
        config.ethereum.wss_url,
        width = width
    );
    info!(
        "{:<width$}{}",
        "🍬 KMS Tendermint node URL:",
        config.kms.tendermint_node_addr,
        width = width
    );
    info!(
        "{:<width$}{}",
        "⭐ KMS ASC contract address:",
        config.kms.contract_address,
        width = width
    );
    info!(
        "{:<width$}{}",
        "🔐 FHE library address:",
        to_checksum(&config.ethereum.fhe_lib_address, None),
        width = width
    );
    info!(
        "{:<width$}{}",
        "🎉 Oracle predeploy address:",
        to_checksum(&config.ethereum.oracle_predeploy_address, None),
        width = width
    );
    info!(
        "{:<width$}{}",
        "🤝 Relayer address:",
        to_checksum(&config.ethereum.relayer_address, None),
        width = width
    );
}
