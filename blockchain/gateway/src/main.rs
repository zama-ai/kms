use ethers::prelude::*;
use ethers::utils::to_checksum;
use eyre::Result;
use gateway::common::config::ethereum_wss_url;
use gateway::common::config::fhe_lib_address;
use gateway::common::config::kms_contract_address;
use gateway::common::config::mode;
use gateway::common::config::oracle_predeploy_address;
use gateway::common::config::relayer_address;
use gateway::common::config::tendermint_node_addr;
use gateway::common::provider::get_provider;

use gateway::common::config::trace_level;
use gateway::events::manager::EventManager;
use gateway::util::height::AtomicBlockHeight;
use std::sync::Arc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber with env filter
    tracing_subscriber::fmt()
        .with_max_level(trace_level())
        .with_line_number(true)
        .with_file(true)
        .with_thread_names(true)
        .with_target(true)
        .init();

    intro();
    let provider = get_provider().await.unwrap_or_else(|e| {
        error!("Failed to set up provider: {:?}", e);
        std::process::exit(1);
    });

    let atomic_height = Arc::new(
        AtomicBlockHeight::new(
            &Provider::<Ws>::connect(ethereum_wss_url())
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

    let event_manager = EventManager::new(&provider, &atomic_height);
    Arc::new(event_manager).run().await.unwrap_or_else(|e| {
        error!("Failed to run event manager: {:?}", e);
        std::process::exit(1);
    });

    Ok(())
}

fn intro() {
    // Welcome message
    info!("🚀 ZAMA Gateway Service 🚀");
    info!("🔥 Initializing gateway service...");
    info!("📡 Connecting to Ethereum and KMS networks...");
    let width = 30;

    info!("{:<width$}{}", "🌐 Mode:", mode(), width = width);

    info!(
        "{:<width$}{}",
        "🔗 Ethereum network URL:",
        ethereum_wss_url(),
        width = width
    );
    info!(
        "{:<width$}{}",
        "🍬 KMS Tendermint node URL:",
        tendermint_node_addr(),
        width = width
    );
    info!(
        "{:<width$}{}",
        "⭐ KMS ASC contract address:",
        kms_contract_address(),
        width = width
    );
    info!(
        "{:<width$}{}",
        "🔐 FHE library address:",
        to_checksum(&fhe_lib_address(), None),
        width = width
    );
    info!(
        "{:<width$}{}",
        "🎉 Oracle predeploy address:",
        to_checksum(&oracle_predeploy_address(), None),
        width = width
    );
    info!(
        "{:<width$}{}",
        "🤝 Relayer address:",
        to_checksum(&relayer_address(), None),
        width = width
    );
}
