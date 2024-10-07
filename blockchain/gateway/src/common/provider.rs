use crate::common::provider::k256::ecdsa::SigningKey;
use crate::config::EthereumConfig;
use crate::util::wallet::WalletManager;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::signers::Wallet;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tokio::time::{sleep, Duration};

abigen!(
    GatewayContract,
    "./artifacts/GatewayContract.abi",
    event_derives(serde::Deserialize, serde::Serialize)
);

// Setup the provider with reconnection logic for the first-time connection
async fn setup_provider(
    config: &EthereumConfig,
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    reconnect(config, 5).await // Retry up to 5 times for initial connection
}

#[allow(clippy::type_complexity)]
static PROVIDER: Lazy<OnceCell<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>> =
    Lazy::new(OnceCell::new);

#[allow(clippy::map_clone)]
pub async fn get_provider(
    config: &EthereumConfig,
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    // Setup the provider and spawn the monitoring task once the provider is created
    let provider = PROVIDER
        .get_or_try_init(move || setup_provider(config))
        .await?
        .clone();

    // Spawn the monitoring task here, is provider is stopped, exit.
    spawn_monitor_provider(Arc::clone(&provider));

    Ok(provider)
}

// Function to monitor the provider and exit the program on connection loss
async fn monitor_provider(provider: Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>) {
    loop {
        match provider.get_block_number().await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(
                    "Connection lost. The provider is no longer reachable. 
                Please ensure that the provider is running and restart the gateway. 
                Gracefully handling reconnection is currently not implemented. 
                Reconnection requires re-subscribing to the necessary event listeners, 
                which is a TODO for future development.
                Error:  {:?}",
                    e
                );

                std::process::exit(1);
            }
        }
        sleep(Duration::from_secs(10)).await; // Polling interval for checking connection
    }
}

// Function to spawn the monitoring task
fn spawn_monitor_provider(provider: Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>) {
    tokio::spawn(monitor_provider(provider));
}

async fn reconnect(
    config: &EthereumConfig,
    max_attempts: u32,
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    let mut attempts = 0;
    let wallet = WalletManager::default().wallet;

    loop {
        if attempts >= max_attempts {
            tracing::error!("Max reconnection attempts reached.");
            std::process::exit(1); // Exit if reconnection fails after max attempts
        }

        match Provider::<Ws>::connect(config.wss_url.to_string()).await {
            Ok(provider) => {
                let provider =
                    SignerMiddleware::new(provider.clone(), wallet.with_chain_id(config.chain_id));
                tracing::info!("Successfully connected to the WebSocket provider.");
                return Ok(Arc::new(provider));
            }
            Err(e) => {
                attempts += 1;
                let backoff = Duration::from_secs(2_u64.pow(attempts));
                tracing::warn!(
                    "Failed to connect to WebSocket provider (attempt {}): {:?}. Retrying in {:?} seconds.",
                    attempts,
                    e,
                    backoff.as_secs()
                );
                sleep(backoff).await;
            }
        }
    }
}

async fn setup_contract(
    config: &EthereumConfig,
) -> Result<Arc<GatewayContract<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>, Box<dyn Error>>
{
    let provider = get_provider(config).await?;
    let contract = GatewayContract::new(config.test_async_decrypt_address, Arc::clone(&provider));
    Ok(Arc::new(contract))
}

#[allow(clippy::type_complexity)]
static CONTRACT: Lazy<
    OnceCell<Arc<GatewayContract<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>>,
> = Lazy::new(OnceCell::new);

pub async fn get_contract(
    config: &EthereumConfig,
) -> Result<Arc<GatewayContract<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>, Box<dyn Error>>
{
    CONTRACT
        .get_or_try_init(move || setup_contract(config))
        .await
        .cloned()
}
