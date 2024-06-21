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

abigen!(
    GatewayContract,
    "./artifacts/GatewayContract.abi",
    event_derives(serde::Deserialize, serde::Serialize)
);
async fn setup_provider(
    config: &EthereumConfig,
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    let wallet = WalletManager::default().wallet;
    let provider = Provider::<Ws>::connect(config.wss_url.to_string()).await?;
    let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
    Ok(Arc::new(provider))
}

#[allow(clippy::type_complexity)]
static PROVIDER: Lazy<OnceCell<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>> =
    Lazy::new(OnceCell::new);

#[allow(clippy::map_clone)]
pub async fn get_provider(
    config: &EthereumConfig,
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    PROVIDER
        .get_or_try_init(move || setup_provider(config))
        .await
        .cloned()
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
