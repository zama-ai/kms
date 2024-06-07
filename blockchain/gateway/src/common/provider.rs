use crate::common::config::ethereum_wss_url;
use crate::common::config::test_async_decrypt_address;
use crate::common::provider::k256::ecdsa::SigningKey;
use crate::util::wallet::WalletManager;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::signers::Wallet;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::OnceCell;

abigen!(
    OraclePredeploy,
    "./artifacts/OraclePredeploy.abi",
    event_derives(serde::Deserialize, serde::Serialize)
);

async fn setup_provider(
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    let wallet = WalletManager::default().wallet;
    tracing::info!("Wallet address: {}", wallet.address());
    let provider = Provider::<Ws>::connect(ethereum_wss_url()).await?;
    let provider = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(9000_u64));
    Ok(Arc::new(provider))
}

#[allow(clippy::type_complexity)]
static PROVIDER: Lazy<OnceCell<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>> =
    Lazy::new(OnceCell::new);

#[allow(clippy::map_clone)]
pub async fn get_provider(
) -> Result<Arc<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>, Box<dyn Error>> {
    PROVIDER.get_or_try_init(setup_provider).await.cloned()
}

async fn setup_contract(
) -> Result<Arc<OraclePredeploy<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>, Box<dyn Error>>
{
    let provider = get_provider().await?;
    let contract = OraclePredeploy::new(test_async_decrypt_address(), Arc::clone(&provider));
    Ok(Arc::new(contract))
}

#[allow(clippy::type_complexity)]
static CONTRACT: Lazy<
    OnceCell<Arc<OraclePredeploy<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>>,
> = Lazy::new(OnceCell::new);

pub async fn get_contract(
) -> Result<Arc<OraclePredeploy<SignerMiddleware<Provider<Ws>, Wallet<SigningKey>>>>, Box<dyn Error>>
{
    CONTRACT.get_or_try_init(setup_contract).await.cloned()
}
