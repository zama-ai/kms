pub mod ciphertext_provider;
pub mod handlers;
pub mod kms_blockchain;
pub mod mockchain;
use crate::blockchain::kms_blockchain::KmsBlockchainImpl;
use crate::blockchain::mockchain::MockchainImpl;
use crate::config::GatewayConfig;
use async_trait::async_trait;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::FheType;
use events::kms::KmsEvent;
use events::kms::ReencryptResponseValues;
use std::sync::Arc;
use tokio::sync::OnceCell;

static BLOCKCHAIN_INSTANCE: Lazy<OnceCell<Arc<dyn Blockchain>>> = Lazy::new(OnceCell::new);

async fn setup_blockchain(config: &GatewayConfig) -> anyhow::Result<Arc<dyn Blockchain>> {
    let debug = config.debug;
    let strategy: Arc<dyn Blockchain> = match debug {
        true => {
            tracing::info!("🐛 Running in debug mode with a mocked KMS backend 🐛");
            Arc::new(MockchainImpl)
        }
        false => Arc::new(KmsBlockchainImpl::new_from_config(config.clone())),
    };

    Ok(strategy)
}

pub(super) async fn blockchain_impl(config: &GatewayConfig) -> Arc<dyn Blockchain> {
    BLOCKCHAIN_INSTANCE
        .get_or_init(|| async {
            setup_blockchain(config)
                .await
                .expect("Failed to set up decryption strategy")
        })
        .await
        .clone()
}

#[async_trait]
pub(crate) trait KmsEventSubscriber: Send + Sync {
    async fn receive(&self, event: KmsEvent) -> anyhow::Result<()>;
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
pub(crate) trait Blockchain: KmsEventSubscriber {
    async fn decrypt(&self, ciphertext: Vec<u8>, fhe_type: FheType) -> anyhow::Result<Token>;

    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        user_address: Vec<u8>,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>>;
}
