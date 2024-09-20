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
use events::kms::ZkpResponseValues;
use kms_lib::kms::Eip712DomainMsg;
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
        false => Arc::new(KmsBlockchainImpl::new_from_config(config.clone()).await?),
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
    async fn decrypt(
        &self,
        typed_cts: Vec<(Vec<u8>, FheType, Vec<u8>)>,
        eip712_domain: Eip712DomainMsg,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)>;

    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        client_address: String,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>>;

    async fn zkp(
        &self,
        client_address: String,
        caller_address: String,
        ct_proof: Vec<u8>,
        max_num_bits: u32,
        chain_id: U256,
    ) -> anyhow::Result<Vec<ZkpResponseValues>>;
}
