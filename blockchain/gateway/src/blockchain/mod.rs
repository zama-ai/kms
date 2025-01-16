pub mod ciphertext_provider;
pub mod handlers;
pub mod kms_blockchain;
pub mod mockchain;
use crate::blockchain::kms_blockchain::KmsBlockchainImpl;
use crate::blockchain::mockchain::MockchainImpl;
use crate::config::GatewayConfig;
use crate::config::KeyUrlResponseValues;
use crate::events::manager::DecryptionEvent;
use crate::events::manager::KmsEventWithHeight;
use crate::state::file_state::GatewayState;
use crate::state::GatewayEventState;
use async_trait::async_trait;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::FheType;
use events::kms::ReencryptResponseValues;
use events::HexVectorList;
use kms_grpc::kms::v1::Eip712DomainMsg;
use std::sync::Arc;
use tokio::sync::OnceCell;

static BLOCKCHAIN_INSTANCE: Lazy<OnceCell<Arc<dyn Blockchain>>> = Lazy::new(OnceCell::new);

async fn setup_blockchain(
    config: &GatewayConfig,
    state: GatewayState,
) -> anyhow::Result<Arc<dyn Blockchain>> {
    let strategy: Arc<dyn Blockchain> = match config.debug {
        true => {
            tracing::info!("🐛 Running in debug mode with a mocked KMS backend 🐛");
            Arc::new(MockchainImpl)
        }
        false => Arc::new(KmsBlockchainImpl::new_from_config(config.clone(), state).await?),
    };

    Ok(strategy)
}

pub(super) async fn blockchain_impl(
    config: &GatewayConfig,
    state: GatewayState,
) -> Arc<dyn Blockchain> {
    BLOCKCHAIN_INSTANCE
        .get_or_init(|| async {
            setup_blockchain(config, state)
                .await
                .expect("Failed to set up decryption strategy")
        })
        .await
        .clone()
}

#[async_trait]
pub(crate) trait KmsEventSubscriber: Send + Sync {
    async fn receive(&self, event: KmsEventWithHeight) -> anyhow::Result<()>;
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
pub(crate) trait Blockchain: KmsEventSubscriber {
    async fn decrypt(
        &self,
        event: DecryptionEvent,
        typed_cts: Vec<(Vec<u8>, FheType, Vec<u8>)>,
        eip712_domain: Eip712DomainMsg,
        asc_address: String,
        acl_address: String,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)>;

    async fn decrypt_catchup(
        &self,
        event: DecryptionEvent,
        event_state: GatewayEventState,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)>;

    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        client_address: String,
        enc_key: Vec<u8>,
        external_ct_handle: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
        salt: Option<Vec<u8>>,
        asc_address: String,
        acl_address: String,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>>;

    async fn verify_proven_ct(
        &self,
        client_address: String,
        contract_address: String,
        key_id_str: String,
        crs_id_str: String,
        ct_proof: Vec<u8>,
        eip712_domain: Eip712DomainMsg,
        asc_address: String,
        acl_address: String,
    ) -> anyhow::Result<HexVectorList>;

    async fn keyurl(&self) -> anyhow::Result<KeyUrlResponseValues>;
}
