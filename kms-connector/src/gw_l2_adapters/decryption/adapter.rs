use alloy::{
    primitives::{Address, Bytes, U256},
    providers::Provider,
};
use std::sync::Arc;

use crate::{
    core::wallet::KmsWallet,
    error::{Error, Result},
    gw_l2_contracts::decryption::IDecryptionManager,
};

/// Adapter for decryption operations
pub struct DecryptionAdapter<P: Provider + Clone> {
    decryption_address: Address,
    provider: Arc<P>,
    wallet: Arc<KmsWallet>,
}

impl<P: Provider + Clone> DecryptionAdapter<P> {
    /// Create a new decryption adapter
    pub fn new(decryption_address: Address, provider: Arc<P>, wallet: KmsWallet) -> Self {
        Self {
            decryption_address,
            provider,
            wallet: Arc::new(wallet),
        }
    }

    /// Send a public decryption response
    pub async fn send_public_decryption_response(
        &self,
        id: U256,
        result: Bytes,
        signature: Bytes,
    ) -> Result<()> {
        let contract = IDecryptionManager::new(self.decryption_address, self.provider.clone());

        // Create and send transaction
        let call = contract.publicDecryptionResponse(id, result, signature);
        let _ = call
            .from(self.wallet.address())
            .send()
            .await
            .map_err(|e| Error::Contract(e.to_string()))?;

        Ok(())
    }

    /// Send a user decryption response
    pub async fn send_user_decryption_response(
        &self,
        id: U256,
        result: Bytes,
        signature: Bytes,
    ) -> Result<()> {
        let contract = IDecryptionManager::new(self.decryption_address, self.provider.clone());

        // Create and send transaction
        let call = contract.userDecryptionResponse(id, result, signature);
        let _ = call
            .from(self.wallet.address())
            .send()
            .await
            .map_err(|e| Error::Contract(e.to_string()))?;

        Ok(())
    }
}
