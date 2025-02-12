use alloy::{primitives::Address, providers::Provider};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::{
    core::wallet::KmsWallet,
    error::Result,
    gw_l2_adapters::{
        decryption::DecryptionAdapter,
        events::{EventsAdapter, KmsCoreEvent},
    },
};

/// Core KMS connector that handles all interactions with L2
pub struct KmsCoreConnector<P: Provider + Clone> {
    events: EventsAdapter,
    #[allow(dead_code)] // TODO: remove when KMS Core adapter is ready
    decryption: DecryptionAdapter<P>,
}

impl<P: Provider + Clone + 'static> KmsCoreConnector<P> {
    /// Creates a new KMS Core connector
    pub fn new(
        provider: Arc<P>,
        wallet: KmsWallet,
        decryption_manager: Address,
        httpz: Address,
        channel_size: usize,
        rpc_url: String,
    ) -> (Self, mpsc::Receiver<KmsCoreEvent>) {
        let (event_tx, event_rx) = mpsc::channel(channel_size);

        let events = EventsAdapter::new(rpc_url, decryption_manager, httpz, event_tx);

        let decryption = DecryptionAdapter::new(decryption_manager, provider, wallet);

        let connector = Self { events, decryption };

        (connector, event_rx)
    }

    /// Start the connector
    pub async fn start(&mut self, _event_rx: mpsc::Receiver<KmsCoreEvent>) -> Result<()> {
        info!("Starting KMS Core Connector...");

        // Initialize event subscriptions
        self.events.initialize().await?;

        Ok(())
    }

    /// Stop the connector
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping KMS Core Connector...");

        // Stop event subscriptions
        self.events.stop();

        Ok(())
    }
}
