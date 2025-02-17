use alloy::{
    primitives::{Address, Bytes},
    providers::Provider,
};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tonic::Request;
use tracing::{error, info};

/// Default channel size for event processing
const DEFAULT_CHANNEL_SIZE: usize = 1000;

use crate::{
    core::wallet::KmsWallet,
    error::Result,
    gw_l2_adapters::{
        decryption::DecryptionAdapter,
        events::{EventsAdapter, KmsCoreEvent},
    },
    kms_core_adapter::service::{
        kms::v1::{
            DecryptionRequest, DecryptionRequestPayload, ReencryptionRequest,
            ReencryptionRequestPayload, RequestId, TypedCiphertext,
        },
        KmsService, KmsServiceImpl,
    },
};

use super::config::Config;

/// Core KMS connector that handles all interactions with L2
pub struct KmsCoreConnector<P: Provider + Clone> {
    events: EventsAdapter,
    decryption: DecryptionAdapter<P>,
    kms_client: Arc<KmsServiceImpl>,
    shutdown: Option<broadcast::Receiver<()>>,
}

impl<P: Provider + Clone + 'static> KmsCoreConnector<P> {
    /// Creates a new KMS Core connector
    pub fn new(
        provider: Arc<P>,
        wallet: KmsWallet,
        config: Config,
        kms_client: Arc<KmsServiceImpl>,
        shutdown: broadcast::Receiver<()>,
    ) -> (Self, mpsc::Receiver<KmsCoreEvent>) {
        let (event_tx, event_rx) =
            mpsc::channel(config.channel_size.unwrap_or(DEFAULT_CHANNEL_SIZE));

        let decryption_manager = Address::from_str(&config.decryption_manager_address)
            .expect("Invalid decryption manager address");
        let httpz = Address::from_str(&config.httpz_address).expect("Invalid HTTPZ address");

        let rpc_url = config.gwl2_url;
        let events = EventsAdapter::new(rpc_url, decryption_manager, httpz, event_tx);
        let decryption = DecryptionAdapter::new(decryption_manager, provider, wallet);

        let connector = Self {
            events,
            decryption,
            kms_client,
            shutdown: Some(shutdown),
        };

        (connector, event_rx)
    }

    /// Handle a decryption request (both public and user)
    async fn handle_decryption(
        &self,
        request_id: String,
        ciphertext_handles: Vec<Vec<u8>>,
        user_address: Option<Vec<u8>>,
    ) -> Result<()> {
        match user_address {
            // Public decryption
            None => {
                let request = Request::new(DecryptionRequest {
                    request_id: Some(RequestId {
                        request_id: request_id.clone(),
                    }),
                    domain: None,
                    payload: Some(DecryptionRequestPayload {
                        ciphertext_handles,
                        acl_address: String::new(),
                    }),
                });

                let response = self.kms_client.request_decryption(request).await?;
                let decryption_response = response.into_inner();

                if let Some(payload) = decryption_response.payload {
                    // Convert Vec<u8> to Bytes for the result
                    let result = Bytes::from(payload.decrypted_result);
                    // Take first signature (we expect only one for now)
                    let signature = payload
                        .signatures
                        .first()
                        .map(|sig| Bytes::from(sig.clone()))
                        .unwrap_or_default();

                    // Send response back to L2
                    info!(
                        "Sending public decryption response for request {}",
                        request_id
                    );
                    self.decryption
                        .send_public_decryption_response(
                            request_id.parse().unwrap(),
                            result,
                            signature,
                        )
                        .await?;
                }
            }
            // User decryption
            Some(user_addr) => {
                let request = Request::new(ReencryptionRequest {
                    request_id: Some(RequestId {
                        request_id: request_id.clone(),
                    }),
                    domain: None,
                    payload: Some(ReencryptionRequestPayload {
                        enc_key: user_addr,
                        ciphertext: Some(TypedCiphertext {
                            bytes: ciphertext_handles.first().cloned().unwrap_or_default(),
                            fhe_type: 0, // Default FHE type
                        }),
                        ciphertext_digest: vec![],
                    }),
                });

                let response = self.kms_client.request_reencryption(request).await?;
                let reencryption_response = response.into_inner();

                if let Some(payload) = reencryption_response.payload {
                    // Get bytes from TypedCiphertext
                    let result = payload
                        .ciphertext
                        .map(|ct| Bytes::from(ct.bytes))
                        .unwrap_or_default();

                    // Take first signature (we expect only one for now)
                    let signature = payload
                        .signatures
                        .first()
                        .map(|sig| Bytes::from(sig.clone()))
                        .unwrap_or_default();

                    // Send response back to L2
                    info!(
                        "Sending user decryption response for request {}",
                        request_id
                    );
                    self.decryption
                        .send_user_decryption_response(
                            request_id.parse().unwrap(),
                            result,
                            signature,
                        )
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Process events from L2
    async fn process_events(&self, mut event_rx: mpsc::Receiver<KmsCoreEvent>) -> Result<()> {
        info!("Starting event processing...");

        let mut shutdown = self.shutdown.as_ref().unwrap().resubscribe();

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    let result = match event {
                        KmsCoreEvent::PublicDecryptionRequest(req) => {
                            info!(
                                "Processing public decryption request {}",
                                req.publicDecryptionId
                            );
                            self.handle_decryption(
                                req.publicDecryptionId.to_string(),
                                req.ctHandleCiphertext128Pairs
                                    .into_iter()
                                    .map(|pair| pair.ctHandle.to_be_bytes::<32>().to_vec())
                                    .collect(),
                                None,
                            )
                            .await
                        }
                        KmsCoreEvent::UserDecryptionRequest(req) => {
                            info!(
                                "Processing user decryption request {}",
                                req.userDecryptionId
                            );
                            // Extract first ciphertext handle from pairs
                            let ciphertext_handle = req.ctHandleContractPairs
                                .first()
                                .map(|pair| pair.ciphertextHandle.to_be_bytes::<32>().to_vec())
                                .unwrap_or_default();

                            self.handle_decryption(
                                req.userDecryptionId.to_string(),
                                vec![ciphertext_handle],
                                Some(req.userAddress.to_vec()),
                            )
                            .await
                        }
                        _ => Ok(()), // Ignore other events for now
                    };

                    if let Err(e) = result {
                        error!("Failed to process event: {}", e);
                        // Continue processing other events
                    }
                }
                _ = shutdown.recv() => {
                    info!("Received shutdown signal in event processor");
                    break;
                }
            }
        }

        info!("Event processing stopped");
        Ok(())
    }

    /// Start the connector
    pub async fn start(&mut self, event_rx: mpsc::Receiver<KmsCoreEvent>) -> Result<()> {
        info!("Starting KMS Core Connector...");

        // Initialize event subscriptions
        self.events.initialize().await?;

        // Keep trying to initialize KMS client
        loop {
            match self.kms_client.initialize().await {
                Ok(_) => {
                    info!("Successfully connected to KMS-core");
                    break;
                }
                Err(e) => {
                    error!("Failed to connect to KMS-core: {}, retrying...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }

            // Check for shutdown signal
            if let Some(shutdown) = &self.shutdown {
                if shutdown.resubscribe().try_recv().is_ok() {
                    info!("Received shutdown signal while trying to connect to KMS-core");
                    return Ok(());
                }
            }
        }

        // Process events
        self.process_events(event_rx).await?;

        Ok(())
    }

    /// Stop the connector and clean up resources
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping KMS Core Connector...");

        // 1. Signal shutdown through broadcast channel first to stop new events
        if let Some(shutdown) = self.shutdown.take() {
            drop(shutdown);
        }

        // 2. Stop KMS client to prevent new operations
        self.kms_client.stop();

        // 3. Stop event adapter and wait for all tasks to complete
        if let Err(e) = self.events.stop().await {
            error!("Error during event adapter shutdown: {}", e);
            // Continue shutdown process despite error
        }

        info!("KMS Core Connector stopped");
        Ok(())
    }
}
