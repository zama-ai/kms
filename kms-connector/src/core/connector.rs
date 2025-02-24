use alloy::{
    hex,
    primitives::{Address, Bytes},
    providers::Provider,
};
use bincode;
use kms_grpc::kms::v1::TypedCiphertext;
use kms_grpc::kms::v1::{
    DecryptionRequest, FheType, ReencryptionRequest, ReencryptionRequestPayload, RequestId,
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
    gwl2_adapters::{
        decryption::DecryptionAdapter,
        events::{EventsAdapter, KmsCoreEvent},
    },
    kms_core_adapter::service::{KmsService, KmsServiceImpl},
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

    /// Get string representation of FHE type
    fn fhe_type_to_string(fhe_type: i32) -> &'static str {
        match fhe_type {
            t if t == FheType::Ebool as i32 => "EBOOL",
            t if t == FheType::Euint4 as i32 => "EUINT4",
            t if t == FheType::Euint8 as i32 => "EUINT8",
            t if t == FheType::Euint16 as i32 => "EUINT16",
            t if t == FheType::Euint32 as i32 => "EUINT32",
            t if t == FheType::Euint64 as i32 => "EUINT64",
            t if t == FheType::Euint128 as i32 => "EUINT128",
            t if t == FheType::Euint160 as i32 => "EUINT160",
            t if t == FheType::Euint256 as i32 => "EUINT256",
            t if t == FheType::Euint512 as i32 => "EUINT512",
            t if t == FheType::Euint1024 as i32 => "EUINT1024",
            t if t == FheType::Euint2048 as i32 => "EUINT2048",
            _ => "UNKNOWN",
        }
    }

    /// Extract FHE type from handle bytes
    fn extract_fhe_type_from_handle(bytes: &[u8]) -> i32 {
        // Format: keccak256(keccak256(bundleCiphertext)+index)[0:29] + index + type + version
        // - Last byte (31): Version (currently 0)
        // - Second-to-last byte (30): FHE Type
        // - Third-to-last byte (29): Handle index
        // - Rest (0-28): Hash data
        if bytes.len() >= 32 {
            let type_byte = bytes[30]; // FHE type is at index 30

            if type_byte >= 12 {
                error!("Unknown FHE type byte: {}, must be less than 12", type_byte);
                return FheType::Ebool as i32;
            }

            match type_byte {
                0 => FheType::Ebool as i32,
                1 => FheType::Euint4 as i32,
                2 => FheType::Euint8 as i32,
                3 => FheType::Euint16 as i32,
                4 => FheType::Euint32 as i32,
                5 => FheType::Euint64 as i32,
                6 => FheType::Euint128 as i32,
                7 => FheType::Euint160 as i32,
                8 => FheType::Euint256 as i32,
                9 => FheType::Euint512 as i32,
                10 => FheType::Euint1024 as i32,
                11 => FheType::Euint2048 as i32,
                _ => unreachable!(), // We checked type_byte < 12 above
            }
        } else {
            error!("Handle too short: {} bytes, expected 32 bytes", bytes.len());
            FheType::Ebool as i32
        }
    }

    /// Extract FHE type and log result details
    fn log_and_extract_result<T>(
        _result: &T,
        fhe_type: i32,
        request_id: &str,
        user_addr: Option<&[u8]>,
    ) where
        T: AsRef<[u8]>,
    {
        match user_addr {
            Some(addr) => info!(
                "Reencrypted result type: {} for request {} (user: 0x{})",
                Self::fhe_type_to_string(fhe_type),
                request_id,
                hex::encode(addr)
            ),
            None => info!(
                "Decrypted result type: {} for request {}",
                Self::fhe_type_to_string(fhe_type),
                request_id
            ),
        }
    }

    /// Handle a decryption request (both public and user)
    async fn handle_decryption(
        &self,
        request_id: String,
        ciphertext_data: Vec<(Vec<u8>, Vec<u8>)>, // (handle, ciphertext) pairs
        user_address: Option<Vec<u8>>,
    ) -> Result<()> {
        info!(
            "Processing {} decryption request {} with {} ciphertexts",
            if user_address.is_some() {
                "user"
            } else {
                "public"
            },
            request_id,
            ciphertext_data.len()
        );

        match user_address {
            // TODO: adjust logic as per #2079
            // Public decryption aka decryption
            None => {
                let request = Request::new(DecryptionRequest {
                    ciphertexts: ciphertext_data
                        .into_iter()
                        .map(|(handle, ciphertext)| {
                            let fhe_type = Self::extract_fhe_type_from_handle(&handle);
                            TypedCiphertext {
                                ciphertext,
                                external_handle: handle,
                                fhe_type,
                            }
                        })
                        .collect(),
                    // TODO: change to actual key id once SC interface is updated
                    key_id: Some(RequestId {
                        request_id: request_id.clone(),
                    }),
                    // TODO: to understand how to populate this
                    domain: None,
                    acl_address: None,
                    request_id: Some(RequestId {
                        request_id: request_id.clone(),
                    }),
                });

                let response = self.kms_client.request_decryption(request).await?;
                let decryption_response = response.into_inner();

                if let Some(payload) = decryption_response.payload {
                    // Get the first plaintext result
                    let result = payload
                        .plaintexts
                        .first()
                        .map(|pt| {
                            Self::log_and_extract_result(&pt.bytes, pt.fhe_type, &request_id, None);
                            Bytes::from(pt.bytes.clone())
                        })
                        .unwrap_or_default();

                    // Get the external signature
                    let signature = payload.external_signature.ok_or_else(|| {
                        crate::error::Error::Contract(
                            "KMS Core did not provide required EIP-712 signature".into(),
                        )
                    })?;

                    // Send response back to L2
                    info!(
                        "Sending public decryption response for request {} (result size: {} bytes)",
                        request_id,
                        result.len()
                    );
                    self.decryption
                        .send_public_decryption_response(
                            request_id.parse().expect("Invalid request ID"),
                            result,
                            signature,
                        )
                        .await?;
                } else {
                    error!(
                        "Received empty payload for decryption request {}",
                        request_id
                    );
                }
            }
            // TODO: adjust logic as per #2079
            // User decryption aka reencryption
            Some(user_addr) => {
                let request = Request::new(ReencryptionRequest {
                    payload: Some(ReencryptionRequestPayload {
                        client_address: Address::from_slice(&user_addr).to_string(),
                        enc_key: user_addr.clone(),
                        // TODO: change to actual key id once SC interface is updated
                        key_id: Some(RequestId {
                            request_id: request_id.clone(),
                        }),
                        typed_ciphertexts: ciphertext_data
                            .into_iter()
                            .map(|(handle, ciphertext)| {
                                let fhe_type = Self::extract_fhe_type_from_handle(&handle);
                                TypedCiphertext {
                                    ciphertext,
                                    external_handle: handle,
                                    fhe_type,
                                }
                            })
                            .collect(),
                    }),
                    // TODO: to understand how to populate this
                    domain: None,
                    request_id: Some(RequestId {
                        request_id: request_id.clone(),
                    }),
                });

                let response = self.kms_client.request_reencryption(request).await?;
                let reencryption_response = response.into_inner();

                if let Some(payload) = reencryption_response.payload {
                    // Serialize all signcrypted ciphertexts
                    let reencrypted_share_buf =
                        bincode::serialize(&payload.signcrypted_ciphertexts).map_err(|e| {
                            crate::error::Error::InvalidResponse(format!(
                                "Failed to serialize reencrypted shares: {}",
                                e
                            ))
                        })?;

                    // Log each ciphertext for debugging
                    for ct in &payload.signcrypted_ciphertexts {
                        Self::log_and_extract_result(
                            &ct.signcrypted_ciphertext,
                            ct.fhe_type,
                            &request_id,
                            Some(&user_addr),
                        );
                    }

                    // Get the external signature (non-optional in ReencryptionResponsePayload)
                    let signature = payload.external_signature;

                    // Send response back to L2
                    info!(
                        "Sending user decryption response for request {} (result size: {} bytes)",
                        request_id,
                        reencrypted_share_buf.len()
                    );
                    self.decryption
                        .send_user_decryption_response(
                            request_id.parse().expect("Invalid request ID"),
                            Bytes::from(reencrypted_share_buf),
                            signature,
                        )
                        .await?;
                } else {
                    error!(
                        "Received empty payload for reencryption request {}",
                        request_id
                    );
                }
            }
        }

        Ok(())
    }

    /// Process events from L2
    async fn process_events(&self, mut event_rx: mpsc::Receiver<KmsCoreEvent>) -> Result<()> {
        info!("Starting EVENTS processing...");

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
                                req.ctMaterials
                                    .into_iter()
                                    .map(|pair| {
                                        let handle = pair.ctHandle.to_be_bytes::<32>().to_vec();
                                        (handle, pair.ciphertext128.to_vec())
                                    })
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
                            let (handle, ciphertext) = req.ctHandleContractPairs
                                .first()
                                .map(|pair| {
                                    let handle = pair.ctHandle.to_be_bytes::<32>().to_vec();
                                    // TODO: Get actual ciphertext from contract using handle and contractAddress
                                    (handle, vec![])
                                })
                                .unwrap_or_default();

                            self.handle_decryption(
                                req.userDecryptionId.to_string(),
                                vec![(handle, ciphertext)],
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
