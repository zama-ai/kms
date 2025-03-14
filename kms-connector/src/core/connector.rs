// TODO: refactor once ciphertext S3 extraction is clarified.
// For now it contains trivial ciphertext extraction from SC for the public decrypt demo to work
use alloy::{
    hex,
    primitives::{Address, Bytes, U256},
    providers::Provider,
};
use kms_grpc::kms::v1::{
    CiphertextFormat, DecryptionRequest, Eip712DomainMsg, FheType, ReencryptionRequest, RequestId,
    TypedCiphertext,
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
        request_id: U256,
        user_addr: Option<&[u8]>,
    ) where
        T: AsRef<[u8]>,
    {
        let fhe_type_str = Self::fhe_type_to_string(fhe_type);

        match user_addr {
            Some(addr) => info!(
                "Reencrypted result type: {} for request {} (user: 0x{})",
                fhe_type_str,
                request_id,
                hex::encode(addr)
            ),
            None => info!(
                "Decrypted result type: {} for request {}",
                fhe_type_str, request_id
            ),
        }
    }

    /// Convert a string request ID to a valid hex format that KMS Core expects
    /// Returns an error if the request ID cannot be properly formatted
    fn format_request_id(request_id: U256) -> String {
        let bytes = request_id.to_be_bytes::<32>();
        hex::encode(bytes)
    }

    /// Handle a decryption request (both public and user)
    async fn handle_decryption(
        &self,
        request_id: U256,
        key_id: U256,
        ciphertext_data: Vec<(Vec<u8>, Vec<u8>)>, // (handle, ciphertext) pairs
        user_address: Option<Vec<u8>>,
    ) -> Result<()> {
        // key_id is also a request_id (from a previous keygen request),
        // so they should be formatted in the same way.
        let key_id_hex = Self::format_request_id(key_id);
        let request_id_hex = Self::format_request_id(request_id);

        // Log request details with FHE type information
        let request_type = if user_address.is_some() {
            "user"
        } else {
            "public"
        };

        // Extract and log FHE types for all ciphertexts
        let fhe_types: Vec<String> = ciphertext_data
            .iter()
            .map(|(handle, _)| {
                let fhe_type = Self::extract_fhe_type_from_handle(handle);
                Self::fhe_type_to_string(fhe_type).to_string()
            })
            .collect();

        info!(
            "Processing {} decryption request {} with {} ciphertexts, key_id: {}, FHE types: [{}]",
            request_type,
            request_id,
            ciphertext_data.len(),
            key_id_hex,
            fhe_types.join(", ")
        );

        // Create request ID objects for the KMS Core API
        let request_id_obj = RequestId {
            request_id: request_id_hex.clone(),
        };

        let key_id_obj = RequestId {
            request_id: key_id_hex.clone(),
        };

        info!("Using request_id in hex format: {}", request_id_hex);

        // Create domain message from config - same for both public and user decryption
        let domain = Some(Eip712DomainMsg {
            name: self
                .kms_client
                .config()
                .decryption_manager_domain_name
                .clone(),
            version: self
                .kms_client
                .config()
                .decryption_manager_domain_version
                .clone(),
            chain_id: vec![self.kms_client.config().chain_id as u8],
            verifying_contract: self.kms_client.config().decryption_manager_address.clone(),
            salt: None,
        });

        match user_address {
            // Public decryption
            None => {
                // Prepare ciphertexts for the decryption request
                let ciphertexts = ciphertext_data
                    .iter()
                    .map(|(handle, ciphertext)| {
                        let fhe_type = Self::extract_fhe_type_from_handle(handle);
                        TypedCiphertext {
                            ciphertext: ciphertext.clone(),
                            fhe_type,
                            external_handle: handle.clone(),
                            ciphertext_format: CiphertextFormat::BigExpanded.into(),
                        }
                    })
                    .collect();

                let request = Request::new(DecryptionRequest {
                    ciphertexts,
                    key_id: Some(key_id_obj),
                    domain,
                    request_id: Some(request_id_obj.clone()),
                });

                let response = self.kms_client.request_decryption(request).await?;
                info!(
                    "[IN] 📡 PublicDecryptionResponse({}) received",
                    request_id_hex
                );
                let decryption_response = response.into_inner();

                // Check if we have a valid payload
                if let Some(payload) = decryption_response.payload {
                    // Get the first plaintext result
                    let result = payload
                        .plaintexts
                        .first()
                        .map(|pt| {
                            Self::log_and_extract_result(&pt.bytes, pt.fhe_type, request_id, None);
                            Bytes::from(pt.bytes.clone())
                        })
                        .ok_or_else(|| {
                            crate::error::Error::InvalidResponse(
                                "KMS Core did not provide any plaintext results".into(),
                            )
                        })?;

                    // Get the external signature
                    let signature = payload.external_signature.ok_or_else(|| {
                        crate::error::Error::Contract(
                            "KMS Core did not provide required EIP-712 signature".into(),
                        )
                    })?;

                    // Send response back to L2
                    info!(
                        "Sending public decryption response for request {}",
                        request_id
                    );
                    self.decryption
                        .send_public_decryption_response(request_id, result, signature)
                        .await?;
                } else {
                    error!(
                        "Received empty payload for decryption request {}",
                        request_id
                    );
                    return Err(crate::error::Error::Contract(
                        "Empty payload received from KMS Core".into(),
                    ));
                }

                Ok(())
            }
            // User decryption aka reencryption
            Some(user_addr) => {
                // Prepare typed ciphertexts for the reencryption request
                let typed_ciphertexts = ciphertext_data
                    .iter()
                    .map(|(handle, ciphertext)| {
                        let fhe_type = Self::extract_fhe_type_from_handle(handle);
                        TypedCiphertext {
                            ciphertext: ciphertext.clone(),
                            external_handle: handle.clone(),
                            fhe_type,
                            ciphertext_format: CiphertextFormat::BigExpanded.into(),
                        }
                    })
                    .collect();

                let request = Request::new(ReencryptionRequest {
                    request_id: Some(request_id_obj),
                    client_address: Address::from_slice(&user_addr).to_string(),
                    enc_key: user_addr.clone(),
                    key_id: Some(key_id_obj),
                    typed_ciphertexts,
                    domain,
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
                            request_id,
                            Some(&user_addr),
                        );
                    }

                    // Get the external signature (non-optional in ReencryptionResponsePayload)
                    let signature = payload.external_signature;

                    // Send response back to L2
                    info!(
                        "Sending user decryption response for request {}",
                        request_id
                    );
                    self.decryption
                        .send_user_decryption_response(
                            request_id,
                            Bytes::from(reencrypted_share_buf),
                            signature,
                        )
                        .await?;
                } else {
                    error!(
                        "Received empty payload for reencryption request {}",
                        request_id
                    );
                    return Err(crate::error::Error::Contract(
                        "Empty payload received from KMS Core".into(),
                    ));
                }

                Ok(())
            }
        }
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

                            // Extract keyId from the first SNS ciphertext material if available
                            let key_id = if !req.snsCtMaterials.is_empty() {
                                let extracted_key_id = req.snsCtMaterials[0].keyId;
                                info!(
                                    "Extracted key_id {:?} from snsCtMaterials[0] for public decryption request {}",
                                    extracted_key_id, req.publicDecryptionId
                                );
                                extracted_key_id
                            } else {
                                // Fail the request if no materials available
                                error!(
                                    "No snsCtMaterials found for public decryption request {}, cannot proceed without a valid key_id",
                                    req.publicDecryptionId
                                );
                                continue;
                            };

                            // Convert ciphertext materials to handle/ciphertext pairs
                            let ciphertext_pairs = req.snsCtMaterials
                                .into_iter()
                                .map(|pair| {
                                    let handle = pair.ctHandle.to_be_bytes::<32>().to_vec();
                                    (handle, pair.snsCiphertext.to_vec())
                                })
                                .collect();

                            self.handle_decryption(
                                req.publicDecryptionId,
                                key_id,
                                ciphertext_pairs,
                                None,
                            )
                            .await
                        }
                        // TODO: properly handle user decryption request
                        KmsCoreEvent::UserDecryptionRequest(req) => {
                            info!(
                                "Processing user decryption request {}",
                                req.userDecryptionId
                            );

                            // Extract first ciphertext handle from pairs
                            let first_pair = req.ctHandleContractPairs.first();

                            if first_pair.is_none() {
                                error!(
                                    "No ctHandleContractPairs found for user decryption request {}, cannot proceed without a valid key_id",
                                    req.userDecryptionId
                                );
                                continue;
                            }

                            let pair = first_pair.unwrap();
                            let handle = pair.ctHandle.to_be_bytes::<32>().to_vec();

                            // Extract key_id from handle similar to public decryption
                            // This is a temporary solution until proper contract interaction is implemented
                            let key_id = pair.ctHandle;
                            info!(
                                "Using ctHandle {:?} as key_id for user decryption request {} (contract: {})",
                                key_id, req.userDecryptionId, pair.contractAddress
                            );

                            // TODO: Get actual ciphertext and key_id from contract
                            // using contractAddress:
                            // 1. Use provider to call the contract at pair.contractAddress
                            // 2. Retrieve the ciphertext and key_id for the given handle
                            // 3. Use that information for decryption
                            let ciphertext = vec![];

                            self.handle_decryption(
                                req.userDecryptionId,
                                key_id,
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
