use alloy::providers::Provider;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

use crate::{
    core::{config::Config, decryption::handler::DecryptionHandler, utils::s3},
    error::Result,
    gwl2_adapters::events::KmsCoreEvent,
    gwl2_contracts::IDecryptionManager::SnsCiphertextMaterial,
};

/// Process events from L2
pub struct EventProcessor<P: Provider + Clone> {
    decryption_handler: DecryptionHandler<P>,
    config: Config,
    provider: Arc<P>,
    shutdown: Option<broadcast::Receiver<()>>,
}

impl<P: Provider + Clone + std::fmt::Debug + 'static> EventProcessor<P> {
    /// Create a new event processor
    pub fn new(
        decryption_handler: DecryptionHandler<P>,
        config: Config,
        provider: Arc<P>,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            decryption_handler,
            config,
            provider,
            shutdown: Some(shutdown),
        }
    }

    /// Helper method to retrieve ciphertext materials from S3
    async fn retrieve_sns_ciphertext_materials(
        &self,
        sns_materials: Vec<SnsCiphertextMaterial>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let s3_config = self.config.s3_config.clone();
        let httpz_address = self
            .config
            .get_httpz_address()
            .expect("Invalid HTTPZ address");

        // Process all SNS ciphertext materials
        let mut sns_ciphertext_materials = Vec::new();
        for sns_material in sns_materials {
            let extracted_ct_handle = sns_material.ctHandle.to_be_bytes::<32>().to_vec();
            let extracted_sns_ciphertext_digest = sns_material.snsCiphertextDigest.to_vec();
            let coprocessor_addresses = sns_material.coprocessorAddresses;

            // Get S3 URL and retrieve ciphertext
            // 1. For each SNS material, we try to retrieve its ciphertext from multiple possible S3 URLs
            // 2. Once we successfully retrieve a ciphertext from any of those URLs, we break out of the S3 URLs loop
            // 3. Then we continue processing the next SNS material in the outer loop
            match s3::prefetch_coprocessor_buckets(
                coprocessor_addresses,
                httpz_address,
                self.provider.clone(),
            )
            .await
            {
                Ok(s3_urls) => {
                    for s3_url in s3_urls {
                        match s3::call_s3_ciphertext_retrieval(
                            s3_url.clone(),
                            extracted_sns_ciphertext_digest.clone(),
                            s3_config.clone(),
                        )
                        .await
                        {
                            Ok(ciphertext) => {
                                sns_ciphertext_materials
                                    .push((extracted_ct_handle.clone(), ciphertext));
                                break; // We want to stop as soon as ciphertext corresponding to extracted_sns_ciphertext_digest is retrieved
                            }
                            Err(e) => {
                                // Log error but continue trying other URLs
                                warn!(
                                    "Failed to retrieve ciphertext for digest {} from S3 URL {}: {}",
                                    alloy::hex::encode(&extracted_sns_ciphertext_digest),
                                    s3_url,
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get S3 URL: {}", e);
                    // Continue with other materials
                }
            }
        }

        sns_ciphertext_materials
    }

    /// Process events from L2
    pub async fn process_l2_events(
        &self,
        mut event_rx: mpsc::Receiver<KmsCoreEvent>,
    ) -> Result<()> {
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
                                let extracted_key_id = req.snsCtMaterials.first().unwrap().keyId;
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

                            // Retrieve ciphertext materials from S3
                            let sns_ciphertext_materials = self.retrieve_sns_ciphertext_materials(req.snsCtMaterials).await;

                            // If we couldn't retrieve any materials, fail the request
                            if sns_ciphertext_materials.is_empty() {
                                error!(
                                    "Failed to retrieve any ciphertext materials for public decryption request {}",
                                    req.publicDecryptionId
                                );
                                continue;
                            }

                            self.decryption_handler.handle_decryption_request_response(
                                req.publicDecryptionId,
                                key_id,
                                sns_ciphertext_materials,
                                None,
                            )
                            .await
                        }

                        KmsCoreEvent::UserDecryptionRequest(req) => {
                            info!(
                                "Processing user decryption request {}",
                                req.userDecryptionId
                            );

                            // Extract keyId from the first SNS ciphertext material if available
                            let key_id = if !req.snsCtMaterials.is_empty() {
                                let extracted_key_id = req.snsCtMaterials.first().unwrap().keyId;
                                info!(
                                    "Extracted key_id {:?} from snsCtMaterials[0] for user decryption request {} (contract: {})",
                                    extracted_key_id, req.userDecryptionId, req.publicKey
                                );
                                extracted_key_id
                            } else {
                                // Fail the request if no materials available
                                error!(
                                    "No snsCtMaterials found for user decryption request {} (contract: {}), cannot proceed without a valid key_id",
                                    req.userDecryptionId, req.publicKey
                                );
                                continue;
                            };

                            // Retrieve ciphertext materials from S3
                            let sns_ciphertext_materials = self.retrieve_sns_ciphertext_materials(req.snsCtMaterials).await;

                            // If we couldn't retrieve any materials, fail the request
                            if sns_ciphertext_materials.is_empty() {
                                error!(
                                    "Failed to retrieve any ciphertext materials for user decryption request {}",
                                    req.userDecryptionId
                                );
                                continue;
                            }

                            self.decryption_handler.handle_decryption_request_response(
                                req.userDecryptionId,
                                key_id,
                                sns_ciphertext_materials,
                                Some(req.publicKey.to_vec()),
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
}
