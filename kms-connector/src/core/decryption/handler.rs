use alloy::{
    primitives::{Address, Bytes, U256},
    providers::Provider,
};
use kms_grpc::kms::v1::{
    CiphertextFormat, DecryptionRequest, Eip712DomainMsg, ReencryptionRequest, RequestId,
    TypedCiphertext,
};
use std::sync::Arc;
use tonic::Request;
use tracing::{error, info, warn};

use crate::{
    core::{
        config::Config,
        types::fhe_types::{
            extract_fhe_type_from_handle, fhe_type_to_string, format_request_id,
            log_and_extract_result,
        },
    },
    error::Result,
    gwl2_adapters::decryption::DecryptionAdapter,
    kms_core_adapters::service::{KmsService, KmsServiceImpl},
};

/// Handle decryption requests and responses
#[derive(Clone)]
pub struct DecryptionHandler<P: Provider + Clone> {
    decryption: DecryptionAdapter<P>,
    kms_client: Arc<KmsServiceImpl>,
    #[allow(dead_code)]
    config: Config,
}

impl<P: Provider + Clone + std::fmt::Debug + 'static> DecryptionHandler<P> {
    /// Create a new decryption handler
    pub fn new(
        decryption: DecryptionAdapter<P>,
        kms_client: Arc<KmsServiceImpl>,
        config: Config,
    ) -> Self {
        Self {
            decryption,
            kms_client,
            config,
        }
    }

    /// Handle a decryption request (both public and user)
    pub async fn handle_decryption_request_response(
        &self,
        request_id: U256,
        key_id: U256,
        sns_ciphertext_materials: Vec<(Vec<u8>, Vec<u8>)>, // (handle, ciphertext) pairs
        user_address: Option<Vec<u8>>,
    ) -> Result<()> {
        let key_id_hex = format_request_id(key_id);
        let request_id_hex = format_request_id(request_id);

        let request_type = if user_address.is_some() {
            "user"
        } else {
            "public"
        };

        // Extract and log FHE types for all ciphertexts
        let fhe_types: Vec<String> = sns_ciphertext_materials
            .iter()
            .map(|(handle, _)| {
                let fhe_type = extract_fhe_type_from_handle(handle);
                fhe_type_to_string(fhe_type).to_string()
            })
            .collect();

        info!(
            "Processing {} decryption request {} with {} ciphertexts, key_id: {}, FHE types: [{}]",
            request_type,
            request_id,
            sns_ciphertext_materials.len(),
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
                let ciphertexts = sns_ciphertext_materials
                    .iter()
                    .map(|(handle, ciphertext)| {
                        let fhe_type = extract_fhe_type_from_handle(handle);
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
                            log_and_extract_result(&pt.bytes, pt.fhe_type, request_id, None);
                            Bytes::from(pt.bytes.clone())
                        })
                        .ok_or_else(|| {
                            crate::error::Error::InvalidResponse(
                                "KMS Core did not provide any plaintext results".into(),
                            )
                        })?;

                    // Check if there are multiple plaintext results
                    if payload.plaintexts.len() > 1 {
                        warn!(
                            "KMS Core returned {} plaintext results, but only the first one will be used",
                            payload.plaintexts.len()
                        );
                    }

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
                let typed_ciphertexts = sns_ciphertext_materials
                    .iter()
                    .map(|(handle, ciphertext)| {
                        let fhe_type = extract_fhe_type_from_handle(handle);
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
                        log_and_extract_result(
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
}
