use super::rpc_types::{
    compute_external_pt_signature, BaseKms, SignedPubDataHandleInternal, CURRENT_FORMAT_VERSION,
};
use crate::cryptography::central_kms::verify_reencryption_eip712;
use crate::cryptography::central_kms::{
    async_generate_crs, async_generate_fhe_keys, async_reencrypt, central_decrypt, BaseKmsStruct,
    SoftwareKms,
};
use crate::cryptography::internal_crypto_types::PublicEncKey;
use crate::cryptography::proven_ct_verifier::{
    get_verify_proven_ct_result, non_blocking_verify_proven_ct,
};
use crate::kms::core_service_endpoint_server::CoreServiceEndpoint;
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, FheType, InitRequest, KeyGenPreprocRequest, KeyGenPreprocStatus, KeyGenRequest,
    KeyGenResult, ParamChoice, ReencryptionRequest, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId, SignedPubDataHandle, TypedCiphertext,
    VerifyProvenCtRequest, VerifyProvenCtResponse,
};
use crate::rpc::rpc_types::{protobuf_to_alloy_domain_option, PubDataType};
use crate::storage::Storage;
use crate::util::meta_store::{handle_res_mapping, HandlerStatus};
use crate::{anyhow_error_and_log, anyhow_error_and_warn_log, top_n_chars};
use alloy_primitives::Address;
use alloy_sol_types::Eip712Domain;
use conf_trace::metrics::METRICS;
use conf_trace::metrics_names::{
    ERR_CRS_GEN_FAILED, ERR_DECRYPTION_FAILED, ERR_KEY_EXISTS, ERR_KEY_NOT_FOUND,
    ERR_RATE_LIMIT_EXCEEDED, ERR_REENCRYPTION_FAILED, OP_CRS_GEN, OP_DECRYPT, OP_KEYGEN,
    OP_REENCRYPT, OP_VERIFY_PROVEN_CT,
};
use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::Instrument;

#[tonic::async_trait]
impl<
        PubS: Storage + std::marker::Sync + std::marker::Send + 'static,
        PrivS: Storage + std::marker::Sync + std::marker::Send + 'static,
    > CoreServiceEndpoint for SoftwareKms<PubS, PrivS>
{
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting init on centralized kms is not suported".to_string(),
        )
    }

    #[tracing::instrument(skip(self, _request))]
    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc on centralized kms is not suported".to_string(),
        )
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_preproc_status(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc status on centralized kms is not suported".to_string(),
        )
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_key_gen(
        &self,
        request: Request<KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.key_gen(request).await
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        self.get_key_gen_result(request).await
    }

    /// starts the centralized KMS key generation
    #[tracing::instrument(skip(self, request))]
    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let _timer = METRICS
            .time_operation(OP_KEYGEN)
            .map_err(|e| Status::internal(format!("Failed to start metrics: {}", e)))?
            .start();
        METRICS
            .increment_request_counter(OP_KEYGEN)
            .map_err(|e| Status::internal(format!("Failed to increment counter: {}", e)))?;

        let permit = self.rate_limiter.start_keygen().await.map_err(|e| {
            if let Err(e) = METRICS.increment_error_counter(OP_KEYGEN, ERR_RATE_LIMIT_EXCEEDED) {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
            Status::resource_exhausted(e.to_string())
        })?;
        let inner = request.into_inner();
        tracing::info!(
            "centralized key-gen with request id: {:?}",
            inner.request_id
        );
        let req_id = tonic_some_or_err(
            inner.request_id,
            "No request ID present in request".to_string(),
        )?;
        validate_request_id(&req_id)?;
        let params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;
        {
            let mut guarded_meta_store = self.key_meta_map.write().await;
            // Insert [HandlerStatus::Started] into the meta store. Note that this will fail if the request ID is already in the meta store
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert key generation into meta store".to_string(),
            )?;
        }

        let meta_store = Arc::clone(&self.key_meta_map);
        let crypto_storage = self.crypto_storage.clone();
        let sk = Arc::clone(&self.base_kms.sig_key);

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref());

        let _handle =
            tokio::spawn(
                async move {
                    let _permit = permit;
                    let start = tokio::time::Instant::now();
                    {
                        // Check if the key already exists
                        if crypto_storage
                            .read_cloned_centralized_fhe_keys_from_cache(&req_id)
                            .await
                            .is_ok()
                        {
                            let mut guarded_meta_store = meta_store.write().await;
                            if let Err(e) = METRICS
                                .increment_error_counter(OP_KEYGEN, ERR_KEY_EXISTS)
                                .map_err(|e| {
                                    tracing::warn!("Failed to increment error counter: {:?}", e)
                                })
                            {
                                tracing::warn!("Failed to increment error counter: {:?}", e);
                            }
                            let _ = guarded_meta_store.update(
                                &req_id,
                                HandlerStatus::Error(format!(
                                    "Failed key generation: Key with ID {req_id} already exists!"
                                )),
                            );
                            return;
                        }
                    }
                    let (fhe_key_set, key_info) =
                        match async_generate_fhe_keys(&sk, params, None, eip712_domain.as_ref())
                            .await
                        {
                            Ok((fhe_key_set, key_info)) => (fhe_key_set, key_info),
                            Err(_e) => {
                                let mut guarded_meta_store = meta_store.write().await;
                                let _ = guarded_meta_store.update(
                                    &req_id,
                                    HandlerStatus::Error(format!(
                                        "Failed key generation: Key with ID {req_id}!"
                                    )),
                                );
                                return;
                            }
                        };

                    if let Err(e) = crypto_storage
                        .write_centralized_keys_with_meta_store(
                            &req_id,
                            key_info,
                            fhe_key_set,
                            meta_store,
                        )
                        .await
                    {
                        tracing::error!(
                            "Error \"{e:?}\" occured to store KeyGen result for request {req_id}",
                        );
                        return;
                    };

                    tracing::info!("⏱️ Core Event Time for Keygen: {:?}", start.elapsed());
                }
                .instrument(tracing::Span::current()),
            );

        Ok(Response::new(Empty {}))
    }

    /// tries to retrieve the result of a previously started key generation
    #[tracing::instrument(skip(self, request))]
    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let request_id = request.into_inner();
        tracing::debug!("Received get key gen result request with id {}", request_id);
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.key_meta_map.read().await;
            guarded_meta_store.retrieve(&request_id).cloned()
        };
        let pub_key_handles = handle_res_mapping(status, &request_id, "Key generation")?;

        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id),
            key_results: convert_key_response(pub_key_handles),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = METRICS
            .time_operation(OP_REENCRYPT)
            .map_err(|e| Status::internal(format!("Failed to start metrics: {}", e)))?
            .start();
        METRICS
            .increment_request_counter(OP_REENCRYPT)
            .map_err(|e| Status::internal(format!("Failed to increment counter: {}", e)))?;

        let permit = self.rate_limiter.start_reenc().await.map_err(|e| {
            if let Err(e) = METRICS.increment_error_counter(OP_REENCRYPT, ERR_RATE_LIMIT_EXCEEDED) {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
            Status::resource_exhausted(e.to_string())
        })?;
        let inner = request.into_inner();
        let (ciphertext, fhe_type, link, client_enc_key, client_address, key_id, request_id) =
            tonic_handle_potential_err(
                validate_reencrypt_req(&inner).await,
                format!("Invalid key in request {:?}", inner),
            )?;
        {
            let mut guarded_meta_store = self.reenc_meta_map.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&request_id),
                "Could not insert reencryption into meta store".to_string(),
            )?;
        }

        let meta_store = Arc::clone(&self.reenc_meta_map);
        let sig_key = Arc::clone(&self.base_kms.sig_key);
        let crypto_storage = self.crypto_storage.clone();
        let mut rng = self.base_kms.new_rng().await;

        tonic_handle_potential_err(
            crypto_storage.refresh_centralized_fhe_keys(&key_id).await,
            "Cannot find centralized keys".to_string(),
        )?;

        // we do not need to hold the handle,
        // the result of the computation is tracked by the reenc_meta_store
        let _handle = tokio::spawn(
            async move {
                let _permit = permit;
                let keys = match crypto_storage
                    .read_cloned_centralized_fhe_keys_from_cache(&key_id)
                    .await
                {
                    Ok(k) => k,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        if let Err(e) =
                            METRICS.increment_error_counter(OP_REENCRYPT, ERR_KEY_NOT_FOUND)
                        {
                            tracing::warn!("Failed to increment error counter: {:?}", e);
                        }
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Error(format!(
                                "Failed to get key ID {key_id} with error {e:?}"
                            )),
                        );
                        return;
                    }
                };
                tracing::info!(
                    "Starting reencryption using key_id {} for request ID {}",
                    &key_id,
                    &request_id
                );
                match async_reencrypt::<PubS, PrivS>(
                    &keys,
                    &sig_key,
                    &mut rng,
                    &ciphertext,
                    fhe_type,
                    &link,
                    &client_enc_key,
                    &client_address,
                )
                .await
                {
                    Ok(raw_decryption) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Done((fhe_type, link, raw_decryption)),
                        );
                    }
                    Result::Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Error(format!("Failed reencryption: {e}")),
                        );
                        METRICS
                            .increment_error_counter(OP_REENCRYPT, ERR_REENCRYPTION_FAILED)
                            .ok();
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.reenc_meta_map.read().await;
            guarded_meta_store.retrieve(&request_id).cloned()
        };
        let (fhe_type, req_digest, partial_dec) =
            handle_res_mapping(status, &request_id, "Reencryption")?;

        let server_verf_key = self.get_serialized_verf_key();

        let payload = ReencryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            signcrypted_ciphertext: partial_dec,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: server_verf_key,
            party_id: 1, // In the centralized KMS, the server ID is always 1
            degree: 0, // In the centralized KMS, the degree is always 0 since result is a constant
        };

        // sign the response
        let sig_payload_vec = tonic_handle_potential_err(
            bincode::serialize(&payload),
            format!("Could not convert payload to bytes {:?}", payload),
        )?;

        let sig = tonic_handle_potential_err(
            self.sign(&sig_payload_vec),
            format!("Could not sign payload {:?}", payload),
        )?;

        Ok(Response::new(ReencryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(payload),
        }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = METRICS
            .time_operation(OP_DECRYPT)
            .map_err(|e| Status::internal(e.to_string()))?
            .start();
        METRICS
            .increment_request_counter(OP_DECRYPT)
            .map_err(|e| Status::internal(e.to_string()))?;

        let permit = self.rate_limiter.start_dec().await.map_err(|e| {
            if let Err(e) = METRICS.increment_error_counter(OP_DECRYPT, ERR_RATE_LIMIT_EXCEEDED) {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
            tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string())
        })?;

        let start = tokio::time::Instant::now();
        let inner = request.into_inner();

        let (ciphertexts, req_digest, key_id, request_id, eip712_domain, acl_address) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )?;

        tracing::info!(
            "Decrypting {:?} ciphertexts using key {:?} with request id {:?}",
            ciphertexts.len(),
            key_id.request_id,
            inner.request_id
        );

        {
            let mut guarded_meta_store = self.dec_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&request_id),
                "Could not insert decryption into meta store".to_string(),
            )?;
        }

        let meta_store = Arc::clone(&self.dec_meta_store);
        let sigkey = Arc::clone(&self.base_kms.sig_key);
        let crypto_storage = self.crypto_storage.clone();

        tonic_handle_potential_err(
            crypto_storage.refresh_centralized_fhe_keys(&key_id).await,
            "Cannot find centralized keys".to_string(),
        )?;

        // we do not need to hold the handle,
        // the result of the computation is tracked by the dec_meta_store
        let _handle = tokio::spawn(
            async move {
                let _permit = permit;
                let keys = match crypto_storage.read_cloned_centralized_fhe_keys_from_cache(&key_id).await {
                    Ok(k) => k,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        if let Err(e) = METRICS.increment_error_counter(OP_DECRYPT, ERR_KEY_NOT_FOUND) {
                            tracing::warn!("Failed to increment error counter: {:?}", e);
                        }
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Error(format!(
                                "Failed to get key ID {key_id} with error {e:?}"
                            )),
                        );
                        return;
                    }
                };
                tracing::info!(
                    "Starting decryption using key_id {} for request ID {}",
                    &key_id,
                    &request_id
                );

                let ext_handles_bytes = ciphertexts
                    .iter()
                    .map(|c| c.external_handle.to_owned())
                    .collect::<Vec<_>>();

                // run the computation in a separate rayon thread to avoid blocking the tokio runtime
                let (send, recv) = tokio::sync::oneshot::channel();
                rayon::spawn(move || {
                    let decryptions = central_decrypt::<PubS, PrivS>(&keys, &ciphertexts);
                    let _ = send.send(decryptions);
                });
                let decryptions = recv.await;

                match decryptions {
                    Ok(Ok(pts)) => {
                        // sign the plaintexts and handles for external verification (in the fhevm)
                        let external_sig = if let (Some(domain), Some(acl_address)) =
                            (eip712_domain, acl_address)
                        {
                            compute_external_pt_signature(
                                &sigkey,
                                ext_handles_bytes,
                                &pts,
                                domain,
                                acl_address,
                            )
                        } else {
                            tracing::warn!("Skipping external signature computation due to missing domain or acl address");
                            vec![]
                        };

                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Done((req_digest.clone(), pts, external_sig)),
                        );
                        tracing::info!(
                            "⏱️ Core Event Time for decryption computation: {:?}",
                            start.elapsed()
                        );
                    }
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Error(format!("Error collecting decrypt result: {:?}", e)),
                        );
                    }
                    Ok(Err(e)) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        if let Err(e) = METRICS.increment_error_counter(OP_DECRYPT, ERR_DECRYPTION_FAILED) {
                            tracing::warn!("Failed to increment error counter: {:?}", e);
                        }
                        let _ = guarded_meta_store.update(
                            &request_id,
                            HandlerStatus::Error(format!("Error during decryption computation: {}", e)),
                        );
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id).cloned()
        };
        let (req_digest, plaintexts, external_signature) =
            handle_res_mapping(status, &request_id, "Decryption")?;

        tracing::debug!(
            "Returning plaintext(s) for request ID {}: {:?}. External signature: {:x?}",
            request_id,
            plaintexts,
            external_signature
        );

        // serialize plaintexts to return as payload
        let pt_payload = tonic_handle_potential_err(
            plaintexts
                .iter()
                .map(bincode::serialize)
                .collect::<Result<Vec<Vec<u8>>, _>>(),
            "Error serializing plaintexts in get_result()".to_string(),
        )?;

        let server_verf_key = self.get_serialized_verf_key();

        // the payload to be signed for verification inside the KMS
        let kms_sig_payload = DecryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            plaintexts: pt_payload,
            verification_key: server_verf_key,
            digest: req_digest,
            external_signature: Some(external_signature),
        };

        let kms_sig_payload_vec = tonic_handle_potential_err(
            bincode::serialize(&kms_sig_payload),
            format!("Could not convert payload to bytes {:?}", kms_sig_payload),
        )?;

        // sign the decryption result with the central KMS key
        let sig = tonic_handle_potential_err(
            self.sign(&kms_sig_payload_vec),
            format!("Could not sign payload {:?}", kms_sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(kms_sig_payload),
        }))
    }

    /// starts the centralized CRS generation
    #[tracing::instrument(skip(self, request))]
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        tracing::info!("Received CRS generation request");
        let _timer = METRICS
            .time_operation(OP_CRS_GEN)
            .map_err(|e| Status::internal(format!("Failed to start metrics: {}", e)))?
            .start();
        METRICS
            .increment_request_counter(OP_CRS_GEN)
            .map_err(|e| Status::internal(format!("Failed to increment counter: {}", e)))?;

        let permit = self
            .rate_limiter
            .start_crsgen()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let inner = request.into_inner();
        let req_id = tonic_some_or_err(
            inner.request_id,
            "Request ID is not set (crs gen)".to_string(),
        )?;
        validate_request_id(&req_id)?;
        let params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;
        {
            let mut guarded_meta_store = self.crs_meta_map.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert CRS generation into meta store".to_string(),
            )?;
        }

        let meta_store = Arc::clone(&self.crs_meta_map);
        let crypto_storage = self.crypto_storage.clone();
        let sk = Arc::clone(&self.base_kms.sig_key);
        let rng = self.base_kms.new_rng().await;

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref());

        let _handle = tokio::spawn(
            async move {
                let _permit = permit;
                let start = tokio::time::Instant::now();

                let (pp, crs_info) = match async_generate_crs(
                    &sk,
                    rng,
                    params,
                    inner.max_num_bits,
                    eip712_domain.as_ref(),
                )
                .await
                {
                    Ok((pp, crs_info)) => (pp, crs_info),
                    Err(e) => {
                        tracing::error!("Error in inner CRS generation: {}", e);
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Error(format!(
                                "Failed CRS generation for CRS with ID {req_id}!"
                            )),
                        );
                        METRICS
                            .increment_error_counter(OP_CRS_GEN, ERR_CRS_GEN_FAILED)
                            .ok();
                        return;
                    }
                };

                if let Err(e) = crypto_storage
                    .write_crs_with_meta_store(&req_id, pp, crs_info, meta_store)
                    .await
                {
                    tracing::error!(
                        "Error \"{e:?}\" occured to store CrsGen result for request {req_id}"
                    );
                    return;
                }

                tracing::info!("⏱️ Core Event Time for CRS-gen: {:?}", start.elapsed());
            }
            .instrument(tracing::Span::current()),
        );
        Ok(Response::new(Empty {}))
    }

    /// tries to retrieve a previously generated CRS
    #[tracing::instrument(skip(self, request))]
    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
        tracing::debug!("Received CRS gen result request with id {}", request_id);
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.crs_meta_map.read().await;
            guarded_meta_store.retrieve(&request_id).cloned()
        };
        let crs_info = handle_res_mapping(status, &request_id, "CRS")?;

        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(crs_info.into()),
        }))
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.crs_gen(request).await
    }

    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        self.get_crs_gen_result(request).await
    }

    #[tracing::instrument(skip(self, request))]
    async fn verify_proven_ct(
        &self,
        request: Request<VerifyProvenCtRequest>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = METRICS
            .time_operation(OP_VERIFY_PROVEN_CT)
            .map_err(|e| Status::internal(format!("Failed to start metrics: {}", e)))?
            .start();
        METRICS
            .increment_request_counter(OP_VERIFY_PROVEN_CT)
            .map_err(|e| Status::internal(format!("Failed to increment counter: {}", e)))?;

        let permit = self
            .rate_limiter
            .start_verify_proven_ct()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let meta_store = Arc::clone(&self.proven_ct_payload_meta_map);
        let sigkey = Arc::clone(&self.base_kms.sig_key);

        // Check well-formedness of the request and return an error early if there's an error
        let request_id = request
            .get_ref()
            .request_id
            .as_ref()
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "missing request ID".to_string(),
                )
            })?
            .clone();
        validate_request_id(&request_id)?;

        non_blocking_verify_proven_ct(
            (&self.crypto_storage).into(),
            meta_store,
            request_id.clone(),
            request.into_inner(),
            sigkey,
            permit,
        )
        .await
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Internal,
                format!("non_blocking_verify_proven_ct failed for request_id {request_id} ({e})"),
            )
        })?;

        Ok(Response::new(Empty {}))
    }

    async fn get_verify_proven_ct_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<VerifyProvenCtResponse>, Status> {
        let meta_store = Arc::clone(&self.proven_ct_payload_meta_map);
        get_verify_proven_ct_result(self, meta_store, request).await
    }
}

/// Validates a request ID and returns an appropriate tonic error if it is invalid.
pub(crate) fn validate_request_id(request_id: &RequestId) -> Result<(), Status> {
    if !request_id.is_valid() {
        tracing::warn!(
            "The value {} is not a valid request ID!",
            request_id.to_string()
        );
        return Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("The value {} is not a valid request ID!", request_id),
        ));
    }
    Ok(())
}

/// Helper method which takes a [HashMap<PubDataType, SignedPubDataHandle>] and returns
/// [HashMap<String, SignedPubDataHandle>] by applying the [ToString] function on [PubDataType] for each element in the map.
/// The function is needed since protobuf does not support enums in maps.
pub(crate) fn convert_key_response(
    key_info_map: HashMap<PubDataType, SignedPubDataHandleInternal>,
) -> HashMap<String, SignedPubDataHandle> {
    key_info_map
        .into_iter()
        .map(|(key_type, key_info)| {
            let key_type = key_type.to_string();
            (key_type, key_info.into())
        })
        .collect()
}

pub(crate) fn retrieve_parameters(param_choice: i32) -> anyhow::Result<DKGParams> {
    let param_choice = ParamChoice::try_from(param_choice)?;
    Ok(param_choice.into())
}

/// Validates a reencryption request and returns ciphertext, FheType, request digest, client
/// encryption key, client verification key, key_id and request_id if valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
pub async fn validate_reencrypt_req(
    req: &ReencryptionRequest,
) -> anyhow::Result<(
    Vec<u8>,
    FheType,
    Vec<u8>,
    PublicEncKey,
    alloy_primitives::Address,
    RequestId,
    RequestId,
)> {
    let payload = tonic_some_ref_or_err(
        req.payload.as_ref(),
        format!("The request {:?} does not have a payload", req),
    )?;
    let request_id = tonic_some_or_err(
        req.request_id.clone(),
        "Request ID is not set (validate reencrypt req)".to_string(),
    )?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "The value {} is not a valid request ID!",
            request_id
        )));
    }
    if payload.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            payload.version, CURRENT_FORMAT_VERSION
        )));
    }

    let client_verf_key =
        alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

    match verify_reencryption_eip712(req) {
        Ok(()) => {
            tracing::debug!("🔒 Signature verified successfully");
        }
        Err(e) => {
            return Err(anyhow_error_and_log(format!(
                "Signature verification failed with error {e} for request: {req:?}"
            )));
        }
    }

    let ciphertext = payload
        .ciphertext
        .clone()
        .ok_or_else(|| anyhow_error_and_log(format!("Missing ciphertext in request {:?}", req)))?;
    let fhe_type = payload.fhe_type();
    let link = req.compute_link_checked()?;
    let client_enc_key: PublicEncKey = bincode::deserialize(&payload.enc_key)?;
    let key_id = tonic_some_or_err(
        payload.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    Ok((
        ciphertext,
        fhe_type,
        link,
        client_enc_key,
        client_verf_key,
        key_id,
        request_id,
    ))
}

/// Validates a decryption request and unpacks and returns
/// the ciphertext, FheType, digest, key_id and request_id if it is valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub(crate) fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    RequestId,
    RequestId,
    Option<Eip712Domain>,
    Option<Address>,
)> {
    let key_id = tonic_some_or_err(
        req.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    if req.version != CURRENT_FORMAT_VERSION {
        return Err(anyhow_error_and_warn_log(format!(
            "Version number was {:?}, whereas current is {:?}",
            req.version, CURRENT_FORMAT_VERSION
        )));
    }
    let serialized_req = tonic_handle_potential_err(
        bincode::serialize(&req),
        format!("Could not serialize payload {:?}", req),
    )?;
    let req_digest = tonic_handle_potential_err(
        BaseKmsStruct::digest(&serialized_req),
        format!("Could not hash payload {:?}", req),
    )?;
    let request_id = tonic_some_or_err(
        req.request_id.clone(),
        "Request ID is not set (validate decrypt req)".to_string(),
    )?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "The value {} is not a valid request ID!",
            request_id
        )));
    }

    let eip712_domain = protobuf_to_alloy_domain_option(req.domain.as_ref());

    let acl_address = if let Some(address) = req.acl_address.as_ref() {
        match Address::parse_checksummed(address, None) {
            Ok(address) => Some(address),
            Err(e) => {
                tracing::warn!(
                    "Could not parse ACL address: {:?}. Error: {:?}. Returning None.",
                    address,
                    e
                );
                None
            }
        }
    } else {
        None
    };

    Ok((
        req.ciphertexts.clone(),
        req_digest,
        key_id,
        request_id,
        eip712_domain,
        acl_address,
    ))
}

pub fn process_response<T: fmt::Debug>(resp: anyhow::Result<Option<T>>) -> Result<T, Status> {
    match resp {
        Ok(None) => {
            tracing::warn!("A request failed validation");
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                format!("The request failed validation: {}", resp.unwrap_err()),
            ))
        }
        Ok(Some(resp)) => Ok(resp),
        Err(e) => {
            tracing::error!("An internal error happened while handle a request: {}", e);
            Err(tonic::Status::new(
                tonic::Code::Aborted,
                format!("Internal server error: {}", e),
            ))
        }
    }
}

pub fn tonic_some_or_err<T>(input: Option<T>, error: String) -> Result<T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

pub fn tonic_some_or_err_ref<T>(input: &Option<T>, error: String) -> Result<&T, tonic::Status> {
    input.as_ref().ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

pub fn tonic_some_ref_or_err<T>(input: Option<&T>, error: String) -> Result<&T, tonic::Status> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(error))
    })
}

pub fn tonic_handle_potential_err<T, E: ToString>(
    resp: Result<T, E>,
    error: String,
) -> Result<T, tonic::Status> {
    resp.map_err(|e| {
        let msg = format!("{}: {}", error, e.to_string());
        tracing::warn!(msg);
        tonic::Status::new(tonic::Code::Aborted, top_n_chars(msg))
    })
}
