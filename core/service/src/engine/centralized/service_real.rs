use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::engine::base::{
    compute_external_pt_signature, convert_key_response, preproc_proto_to_keyset_config,
    retrieve_parameters, KeyGenCallValues,
};
use crate::engine::centralized::central_kms::{
    async_generate_crs, async_generate_fhe_keys, async_reencrypt, central_decrypt,
    RealCentralizedKms,
};
use crate::engine::traits::BaseKms;
use crate::engine::validation::{
    validate_decrypt_req, validate_reencrypt_req, validate_request_id,
};
use crate::util::meta_store::{handle_res_mapping, MetaStore};
use crate::vault::storage::crypto_material::CentralizedCryptoMaterialStorage;
use crate::vault::storage::Storage;
use crate::{tonic_handle_potential_err, tonic_some_or_err};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use conf_trace::metrics::METRICS;
use conf_trace::metrics_names::{
    ERR_CRS_GEN_FAILED, ERR_DECRYPTION_FAILED, ERR_KEY_EXISTS, ERR_KEY_NOT_FOUND,
    ERR_RATE_LIMIT_EXCEEDED, ERR_REENCRYPTION_FAILED, OP_CRS_GEN, OP_DECRYPT_REQUEST, OP_KEYGEN,
    OP_REENCRYPT_REQUEST, TAG_DECRYPTION_KIND, TAG_KEY_ID, TAG_PARTY_ID,
};
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocResult, KeyGenRequest, KeyGenResult,
    KeySetAddedInfo, ReencryptionRequest, ReencryptionResponse, RequestId,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use kms_grpc::rpc_types::{protobuf_to_alloy_domain_option, SignedPubDataHandleInternal};
use std::collections::HashMap;
use std::sync::Arc;
use threshold_fhe::execution::keyset_config::KeySetConfig;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::sync::{OwnedSemaphorePermit, RwLock};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use super::central_kms::async_generate_decompression_keys;

#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > CoreServiceEndpoint for RealCentralizedKms<PubS, PrivS, BackS>
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
    async fn get_key_gen_preproc_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
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

        let keyset_config = tonic_handle_potential_err(
            preproc_proto_to_keyset_config(&inner.keyset_config),
            "Invalid keyset config".to_string(),
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
        let handle = self.tracker.spawn(
            async move {
                let _timer = _timer;
                if let Err(e) = key_gen_background(
                    &req_id,
                    meta_store,
                    crypto_storage,
                    sk,
                    params,
                    keyset_config,
                    inner.keyset_added_info,
                    eip712_domain,
                    permit,
                )
                .await
                {
                    tracing::error!("Key generation of request {} failed: {}", req_id, e);
                } else {
                    tracing::info!(
                        "Key generation of request {} completed successfully.",
                        req_id
                    );
                }
            }
            .instrument(tracing::Span::current()),
        );
        self.thread_handles.write().await.add(handle);

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
            guarded_meta_store.retrieve(&request_id)
        };
        let pub_key_handles = handle_res_mapping(status, &request_id, "Key generation").await?;

        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id),
            key_results: convert_key_response(pub_key_handles),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        // Start timing and counting before any operations
        let mut timer = METRICS
            .time_operation(OP_REENCRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                // Use a constant party ID since this is the central KMS
                b.tag(TAG_PARTY_ID, "central")
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();

        let _request_counter = METRICS
            .increment_request_counter(OP_REENCRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        let permit = self.rate_limiter.start_reenc().await.map_err(|e| {
            if let Err(e) =
                METRICS.increment_error_counter(OP_REENCRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED)
            {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
            Status::resource_exhausted(e.to_string())
        })?;

        let inner = request.into_inner();

        let (typed_ciphertexts, link, client_enc_key, client_address, key_id, request_id, domain) =
            tonic_handle_potential_err(
                validate_reencrypt_req(&inner),
                format!("Failed to validate reencryption request: {:?}", inner),
            )?;

        if let Some(b) = timer.as_mut() {
            //We log but we don't want to return early because timer failed
            let _ = b
                .tags([(TAG_KEY_ID, key_id.request_id.clone())])
                .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
        }

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
            format!("Cannot find centralized keys with key ID {key_id}"),
        )?;

        let mut handles = self.thread_handles.write().await;

        let metric_tags = vec![
            (TAG_KEY_ID, key_id.request_id.clone()),
            (TAG_DECRYPTION_KIND, "centralized".to_string()),
        ];

        let server_verf_key = self.base_kms.get_serialized_verf_key();

        let handle = tokio::spawn(
            async move {
                let _timer = timer;
                let _permit = permit;
                let keys = match crypto_storage
                    .read_cloned_centralized_fhe_keys_from_cache(&key_id)
                    .await
                {
                    Ok(k) => k,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        if let Err(e) =
                            METRICS.increment_error_counter(OP_REENCRYPT_REQUEST, ERR_KEY_NOT_FOUND)
                        {
                            tracing::warn!("Failed to increment error counter: {:?}", e);
                        }
                        let _ = guarded_meta_store.update(
                            &request_id,
                            Err(format!("Failed to get key ID {key_id} with error {e:?}")),
                        );
                        return;
                    }
                };

                tracing::info!(
                    "Starting reencryption using key_id {} for request ID {}",
                    &key_id,
                    &request_id
                );
                match async_reencrypt::<PubS, PrivS, BackS>(
                    &keys,
                    &sig_key,
                    &mut rng,
                    &typed_ciphertexts,
                    &link,
                    &client_enc_key,
                    &client_address,
                    server_verf_key,
                    &domain,
                    metric_tags,
                )
                .await
                {
                    Ok((payload, external_signature)) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store
                            .update(&request_id, Ok((payload, external_signature)));
                    }
                    Result::Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store
                            .update(&request_id, Err(format!("Failed reencryption: {e}")));
                        METRICS
                            .increment_error_counter(OP_REENCRYPT_REQUEST, ERR_REENCRYPTION_FAILED)
                            .ok();
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );

        handles.add(handle);
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
            guarded_meta_store.retrieve(&request_id)
        };

        let (payload, external_signature) =
            handle_res_mapping(status, &request_id, "Reencryption").await?;

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
            external_signature,
            payload: Some(payload),
        }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        // Start timing and counting before any operations
        let mut timer = METRICS
            .time_operation(OP_DECRYPT_REQUEST)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                // Use a constant party ID since this is the central KMS
                b.tag(TAG_PARTY_ID, "central")
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();

        METRICS
            .increment_request_counter(OP_DECRYPT_REQUEST)
            .map_err(|e| Status::internal(e.to_string()))?;

        let permit = self.rate_limiter.start_dec().await.map_err(|e| {
            if let Err(e) =
                METRICS.increment_error_counter(OP_DECRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED)
            {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
            tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string())
        })?;

        let start = tokio::time::Instant::now();
        let inner = request.into_inner();

        let (ciphertexts, req_digest, key_id, request_id, eip712_domain) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Failed to validate decrypt request {:?}", inner),
            )?;

        if let Some(b) = timer.as_mut() {
            //We log but we don't want to return early because timer failed
            let _ = b
                .tags([(TAG_KEY_ID, key_id.request_id.clone())])
                .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
        }

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
            format!("Cannot find centralized keys with key ID {key_id}"),
        )?;

        let metric_tags = vec![
            (TAG_KEY_ID, key_id.request_id.clone()),
            (TAG_DECRYPTION_KIND, "centralized".to_string()),
        ];
        // we do not need to hold the handle,
        // the result of the computation is tracked by the dec_meta_store
        let _handle = tokio::spawn(
            async move {
                let _timer = timer;
                let _permit = permit;
                let keys = match crypto_storage
                    .read_cloned_centralized_fhe_keys_from_cache(&key_id)
                    .await
                {
                    Ok(k) => k,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        if let Err(e) =
                            METRICS.increment_error_counter(OP_DECRYPT_REQUEST, ERR_KEY_NOT_FOUND)
                        {
                            tracing::warn!("Failed to increment error counter: {:?}", e);
                        }
                        let _ = guarded_meta_store.update(
                            &request_id,
                            Err(format!("Failed to get key ID {key_id} with error {e:?}")),
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
                rayon::spawn_fifo(move || {
                    let decryptions =
                        central_decrypt::<PubS, PrivS, BackS>(&keys, &ciphertexts, metric_tags);
                    let _ = send.send(decryptions);
                });
                let decryptions = recv.await;

                match decryptions {
                    Ok(Ok(pts)) => {
                        // sign the plaintexts and handles for external verification (in HTTPZ)
                        let external_sig = if let Some(domain) = eip712_domain {
                            compute_external_pt_signature(&sigkey, ext_handles_bytes, &pts, domain)
                        } else {
                            tracing::warn!(
                                "Skipping external signature computation due to missing domain"
                            );
                            vec![]
                        };

                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store
                            .update(&request_id, Ok((req_digest.clone(), pts, external_sig)));
                        tracing::info!(
                            "⏱️ Core Event Time for decryption computation: {:?}",
                            start.elapsed()
                        );
                    }
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        let _ = guarded_meta_store.update(
                            &request_id,
                            Err(format!("Error collecting decrypt result: {:?}", e)),
                        );
                    }
                    Ok(Err(e)) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        if let Err(e) = METRICS
                            .increment_error_counter(OP_DECRYPT_REQUEST, ERR_DECRYPTION_FAILED)
                        {
                            tracing::warn!("Failed to increment error counter: {:?}", e);
                        }
                        let _ = guarded_meta_store.update(
                            &request_id,
                            Err(format!("Error during decryption computation: {}", e)),
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
        tracing::debug!("Received get key gen result request with id {}", request_id);
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let (req_digest, plaintexts, external_signature) =
            handle_res_mapping(status, &request_id, "Decryption").await?;

        tracing::debug!(
            "Returning plaintext(s) for request ID {}: {:?}. External signature: {:x?}",
            request_id,
            plaintexts,
            external_signature
        );

        let server_verf_key = self.get_serialized_verf_key();

        // the payload to be signed for verification inside the KMS
        let kms_sig_payload = DecryptionResponsePayload {
            plaintexts,
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
        let handle = self.tracker.spawn(
            async move {
                let _timer = _timer;
                if let Err(e) = crs_gen_background(
                    &req_id,
                    rng,
                    meta_store,
                    crypto_storage,
                    sk,
                    params,
                    eip712_domain,
                    inner.max_num_bits,
                    permit,
                )
                .await
                {
                    tracing::error!("CRS generation of request {} failed: {}", req_id, e);
                } else {
                    tracing::info!(
                        "CRS generation of request {} completed successfully.",
                        req_id
                    );
                }
            }
            .instrument(tracing::Span::current()),
        );
        self.thread_handles.write().await.add(handle);
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
            guarded_meta_store.retrieve(&request_id)
        };
        let crs_info = handle_res_mapping(status, &request_id, "CRS").await?;

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
}

#[allow(clippy::too_many_arguments)]
async fn key_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Sync + Send + 'static,
>(
    req_id: &RequestId,
    meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
    crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>,
    sk: Arc<PrivateSigKey>,
    params: DKGParams,
    keyset_config: KeySetConfig,
    keyset_added_info: Option<KeySetAddedInfo>,
    eip712_domain: Option<Eip712Domain>,
    permit: OwnedSemaphorePermit,
) -> Result<(), anyhow::Error> {
    let _permit = permit;
    let start = tokio::time::Instant::now();
    {
        // Check if the key already exists
        if crypto_storage
            .read_cloned_centralized_fhe_keys_from_cache(req_id)
            .await
            .is_ok()
        {
            let mut guarded_meta_store = meta_store.write().await;
            METRICS
                .increment_error_counter(OP_KEYGEN, ERR_KEY_EXISTS)
                .map_err(|e| {
                    tracing::warn!("Failed to increment error counter: {:?}", e);
                    anyhow::anyhow!("Failed to increment error counter: {:?}", e)
                })?;
            let _ = guarded_meta_store.update(
                req_id,
                Err(format!(
                    "Failed key generation: Key with ID {req_id} already exists!"
                )),
            );
            return Ok(());
        }
    }
    match keyset_config {
        KeySetConfig::Standard(standard_key_set_config) => {
            let (fhe_key_set, key_info) = match async_generate_fhe_keys(
                &sk,
                crypto_storage.clone(),
                params,
                standard_key_set_config,
                keyset_added_info,
                None,
                eip712_domain.as_ref(),
            )
            .await
            {
                Ok((fhe_key_set, key_info)) => (fhe_key_set, key_info),
                Err(e) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        req_id,
                        Err(format!(
                            "Failed key generation for key with ID {req_id}: {e}"
                        )),
                    );
                    return Err(anyhow::anyhow!("Failed key generation: {}", e));
                }
            };

            crypto_storage
                .write_centralized_keys_with_meta_store(req_id, key_info, fhe_key_set, meta_store)
                .await;

            tracing::info!("⏱️ Core Event Time for Keygen: {:?}", start.elapsed());
        }

        KeySetConfig::DecompressionOnly => match keyset_added_info {
            Some(added_info) => {
                match (
                    added_info.from_keyset_id_decompression_only,
                    added_info.to_keyset_id_decompression_only,
                ) {
                    (Some(from), Some(to)) => {
                        let decompression_key =
                            async_generate_decompression_keys(crypto_storage.clone(), &from, &to)
                                .await?;
                        let info = match crate::engine::base::compute_info(
                            &sk,
                            &decompression_key,
                            eip712_domain.as_ref(),
                        ) {
                            Ok(info) => HashMap::from_iter(vec![(
                                kms_grpc::rpc_types::PubDataType::DecompressionKey,
                                info,
                            )]),
                            Err(_) => {
                                let mut guarded_meta_storage = meta_store.write().await;
                                // We cannot do much if updating the storage fails at this point...
                                let _ = guarded_meta_storage.update(
                                    req_id,
                                    Err("Failed to compute decompression key info".to_string()),
                                );
                                anyhow::bail!("Failed to compute decompression key info");
                            }
                        };
                        crypto_storage
                            .write_decompression_key_with_meta_store(
                                req_id,
                                decompression_key,
                                info,
                                meta_store,
                            )
                            .await;
                        tracing::info!(
                            "⏱️ Core Event Time for decompression Keygen: {:?}",
                            start.elapsed()
                        );
                    }
                    _ => anyhow::bail!("Missing from and to keyset information"),
                }
            }
            None => {
                anyhow::bail!("Added info is required when only generating a decompression key")
            }
        },
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn crs_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Sync + Send + 'static,
>(
    req_id: &RequestId,
    rng: AesRng,
    meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>,
    sk: Arc<PrivateSigKey>,
    params: DKGParams,
    eip712_domain: Option<Eip712Domain>,
    max_number_bits: Option<u32>,
    permit: OwnedSemaphorePermit,
) -> Result<(), anyhow::Error> {
    let _permit = permit;
    let start = tokio::time::Instant::now();

    let (pp, crs_info) =
        match async_generate_crs(&sk, rng, params, max_number_bits, eip712_domain.as_ref()).await {
            Ok((pp, crs_info)) => (pp, crs_info),
            Err(e) => {
                tracing::error!("Error in inner CRS generation: {}", e);
                let mut guarded_meta_store = meta_store.write().await;
                let _ = guarded_meta_store.update(
                    req_id,
                    Err(format!(
                        "Failed CRS generation for CRS with ID {req_id}: {e}"
                    )),
                );
                METRICS
                    .increment_error_counter(OP_CRS_GEN, ERR_CRS_GEN_FAILED)
                    .ok();
                return Err(anyhow::anyhow!("Failed CRS generation: {}", e));
            }
        };

    crypto_storage
        .write_crs_with_meta_store(req_id, pp, crs_info, meta_store)
        .await;

    tracing::info!("⏱️ Core Event Time for CRS-gen: {:?}", start.elapsed());
    Ok(())
}
