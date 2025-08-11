use std::sync::Arc;

use kms_grpc::kms::v1::{
    Empty, PublicDecryptionRequest, PublicDecryptionResponse, PublicDecryptionResponsePayload,
    UserDecryptionRequest, UserDecryptionResponse,
};
use observability::metrics::METRICS;
use observability::metrics_names::{
    ERR_KEY_NOT_FOUND, ERR_PUBLIC_DECRYPTION_FAILED, ERR_RATE_LIMIT_EXCEEDED,
    ERR_USER_DECRYPTION_FAILED, OP_PUBLIC_DECRYPT_REQUEST, OP_USER_DECRYPT_REQUEST, TAG_KEY_ID,
    TAG_PARTY_ID, TAG_PUBLIC_DECRYPTION_KIND,
};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::engine::base::compute_external_pt_signature;
use crate::engine::centralized::central_kms::{
    async_user_decrypt, central_public_decrypt, RealCentralizedKms,
};
use crate::engine::traits::BaseKms;
use crate::engine::validation::{
    validate_public_decrypt_req, validate_request_id, validate_user_decrypt_req,
    DSEP_PUBLIC_DECRYPTION, DSEP_USER_DECRYPTION,
};
use crate::tonic_handle_potential_err;
use crate::util::meta_store::handle_res_mapping;
use crate::vault::storage::Storage;

/// Implementation of the user_decrypt endpoint
pub async fn user_decrypt_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<UserDecryptionRequest>,
) -> Result<Response<Empty>, Status> {
    // Start timing and counting before any operations
    let mut timer = METRICS
        .time_operation(OP_USER_DECRYPT_REQUEST)
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
        .increment_request_counter(OP_USER_DECRYPT_REQUEST)
        .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

    let permit = service
        .rate_limiter
        .start_user_decrypt()
        .await
        .inspect_err(|_e| {
            if let Err(e) =
                METRICS.increment_error_counter(OP_USER_DECRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED)
            {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
        })?;

    let inner = request.into_inner();

    let (typed_ciphertexts, link, client_enc_key, client_address, key_id, request_id, domain) =
        tonic_handle_potential_err(
            validate_user_decrypt_req(&inner),
            format!("Failed to validate user decryption request: {inner:?}"),
        )?;

    if let Some(b) = timer.as_mut() {
        //We log but we don't want to return early because timer failed
        let _ = b
            .tags([(TAG_KEY_ID, key_id.as_str())])
            .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
    }

    {
        let mut guarded_meta_store = service.user_decrypt_meta_map.write().await;
        tonic_handle_potential_err(
            guarded_meta_store.insert(&request_id),
            "Could not insert user decryption into meta store".to_string(),
        )?;
    }

    let meta_store = Arc::clone(&service.user_decrypt_meta_map);
    let sig_key = Arc::clone(&service.base_kms.sig_key);
    let crypto_storage = service.crypto_storage.clone();
    let mut rng = service.base_kms.new_rng().await;

    tonic_handle_potential_err(
        crypto_storage.refresh_centralized_fhe_keys(&key_id).await,
        format!("Cannot find centralized keys with key ID {key_id}"),
    )?;

    let mut handles = service.thread_handles.write().await;

    let metric_tags = vec![
        (TAG_KEY_ID, key_id.as_str()),
        (TAG_PUBLIC_DECRYPTION_KIND, "centralized".to_string()),
    ];

    let server_verf_key = service.base_kms.get_serialized_verf_key();

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
                        METRICS.increment_error_counter(OP_USER_DECRYPT_REQUEST, ERR_KEY_NOT_FOUND)
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
                "Starting user decryption using key_id {} for request ID {}",
                &key_id,
                &request_id
            );
            match async_user_decrypt::<PubS, PrivS>(
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
                    let _ =
                        guarded_meta_store.update(&request_id, Ok((payload, external_signature)));
                }
                Result::Err(e) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store
                        .update(&request_id, Err(format!("Failed user decryption: {e}")));
                    METRICS
                        .increment_error_counter(
                            OP_USER_DECRYPT_REQUEST,
                            ERR_USER_DECRYPTION_FAILED,
                        )
                        .ok();
                }
            }
        }
        .instrument(tracing::Span::current()),
    );

    handles.add(handle);
    Ok(Response::new(Empty {}))
}

/// Implementation of the get_user_decryption_result endpoint
pub async fn get_user_decryption_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<UserDecryptionResponse>, Status> {
    let request_id = request.into_inner().into();
    validate_request_id(&request_id)?;

    let status = {
        let guarded_meta_store = service.user_decrypt_meta_map.read().await;
        guarded_meta_store.retrieve(&request_id)
    };

    let (payload, external_signature) =
        handle_res_mapping(status, &request_id, "UserDecryption").await?;

    // sign the response
    let sig_payload_vec = tonic_handle_potential_err(
        bc2wrap::serialize(&payload),
        format!("Could not convert payload to bytes {payload:?}"),
    )?;

    let sig = tonic_handle_potential_err(
        service.sign(&DSEP_USER_DECRYPTION, &sig_payload_vec),
        format!("Could not sign payload {payload:?}"),
    )?;

    Ok(Response::new(UserDecryptionResponse {
        signature: sig.sig.to_vec(),
        external_signature,
        payload: Some(payload),
    }))
}

/// Implementation of the public_decrypt endpoint
pub async fn public_decrypt_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<PublicDecryptionRequest>,
) -> Result<Response<Empty>, Status> {
    // Start timing and counting before any operations
    let mut timer = METRICS
        .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
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
        .increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST)
        .map_err(|e| Status::internal(e.to_string()))?;

    let permit = service
        .rate_limiter
        .start_pub_decrypt()
        .await
        .inspect_err(|_e| {
            if let Err(e) =
                METRICS.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_RATE_LIMIT_EXCEEDED)
            {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
        })?;

    let start = tokio::time::Instant::now();
    let inner = request.into_inner();

    let (ciphertexts, key_id, request_id, eip712_domain) = tonic_handle_potential_err(
        validate_public_decrypt_req(&inner),
        format!("Failed to validate decrypt request {inner:?}"),
    )?;

    if let Some(b) = timer.as_mut() {
        //We log but we don't want to return early because timer failed
        let _ = b
            .tags([(TAG_KEY_ID, key_id.as_str())])
            .map_err(|e| tracing::warn!("Failed to add tag key_id or request_id: {}", e));
    }

    tracing::info!(
        "Decrypting {} ciphertexts using key {} with request id {}",
        ciphertexts.len(),
        key_id.as_str(),
        request_id.as_str()
    );

    {
        let mut guarded_meta_store = service.pub_dec_meta_store.write().await;
        tonic_handle_potential_err(
            guarded_meta_store.insert(&request_id),
            "Could not insert decryption into meta store".to_string(),
        )?;
    }

    let meta_store = Arc::clone(&service.pub_dec_meta_store);
    let sigkey = Arc::clone(&service.base_kms.sig_key);
    let crypto_storage = service.crypto_storage.clone();

    tonic_handle_potential_err(
        crypto_storage.refresh_centralized_fhe_keys(&key_id).await,
        format!("Cannot find centralized keys with key ID {key_id}"),
    )?;

    let metric_tags = vec![
        (TAG_KEY_ID, key_id.as_str()),
        (TAG_PUBLIC_DECRYPTION_KIND, "centralized".to_string()),
    ];
    // we do not need to hold the handle,
    // the result of the computation is tracked by the pub_dec_meta_store
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
                    if let Err(e) = METRICS
                        .increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_KEY_NOT_FOUND)
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
                    central_public_decrypt::<PubS, PrivS>(&keys, &ciphertexts, metric_tags);
                let _ = send.send(decryptions);
            });
            let decryptions = recv.await;

            match decryptions {
                Ok(Ok(pts)) => {
                    // sign the plaintexts and handles for external verification (in fhevm)
                    let external_sig = compute_external_pt_signature(
                        &sigkey,
                        ext_handles_bytes,
                        &pts,
                        eip712_domain,
                    );

                    let mut guarded_meta_store = meta_store.write().await;
                    let _ =
                        guarded_meta_store.update(&request_id, Ok((request_id, pts, external_sig)));
                    tracing::info!(
                        "⏱️ Core Event Time for decryption computation: {:?}",
                        start.elapsed()
                    );
                }
                Err(e) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store.update(
                        &request_id,
                        Err(format!("Error collecting decrypt result: {e:?}")),
                    );
                }
                Ok(Err(e)) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    if let Err(e) = METRICS.increment_error_counter(
                        OP_PUBLIC_DECRYPT_REQUEST,
                        ERR_PUBLIC_DECRYPTION_FAILED,
                    ) {
                        tracing::warn!("Failed to increment error counter: {:?}", e);
                    }
                    let _ = guarded_meta_store.update(
                        &request_id,
                        Err(format!("Error during decryption computation: {e}")),
                    );
                }
            }
        }
        .instrument(tracing::Span::current()),
    );

    Ok(Response::new(Empty {}))
}

/// Implementation of the get_public_decryption_result endpoint
pub async fn get_public_decryption_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<PublicDecryptionResponse>, Status> {
    let request_id = request.into_inner().into();
    tracing::debug!("Received get key gen result request with id {}", request_id);
    validate_request_id(&request_id)?;

    let status = {
        let guarded_meta_store = service.pub_dec_meta_store.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let (retrieved_req_id, plaintexts, external_signature) =
        handle_res_mapping(status, &request_id, "Decryption").await?;

    if retrieved_req_id != request_id {
        return Err(Status::not_found(format!(
            "Request ID mismatch: expected {request_id}, got {retrieved_req_id}",
        )));
    }

    tracing::debug!(
        "Returning plaintext(s) for request ID {}: {:?}. External signature: {:x?}",
        request_id,
        plaintexts,
        external_signature
    );

    let server_verf_key = service.get_serialized_verf_key();

    // the payload to be signed for verification inside the KMS
    let kms_sig_payload = PublicDecryptionResponsePayload {
        plaintexts,
        verification_key: server_verf_key,
        #[allow(deprecated)] // we have to allow to fill the struct
        digest: vec![],
        external_signature: Some(external_signature),
        request_id: Some(retrieved_req_id.into()),
    };

    let kms_sig_payload_vec = tonic_handle_potential_err(
        bc2wrap::serialize(&kms_sig_payload),
        format!("Could not convert payload to bytes {kms_sig_payload:?}"),
    )?;

    // sign the decryption result with the central KMS key
    let sig = tonic_handle_potential_err(
        service.sign(&DSEP_PUBLIC_DECRYPTION, &kms_sig_payload_vec),
        format!("Could not sign payload {kms_sig_payload:?}"),
    )?;
    Ok(Response::new(PublicDecryptionResponse {
        signature: sig.sig.to_vec(),
        payload: Some(kms_sig_payload),
    }))
}
