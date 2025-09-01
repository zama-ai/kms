use std::sync::Arc;

use kms_grpc::kms::v1::{
    Empty, PublicDecryptionRequest, PublicDecryptionResponse, PublicDecryptionResponsePayload,
    UserDecryptionRequest, UserDecryptionResponse,
};
use observability::metrics::METRICS;
use observability::metrics_names::{
    ERR_KEY_NOT_FOUND, ERR_PUBLIC_DECRYPTION_FAILED, ERR_USER_DECRYPTION_FAILED,
    OP_PUBLIC_DECRYPT_REQUEST, OP_USER_DECRYPT_REQUEST, TAG_KEY_ID, TAG_PARTY_ID,
    TAG_PUBLIC_DECRYPTION_KIND,
};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::engine::base::compute_external_pt_signature;
use crate::engine::centralized::central_kms::{
    async_user_decrypt, central_public_decrypt, CentralizedKms,
};
use crate::engine::traits::{BackupOperator, BaseKms, ContextManager};
use crate::engine::validation::{
    parse_proto_request_id, validate_public_decrypt_req, validate_user_decrypt_req,
    RequestIdParsingErr, DSEP_PUBLIC_DECRYPTION, DSEP_USER_DECRYPTION,
};
use crate::ok_or_tonic_abort;
use crate::util::meta_store::handle_res_mapping;
use crate::vault::storage::Storage;

/// Implementation of the user_decrypt endpoint
pub async fn user_decrypt_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<UserDecryptionRequest>,
) -> Result<Response<Empty>, Status> {
    // Start timing and counting before any operations
    let mut timer = METRICS
        .time_operation(OP_USER_DECRYPT_REQUEST)
        // Use a constant party ID since this is the central KMS
        .tag(TAG_PARTY_ID, "central")
        .start();

    let permit = service.rate_limiter.start_user_decrypt().await?;

    let inner = request.into_inner();

    let (typed_ciphertexts, link, client_enc_key, client_address, key_id, request_id, domain) =
        validate_user_decrypt_req(&inner).map_err(|e| {
            tracing::error!("Failed to validate user decryption request: {inner:?}, error: {e}");
            Status::invalid_argument("Failed to validate user decryption request: {e:?}")
        })?;

    timer.tags([(TAG_KEY_ID, key_id.as_str())]);

    {
        let mut guarded_meta_store = service.user_decrypt_meta_map.write().await;
        ok_or_tonic_abort(
            guarded_meta_store.insert(&request_id),
            "Could not insert user decryption into meta store".to_string(),
        )?;
    }

    let meta_store = Arc::clone(&service.user_decrypt_meta_map);
    let sig_key = Arc::clone(&service.base_kms.sig_key);
    let crypto_storage = service.crypto_storage.clone();
    let mut rng = service.base_kms.new_rng().await;

    ok_or_tonic_abort(
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
                    METRICS.increment_error_counter(OP_USER_DECRYPT_REQUEST, ERR_KEY_NOT_FOUND);
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
            // NOTE: extra_data is not used in the current implementation
            let extra_data = vec![];
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
                extra_data.clone(),
            )
            .await
            {
                Ok((payload, external_signature)) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store
                        .update(&request_id, Ok((payload, external_signature, extra_data)));
                }
                Result::Err(e) => {
                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store
                        .update(&request_id, Err(format!("Failed user decryption: {e}")));
                    METRICS.increment_error_counter(
                        OP_USER_DECRYPT_REQUEST,
                        ERR_USER_DECRYPTION_FAILED,
                    );
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
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<UserDecryptionResponse>, Status> {
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::UserDecResponse)?;

    let status = {
        let guarded_meta_store = service.user_decrypt_meta_map.read().await;
        guarded_meta_store.retrieve(&request_id)
    };

    let (payload, external_signature, extra_data) =
        handle_res_mapping(status, &request_id, "UserDecryption").await?;

    // sign the response
    let sig_payload_vec = ok_or_tonic_abort(
        bc2wrap::serialize(&payload),
        format!("Could not convert payload to bytes {payload:?}"),
    )?;

    let sig = ok_or_tonic_abort(
        service.sign(&DSEP_USER_DECRYPTION, &sig_payload_vec),
        format!("Could not sign payload {payload:?}"),
    )?;

    Ok(Response::new(UserDecryptionResponse {
        signature: sig.sig.to_vec(),
        external_signature,
        payload: Some(payload),
        extra_data,
    }))
}

/// Implementation of the public_decrypt endpoint
pub async fn public_decrypt_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<PublicDecryptionRequest>,
) -> Result<Response<Empty>, Status> {
    // Start timing and counting before any operations
    let mut timer = METRICS
        .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
        // Use a constant party ID since this is the central KMS
        .tag(TAG_PARTY_ID, "central")
        .start();

    let permit = service.rate_limiter.start_pub_decrypt().await?;

    let start = tokio::time::Instant::now();
    let inner = request.into_inner();

    let (ciphertexts, key_id, request_id, eip712_domain) = validate_public_decrypt_req(&inner)
        .map_err(|e| {
            tracing::error!("Failed to validate public decryption request: {inner:?}, error: {e}");
            Status::invalid_argument("Failed to validate public decryption request: {e:?}")
        })?;

    timer.tags([(TAG_KEY_ID, key_id.as_str())]);

    tracing::info!(
        "Decrypting {} ciphertexts using key {} with request id {}",
        ciphertexts.len(),
        key_id.as_str(),
        request_id.as_str()
    );

    {
        let mut guarded_meta_store = service.pub_dec_meta_store.write().await;
        ok_or_tonic_abort(
            guarded_meta_store.insert(&request_id),
            "Could not insert decryption into meta store".to_string(),
        )?;
    }

    let meta_store = Arc::clone(&service.pub_dec_meta_store);
    let sigkey = Arc::clone(&service.base_kms.sig_key);
    let crypto_storage = service.crypto_storage.clone();

    ok_or_tonic_abort(
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
                    METRICS.increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, ERR_KEY_NOT_FOUND);
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

            let extra_data = vec![]; // NOTE: extra_data is not used in the current implementation
            match decryptions {
                Ok(Ok(pts)) => {
                    // sign the plaintexts and handles for external verification (in fhevm)
                    let external_sig = compute_external_pt_signature(
                        &sigkey,
                        ext_handles_bytes,
                        &pts,
                        extra_data.clone(),
                        eip712_domain,
                    );

                    let mut guarded_meta_store = meta_store.write().await;
                    let _ = guarded_meta_store
                        .update(&request_id, Ok((request_id, pts, external_sig, extra_data)));
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
                    METRICS.increment_error_counter(
                        OP_PUBLIC_DECRYPT_REQUEST,
                        ERR_PUBLIC_DECRYPTION_FAILED,
                    );
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
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<PublicDecryptionResponse>, Status> {
    let request_id = parse_proto_request_id(
        &request.into_inner(),
        RequestIdParsingErr::PublicDecResponse,
    )?;
    tracing::debug!("Received get key gen result request with id {}", request_id);

    let status = {
        let guarded_meta_store = service.pub_dec_meta_store.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let (retrieved_req_id, plaintexts, external_signature, extra_data) =
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
        request_id: Some(retrieved_req_id.into()),
    };

    let kms_sig_payload_vec = ok_or_tonic_abort(
        bc2wrap::serialize(&kms_sig_payload),
        format!("Could not convert payload to bytes {kms_sig_payload:?}"),
    )?;

    // sign the decryption result with the central KMS key
    let sig = ok_or_tonic_abort(
        service.sign(&DSEP_PUBLIC_DECRYPTION, &kms_sig_payload_vec),
        format!("Could not sign payload {kms_sig_payload:?}"),
    )?;
    Ok(Response::new(PublicDecryptionResponse {
        signature: sig.sig.to_vec(),
        payload: Some(kms_sig_payload),
        external_signature,
        extra_data,
    }))
}
