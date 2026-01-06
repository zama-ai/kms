use crate::cryptography::internal_crypto_types::LegacySerialization;
use crate::engine::base::compute_external_pt_signature;
use crate::engine::centralized::central_kms::{
    async_user_decrypt, central_public_decrypt, CentralizedKms,
};
use crate::engine::traits::{BackupOperator, BaseKms, ContextManager};
use crate::engine::utils::MetricedError;
use crate::engine::validation::{
    proto_request_id, validate_public_decrypt_req, validate_user_decrypt_req, RequestIdParsingErr,
    DSEP_PUBLIC_DECRYPTION, DSEP_USER_DECRYPTION,
};
use crate::util::meta_store::{
    add_req_to_meta_store, retrieve_from_meta_store, update_err_req_in_meta_store,
    update_req_in_meta_store,
};
use crate::vault::storage::{Storage, StorageExt};
use kms_grpc::kms::v1::{
    Empty, PublicDecryptionRequest, PublicDecryptionResponse, PublicDecryptionResponsePayload,
    UserDecryptionRequest, UserDecryptionResponse,
};
use observability::metrics::METRICS;
use observability::metrics_names::{
    CENTRAL_TAG, OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, OP_USER_DECRYPT_REQUEST,
    OP_USER_DECRYPT_RESULT, TAG_CONTEXT_ID, TAG_EPOCH_ID, TAG_KEY_ID, TAG_PARTY_ID,
};
use std::sync::Arc;
use tonic::{Request, Response};
use tracing::Instrument;

/// Implementation of the user_decrypt endpoint
pub async fn user_decrypt_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<UserDecryptionRequest>,
) -> Result<Response<Empty>, MetricedError> {
    let permit = service
        .rate_limiter
        .start_user_decrypt()
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                None,
                e,
                tonic::Code::ResourceExhausted,
            )
        })?;
    let mut timer = METRICS
        .time_operation(OP_USER_DECRYPT_REQUEST)
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();

    let inner = request.into_inner();
    let (
        typed_ciphertexts,
        link,
        client_enc_key,
        client_address,
        request_id,
        key_id,
        context_id,
        epoch_id,
        domain,
    ) = validate_user_decrypt_req(&inner).map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })?;

    // Use a constant party ID since this is the central KMS
    let metric_tags = vec![
        (TAG_KEY_ID, key_id.to_string()),
        (TAG_CONTEXT_ID, context_id.to_string()),
        (TAG_EPOCH_ID, epoch_id.to_string()),
    ];
    timer.tags(metric_tags.clone());

    match service
        .crypto_storage
        .inner
        .fhe_keys_exist(&key_id.into(), &epoch_id)
        .await
    {
        Ok(true) => {}
        e_or_false => {
            return Err(MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                Some(request_id),
                anyhow::anyhow!("Key ID {} not found: exists={:?}", key_id, e_or_false),
                tonic::Code::NotFound,
            ));
        }
    };

    let meta_store = Arc::clone(&service.user_dec_meta_store);
    let crypto_storage = service.crypto_storage.clone();
    let mut rng = service.base_kms.new_rng().await;
    add_req_to_meta_store(
        &mut service.user_dec_meta_store.write().await,
        &request_id,
        OP_USER_DECRYPT_REQUEST,
    )
    .await?;
    let sig_key = service.base_kms.sig_key().map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
            tonic::Code::FailedPrecondition,
        )
    })?;

    let mut handles = service.thread_handles.write().await;

    let server_verf_key = sig_key.verf_key().to_legacy_bytes().map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Failed to serialize server verification key: {e:?}"),
            tonic::Code::Internal,
        )
    })?;

    let handle = tokio::spawn(
        async move {
            let _timer = timer;
            let _permit = permit;
            let keys = match crypto_storage
                .read_centralized_fhe_keys(&key_id.into(), &epoch_id)
                .await
            {
                Ok(k) => k,
                Err(e) => {
                    let _ = update_err_req_in_meta_store(
                        &mut meta_store.write().await,
                        &request_id,
                        format!("Failed to get key ID {key_id} with error {e:?}"),
                        OP_USER_DECRYPT_REQUEST,
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
            let res = async_user_decrypt::<PubS, PrivS>(
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
            .await;
            let res_with_extra_data = res.map(|(payload, sig)| (payload, sig, extra_data));
            let _ = update_req_in_meta_store(
                &mut meta_store.write().await,
                &request_id,
                res_with_extra_data,
                OP_USER_DECRYPT_REQUEST,
            );
        }
        .instrument(tracing::Span::current()),
    );

    handles.add(handle);
    Ok(Response::new(Empty {}))
}

/// Implementation of the get_user_decryption_result endpoint
pub async fn get_user_decryption_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<UserDecryptionResponse>, MetricedError> {
    let request_id = proto_request_id(&request.into_inner(), RequestIdParsingErr::UserDecRequest)
        .map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_RESULT,
            None,
            e,
            tonic::Code::InvalidArgument,
        )
    })?;

    let (payload, external_signature, extra_data) = retrieve_from_meta_store(
        service.user_dec_meta_store.read().await,
        &request_id,
        OP_USER_DECRYPT_RESULT,
    )
    .await?;

    // sign the response
    let sig_payload_vec = bc2wrap::serialize(&payload).map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_RESULT,
            Some(request_id),
            anyhow::anyhow!("Could not serialize user decryption payload: {e}"),
            tonic::Code::Internal,
        )
    })?;

    let sig = service
        .sign(&DSEP_USER_DECRYPTION, &sig_payload_vec)
        .map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_RESULT,
                Some(request_id),
                anyhow::anyhow!("Could not sign user decryption payload: {e}"),
                tonic::Code::Aborted,
            )
        })?;

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
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<PublicDecryptionRequest>,
) -> Result<Response<Empty>, MetricedError> {
    let permit = service
        .rate_limiter
        .start_pub_decrypt()
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                None,
                e,
                tonic::Code::ResourceExhausted,
            )
        })?;
    let mut timer = METRICS
        .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
        // Use a constant party ID since this is the central KMS
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();
    let inner = request.into_inner();
    let (ciphertexts, request_id, key_id, context_id, epoch_id, eip712_domain) =
        validate_public_decrypt_req(&inner).map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                None,
                e,
                tonic::Code::InvalidArgument,
            )
        })?;

    let metric_tags = vec![
        (TAG_KEY_ID, key_id.to_string()),
        (TAG_CONTEXT_ID, context_id.to_string()),
        (TAG_EPOCH_ID, epoch_id.to_string()),
    ];
    timer.tags(metric_tags.clone());

    let keys_exist = match service
        .crypto_storage
        .inner
        .fhe_keys_exist(&key_id.into(), &epoch_id)
        .await
    {
        Ok(exists) => exists,
        Err(e) => {
            tracing::error!(
                "Error checking if keys exist for key_id={}, epoch_id={}: {}",
                key_id,
                epoch_id,
                e
            );
            false
        }
    };
    if !keys_exist {
        return Err(MetricedError::new(
            OP_PUBLIC_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Key ID {} not found", key_id),
            tonic::Code::NotFound,
        ));
    }
    let start = tokio::time::Instant::now();

    tracing::info!(
        "Decrypting {} ciphertexts using key {} with request id {}",
        ciphertexts.len(),
        key_id.as_str(),
        request_id.as_str()
    );

    // if the request already exists, then return the AlreadyExists error
    // otherwise attempt to insert it to the meta store
    add_req_to_meta_store(
        &mut service.pub_dec_meta_store.write().await,
        &request_id,
        OP_PUBLIC_DECRYPT_REQUEST,
    )
    .await?;

    let meta_store = Arc::clone(&service.pub_dec_meta_store);
    let crypto_storage = service.crypto_storage.clone();
    let sig_key = service.base_kms.sig_key().map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
            tonic::Code::FailedPrecondition,
        )
    })?;

    // we do not need to hold the handle,
    // the result of the computation is tracked by the pub_dec_meta_store
    let _handle = tokio::spawn(async move {
        let _timer = timer;
        let _permit = permit;
        let keys = match crypto_storage
            .read_centralized_fhe_keys(&key_id.into(), &epoch_id)
            .await
        {
            Ok(k) => k,
            Err(e) => {
                let _ = update_err_req_in_meta_store(
                    &mut meta_store.write().await,
                    &request_id,
                    format!("Failed to get key ID {key_id} with error {e:?}"),
                    OP_PUBLIC_DECRYPT_REQUEST,
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
        let res = match decryptions {
            Ok(Ok(pts)) => {
                // sign the plaintexts and handles for external verification (in fhevm)
                match compute_external_pt_signature(
                    &sig_key,
                    ext_handles_bytes,
                    &pts,
                    extra_data.clone(),
                    eip712_domain,
                ) {
                    Ok(sig) => Ok((request_id, pts, sig, extra_data)),
                    Err(e) => Err(format!("Failed to compute external signature: {e:?}")),
                }
            }
            Err(e) => Err(format!("Error collecting decrypt result: {e:?}")),
            Ok(Err(e)) => Err(format!("Error during decryption computation: {e}")),
        };
        let _ = update_req_in_meta_store(
            &mut meta_store.write().await,
            &request_id,
            res,
            OP_PUBLIC_DECRYPT_REQUEST,
        );
        tracing::info!(
            "⏱️ Core Event Time for decryption computation: {:?}",
            start.elapsed()
        );
    })
    .instrument(tracing::Span::current());

    Ok(Response::new(Empty {}))
}

/// Implementation of the get_public_decryption_result endpoint
pub async fn get_public_decryption_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<PublicDecryptionResponse>, MetricedError> {
    let request_id = proto_request_id(
        &request.into_inner(),
        RequestIdParsingErr::PublicDecResponse,
    )
    .map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_RESULT,
            None,
            e,
            tonic::Code::InvalidArgument,
        )
    })?;
    tracing::debug!("Received get key gen result request with id {}", request_id);

    let (retrieved_req_id, plaintexts, external_signature, extra_data) = retrieve_from_meta_store(
        service.pub_dec_meta_store.read().await,
        &request_id,
        OP_PUBLIC_DECRYPT_RESULT,
    )
    .await?;

    if retrieved_req_id != request_id {
        return Err(MetricedError::new(
            OP_PUBLIC_DECRYPT_RESULT,
            Some(request_id),
            anyhow::anyhow!("Request ID mismatch: expected {request_id}, got {retrieved_req_id}"),
            tonic::Code::NotFound,
        ));
    }

    tracing::debug!(
        "Returning plaintext(s) for request ID {}: {:?}. External signature: {:x?}",
        request_id,
        plaintexts,
        external_signature
    );

    let server_verf_key = service.base_kms.verf_key().to_legacy_bytes().map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_RESULT,
            Some(request_id),
            anyhow::anyhow!("Failed to serialize server verification key: {e:?}"),
            tonic::Code::Internal,
        )
    })?;

    // the payload to be signed for verification inside the KMS
    let kms_sig_payload = PublicDecryptionResponsePayload {
        plaintexts,
        verification_key: server_verf_key,
        request_id: Some(retrieved_req_id.into()),
    };

    let kms_sig_payload_vec = bc2wrap::serialize(&kms_sig_payload).map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_RESULT,
            Some(request_id),
            anyhow::anyhow!("Could not convert payload to bytes {kms_sig_payload:?}: {e:?}"),
            tonic::Code::Internal,
        )
    })?;

    // sign the decryption result with the central KMS key
    let sig = service
        .base_kms
        .sign(&DSEP_PUBLIC_DECRYPTION, &kms_sig_payload_vec)
        .map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_RESULT,
                Some(request_id),
                anyhow::anyhow!("Could not sign payload {kms_sig_payload_vec:?}: {e:?}"),
                tonic::Code::Aborted,
            )
        })?;
    Ok(Response::new(PublicDecryptionResponse {
        signature: sig.sig.to_vec(),
        payload: Some(kms_sig_payload),
        external_signature,
        extra_data,
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::TypedCiphertext,
        rpc_types::{PubDataType, WrappedPublicKeyOwned},
        RequestId,
    };

    use crate::{
        cryptography::signatures::PublicSigKey,
        engine::centralized::{
            central_kms::RealCentralizedKms,
            service::key_gen::tests::{setup_test_kms_with_preproc, test_standard_keygen},
        },
        util::key_setup::test_tools::{compute_cipher, EncryptionConfig, TestingPlaintext},
        vault::storage::{ram::RamStorage, read_versioned_at_request_id},
    };

    // This function will also output a public key and load the server key into memory
    // so that we can use to encyrpt messages.
    pub(crate) async fn setup_test_kms_with_key(
        rng: &mut AesRng,
        key_id: &RequestId,
    ) -> (
        RealCentralizedKms<RamStorage, RamStorage>,
        tfhe::CompactPublicKey,
        PublicSigKey,
    ) {
        let preproc_id: RequestId = RequestId::new_random(rng);
        let (kms, verf_key) = setup_test_kms_with_preproc(rng, &preproc_id).await;

        // at this point the key is generated
        test_standard_keygen(&kms, key_id, &preproc_id).await;

        let wrapped_pk = kms
            .crypto_storage
            .inner
            .read_cloned_pk(key_id)
            .await
            .unwrap();
        let key: tfhe::ServerKey = {
            let storage = kms.crypto_storage.inner.get_public_storage();
            let guard = storage.lock().await;
            read_versioned_at_request_id(&(*guard), key_id, &PubDataType::ServerKey.to_string())
                .await
                .unwrap()
        };
        tfhe::set_server_key(key);
        let WrappedPublicKeyOwned::Compact(pk) = wrapped_pk;

        (kms, pk, verf_key)
    }

    pub(crate) fn make_test_msg_ct(
        pk: &tfhe::CompactPublicKey,
        msg: bool,
    ) -> (TestingPlaintext, Vec<TypedCiphertext>) {
        let msg = TestingPlaintext::Bool(msg);
        let (ct_buf, ct_format, ct_type) = compute_cipher(
            msg,
            pk,
            None,
            EncryptionConfig {
                compression: false,
                precompute_sns: false,
            },
        );

        (
            msg,
            vec![TypedCiphertext {
                ciphertext: ct_buf,
                fhe_type: ct_type as i32,
                external_handle: vec![],
                ciphertext_format: ct_format as i32,
            }],
        )
    }
}

#[cfg(test)]
mod tests_public_decryption {
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::alloy_to_protobuf_domain;
    use rand::SeedableRng;

    use crate::{
        dummy_domain,
        engine::{
            base::derive_request_id,
            centralized::service::decryption::tests::{make_test_msg_ct, setup_test_kms_with_key},
        },
    };

    use super::*;

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sunshine").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);

        let request = PublicDecryptionRequest {
            request_id: Some(request_id.into()),
            ciphertexts,
            key_id: Some(key_id.into()),
            domain: Some(domain.clone()),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
        };

        let _ = public_decrypt_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap();

        let response =
            get_public_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
                .await
                .unwrap();
        assert_eq!(
            response.into_inner().payload.unwrap().plaintexts[0].clone(),
            msg.into(),
        );
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_invalid_args").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_invalid_args").unwrap();
        let (_msg, ct) = make_test_msg_ct(&pk, true);

        // missing request Id
        {
            let request = PublicDecryptionRequest {
                request_id: None, // missing
                ciphertexts: ct.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };

            let err = public_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrong request id
        {
            let wrong_request_id = kms_grpc::kms::v1::RequestId {
                request_id: "wrong_id".to_string(),
            };
            let request = PublicDecryptionRequest {
                request_id: Some(wrong_request_id),
                ciphertexts: ct.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };

            let err = public_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let request = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: ct.clone(),
                key_id: Some(key_id.into()),
                domain: None, // missing
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = public_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing ciphertexts
        {
            let request = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: vec![], // missing
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = public_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_not_found").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_not_found").unwrap();
        let (_msg, ct) = make_test_msg_ct(&pk, true);

        // request with unknown key id
        {
            let wrong_key_id = derive_request_id("wrong_keyid_decryption_not_found").unwrap();
            let request = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: ct.clone(),
                key_id: Some(wrong_key_id.into()), // wrong
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };

            let err = public_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        // trying to fetch result with unknown request id
        {
            let wrong_request_id = derive_request_id("wrong_req_id_decryption_not_found").unwrap();
            let err = get_public_decryption_result_impl(
                &kms,
                tonic::Request::new(wrong_request_id.into()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_resource_exhausted").unwrap();
        let (mut kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_resource_exhausted").unwrap();
        let (_msg, ct) = make_test_msg_ct(&pk, true);

        // set the rate limiter bucket size to 0
        // it won't work if we just set it to 1 like crs/keygen because decryption only uses 1 token
        kms.set_bucket_size(0);

        // make a normal request then it should fail
        {
            let request = PublicDecryptionRequest {
                request_id: Some(request_id.into()),
                ciphertexts: ct.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = public_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_already_exists").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_already_exists").unwrap();
        let (_msg, ct) = make_test_msg_ct(&pk, true);

        let request = PublicDecryptionRequest {
            request_id: Some(request_id.into()),
            ciphertexts: ct.clone(),
            key_id: Some(key_id.into()),
            domain: Some(domain.clone()),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
        };

        // make a normal request, which should pass
        let _ = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap();

        // this should fail since it's using the same ID
        let err = public_decrypt_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }
}

#[cfg(test)]
mod test_user_decryption {
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::alloy_to_protobuf_domain;
    use rand::SeedableRng;

    use crate::{
        consts::SAFE_SER_SIZE_LIMIT,
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey},
            hybrid_ml_kem::{self, HybridKemCt},
        },
        dummy_domain,
        engine::{
            base::derive_request_id,
            centralized::service::decryption::tests::{make_test_msg_ct, setup_test_kms_with_key},
        },
        util::key_setup::test_tools::TestingPlaintext,
    };

    use super::*;

    fn make_test_pk(rng: &mut AesRng) -> (Vec<u8>, UnifiedPrivateEncKey) {
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, rng);
        let (enc_sk, enc_pk) = encryption.keygen().unwrap();
        let mut enc_key_buf = Vec::new();
        // The key is freshly generated, so we can safely unwrap the serialization
        tfhe::safe_serialization::safe_serialize(&enc_pk, &mut enc_key_buf, SAFE_SER_SIZE_LIMIT)
            .expect("Failed to serialize ephemeral encryption key");

        (enc_key_buf, enc_sk)
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sunshine").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let client_address = alloy_primitives::address!("dadB0d80178819F2319190D340ce9A924f783711");
        let (enc_key_buf, enc_sk) = make_test_pk(&mut rng);

        let request = UserDecryptionRequest {
            request_id: Some(request_id.into()),
            typed_ciphertexts: ciphertexts,
            key_id: Some(key_id.into()),
            client_address: client_address.to_checksum(None),
            enc_key: enc_key_buf,
            domain: Some(domain.clone()),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
        };

        let _ = user_decrypt_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap();

        let response =
            get_user_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
                .await
                .unwrap();
        // LEGACY should have been using safe_deserialize
        let signcrypted_msg: HybridKemCt = bc2wrap::deserialize_unsafe(
            &response
                .into_inner()
                .payload
                .unwrap()
                .signcrypted_ciphertexts[0]
                .signcrypted_ciphertext,
        )
        .unwrap();
        // Extract the DecapsulationKey<MlKem512Params> from UnifiedPrivateDecKey
        let decap_key = match &enc_sk {
            UnifiedPrivateEncKey::MlKem512(sk) => sk,
            _ => panic!("Expected UnifiedPrivateDecKey::MlKem512"),
        };
        let res = hybrid_ml_kem::dec::<ml_kem::MlKem512>(signcrypted_msg, &decap_key.0).unwrap();
        assert_eq!(TestingPlaintext::from((res, tfhe::FheTypes::Bool)), msg);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_invalid_argument").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let client_address = alloy_primitives::address!("dadB0d80178819F2319190D340ce9A924f783711");
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);

        // missing request ID
        {
            let request = UserDecryptionRequest {
                request_id: None,
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_key_buf.clone(),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };

            let err = user_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrongly formatted request ID
        {
            let wrong_request_id = kms_grpc::kms::v1::RequestId {
                request_id: "wrong_id".to_string(),
            };
            let request = UserDecryptionRequest {
                request_id: Some(wrong_request_id),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_key_buf.clone(),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = user_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let request = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_key_buf.clone(),
                domain: None,
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = user_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrongly formatted client address
        {
            let request = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: "wrong_address".to_string(),
                enc_key: enc_key_buf.clone(),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = user_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_invalid_argument").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let client_address = alloy_primitives::address!("dadB0d80178819F2319190D340ce9A924f783711");
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);

        // not found when using a wrong key
        {
            let wrong_key_id = derive_request_id("wrong_keyid_decryption_not_found").unwrap();
            let request = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(wrong_key_id.into()), // wrong
                client_address: client_address.to_checksum(None),
                enc_key: enc_key_buf.clone(),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };

            let err = user_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        // not found while attempting to get a response
        {
            let err = get_user_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_resource_exhausted").unwrap();
        let (mut kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_resource_exhausted").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let client_address = alloy_primitives::address!("dadB0d80178819F2319190D340ce9A924f783711");
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);

        // set the rate limiter bucket size to 0
        // it won't work if we just set it to 1 like crs/keygen because decryption only uses 1 token
        kms.set_bucket_size(0);

        // make a normal request then it should fail
        {
            let request = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_key_buf.clone(),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let err = user_decrypt_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_already_exists").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_already_exists").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let client_address = alloy_primitives::address!("dadB0d80178819F2319190D340ce9A924f783711");
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);

        let request = UserDecryptionRequest {
            request_id: Some(request_id.into()),
            typed_ciphertexts: ciphertexts.clone(),
            key_id: Some(key_id.into()),
            client_address: client_address.to_checksum(None),
            enc_key: enc_key_buf.clone(),
            domain: Some(domain.clone()),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
        };

        // first request should succeed
        let _ = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap();

        // second one should fail
        let err = user_decrypt_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }
}
