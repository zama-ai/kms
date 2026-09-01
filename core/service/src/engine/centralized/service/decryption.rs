use crate::consts::DURATION_WAITING_ON_RESULT_SECONDS;
use crate::cryptography::internal_crypto_types::LegacySerialization;
use crate::engine::base::{PubDecCallValues, UserDecryptCallValues, sign_public_decryption_result};
use crate::engine::centralized::central_kms::{
    CentralizedKms, async_user_decrypt, central_public_decrypt,
};
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::utils::MetricedError;
use crate::engine::validation::{
    RequestIdParsingErr, parse_grpc_request_id, parse_optional_grpc_request_id,
    validate_public_decrypt_req, validate_user_decrypt_req,
};
use crate::util::meta_store::{
    add_or_redo_failed_in_meta_store, retrieve_from_meta_store_with_timeout,
    update_req_in_meta_store,
};
use crate::vault::storage::{Storage, StorageExt};
use kms_grpc::RequestId;
use kms_grpc::kms::v1::{
    Empty, PublicDecryptionRequest, PublicDecryptionResponse, PublicDecryptionResponsePayload,
    UserDecryptionRequest, UserDecryptionResponse,
};
use observability::metrics::METRICS;
use observability::metrics_names::{
    CENTRAL_TAG, OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, OP_USER_DECRYPT_REQUEST,
    OP_USER_DECRYPT_RESULT, TAG_PARTY_ID,
};
use std::sync::Arc;
use thread_handles::spawn_compute_bound;
use tonic::{Code, Request, Response};
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
    METRICS.increment_request_counter(OP_USER_DECRYPT_REQUEST);

    let permit = service.rate_limiter.start_user_decrypt().await?;
    let timer = METRICS
        .time_operation(OP_USER_DECRYPT_REQUEST)
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();

    let inner = request.into_inner();
    let (
        typed_ciphertexts,
        link,
        client_enc_key_bytes,
        receiver,
        request_id,
        key_id,
        context_id,
        epoch_id,
        domain,
        extra_data,
        signing_schemes,
    ) = validate_user_decrypt_req(&inner)?;
    if !service
        .context_manager
        .mpc_context_exists_in_cache(&context_id)
        .await
    {
        return Err(MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("context at ID {context_id} not found"),
            tonic::Code::NotFound,
        ));
    }

    let keys = service
        .crypto_storage
        .read_centralized_fhe_keys(&key_id.into(), &epoch_id)
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_USER_DECRYPT_REQUEST,
                Some(request_id),
                anyhow::anyhow!("Key ID {key_id} not found: {e}"),
                tonic::Code::NotFound,
            )
        })?;
    let sig_key = service.base_kms.sig_key().map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
            tonic::Code::FailedPrecondition,
        )
    })?;

    let server_verf_key = sig_key.verf_key().to_legacy_bytes().map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Failed to serialize server verification key: {e:?}"),
            tonic::Code::Internal,
        )
    })?;

    let meta_store = Arc::clone(&service.user_dec_meta_store);
    let mut rng = service.base_kms.new_rng().await;
    let meta_permit = add_or_redo_failed_in_meta_store(
        &service.user_dec_meta_store,
        &request_id,
        OP_USER_DECRYPT_REQUEST,
    )
    .await?;

    tokio::spawn(
        async move {
            let _timer = timer;
            let _permit = permit;
            let meta_permit = meta_permit;

            tracing::info!(
                "Starting user decryption using key_id {} for request ID {}",
                &key_id,
                &request_id
            );
            let res = async_user_decrypt::<PubS, PrivS>(
                &keys,
                &sig_key,
                &mut rng,
                &typed_ciphertexts,
                &link,
                &client_enc_key_bytes,
                &receiver,
                server_verf_key,
                &domain,
                extra_data,
                &signing_schemes,
            )
            .await;
            let _ =
                update_req_in_meta_store(&meta_store, meta_permit, res, OP_USER_DECRYPT_REQUEST)
                    .await;
        }
        .instrument(tracing::Span::current()),
    );

    Ok(Response::new(Empty {}))
}

/// Implementation of the user_decrypt_sync endpoint
pub async fn user_decrypt_sync_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<UserDecryptionRequest>,
) -> Result<Response<UserDecryptionResponse>, MetricedError> {
    // `user_decrypt_impl` consumes the request, so keep the raw id for fetching the result below.
    let raw_request_id = request.get_ref().request_id.clone();

    match user_decrypt_impl(service, request).await {
        Ok(_empty) => (),
        // Already succeeded, in flight, or tombstoned: attach to the existing entry
        Err(e) if e.code() == tonic::Code::AlreadyExists => e.defuse(),
        Err(e) => return Err(e),
    }

    // `user_decrypt_impl` accepted the request, so its id must parse.
    let request_id: RequestId =
        parse_optional_grpc_request_id(&raw_request_id, RequestIdParsingErr::UserDecRequest)
            .map_err(|e| {
                MetricedError::new(OP_USER_DECRYPT_REQUEST, None, e, Code::InvalidArgument)
            })?;

    get_user_decryption_result_impl(service, Request::new(request_id.into())).await
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
    METRICS.increment_request_counter(OP_USER_DECRYPT_RESULT);

    let request_id =
        parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::UserDecRequest).map_err(
            |e| {
                MetricedError::new(
                    OP_USER_DECRYPT_RESULT,
                    None,
                    e,
                    tonic::Code::InvalidArgument,
                )
            },
        )?;

    let arc = retrieve_from_meta_store_with_timeout(
        &service.user_dec_meta_store,
        &request_id,
        OP_USER_DECRYPT_RESULT,
        DURATION_WAITING_ON_RESULT_SECONDS,
    )
    .await?;
    let UserDecryptCallValues {
        payload,
        signature,
        external_signature,
        extra_data,
        signatures,
    } = (*arc).clone();

    Ok(Response::new(UserDecryptionResponse {
        signature,
        signatures,
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
    METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST);

    let permit = service.rate_limiter.start_pub_decrypt().await?;
    let timer = METRICS
        .time_operation(OP_PUBLIC_DECRYPT_REQUEST)
        // Use a constant party ID since this is the central KMS
        .tag(TAG_PARTY_ID, CENTRAL_TAG.to_string())
        .start();
    let inner = request.into_inner();
    let (
        ciphertexts,
        request_id,
        key_id,
        context_id,
        epoch_id,
        eip712_domain,
        extra_data,
        signing_schemes,
    ) = validate_public_decrypt_req(&inner)?;

    if !service
        .context_manager
        .mpc_context_exists_in_cache(&context_id)
        .await
    {
        return Err(MetricedError::new(
            OP_PUBLIC_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("context at ID {context_id} not found"),
            tonic::Code::NotFound,
        ));
    }
    // Observe we accept any epoch ID
    let start = tokio::time::Instant::now();

    tracing::info!(
        "Decrypting {} ciphertexts using key {} with request id {}",
        ciphertexts.len(),
        key_id.as_str(),
        request_id.as_str()
    );

    let keys = service
        .crypto_storage
        .read_centralized_fhe_keys(&key_id.into(), &epoch_id)
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_PUBLIC_DECRYPT_REQUEST,
                Some(request_id),
                anyhow::anyhow!("Key ID {key_id} not found: {e}"),
                tonic::Code::NotFound,
            )
        })?;
    let sig_key = service.base_kms.sig_key().map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Signing key is not present. This should only happen when server is booted in recovery mode: {}", e),
            tonic::Code::FailedPrecondition,
        )
    })?;
    let server_verf_key = service.base_kms.verf_key().to_legacy_bytes().map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_REQUEST,
            Some(request_id),
            anyhow::anyhow!("Failed to serialize server verification key: {e:?}"),
            tonic::Code::Internal,
        )
    })?;
    // Insert a fresh entry; if the id previously failed, it is retried instead
    // of rejected, while a successful or in-flight id still returns AlreadyExists.
    let meta_permit = add_or_redo_failed_in_meta_store(
        &service.pub_dec_meta_store,
        &request_id,
        OP_PUBLIC_DECRYPT_REQUEST,
    )
    .await?;

    let meta_store = Arc::clone(&service.pub_dec_meta_store);

    // we do not need to hold the handle,
    // the result of the computation is tracked by the pub_dec_meta_store
    let _handle = tokio::spawn(async move {
        let _timer = timer;
        let _permit = permit;
        let meta_permit = meta_permit;
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
            let decryptions = central_public_decrypt::<PubS, PrivS>(&keys, &ciphertexts);
            let _ = send.send(decryptions);
        });
        let decryptions = recv.await;

        let res = match decryptions {
            Ok(Ok(pts)) => {
                let payload = PublicDecryptionResponsePayload {
                    plaintexts: pts,
                    verification_key: server_verf_key,
                    request_id: Some(request_id.into()),
                };
                let signed = spawn_compute_bound(move || {
                    sign_public_decryption_result(
                        &sig_key,
                        &signing_schemes,
                        payload,
                        &ext_handles_bytes,
                        extra_data,
                        &eip712_domain,
                    )
                })
                .await;
                match signed {
                    Ok(Ok(values)) => Ok(values),
                    Err(e) | Ok(Err(e)) => Err(format!("Failed to sign decryption result: {e:?}")),
                }
            }
            Err(e) => Err(format!("Error collecting decrypt result: {e:?}")),
            Ok(Err(e)) => Err(format!("Error during decryption computation: {e}")),
        };
        let _ = update_req_in_meta_store(&meta_store, meta_permit, res, OP_PUBLIC_DECRYPT_REQUEST)
            .await;
        tracing::info!(
            "⏱️ Core Event Time for decryption computation: {:?}",
            start.elapsed()
        );
    })
    .instrument(tracing::Span::current());

    Ok(Response::new(Empty {}))
}

/// Implementation of the public_decrypt_sync endpoint
pub async fn public_decrypt_sync_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<PublicDecryptionRequest>,
) -> Result<Response<PublicDecryptionResponse>, MetricedError> {
    // `public_decrypt_impl` consumes the request, so keep the raw id for fetching the result below
    let raw_request_id = request.get_ref().request_id.clone();

    match public_decrypt_impl(service, request).await {
        Ok(_empty) => (),
        // Already succeeded, in flight, or tombstoned: attach to the existing entry
        Err(e) if e.code() == tonic::Code::AlreadyExists => e.defuse(),
        Err(e) => return Err(e),
    }

    // `public_decrypt_impl` accepted the request, so its id must parse.
    let req_id: RequestId =
        parse_optional_grpc_request_id(&raw_request_id, RequestIdParsingErr::PublicDecRequest)
            .map_err(|e| {
                MetricedError::new(OP_PUBLIC_DECRYPT_REQUEST, None, e, Code::InvalidArgument)
            })?;

    get_public_decryption_result_impl(service, Request::new(req_id.into())).await
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
    METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_RESULT);

    let request_id = parse_grpc_request_id(
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

    let dec_res = retrieve_from_meta_store_with_timeout(
        &service.pub_dec_meta_store,
        &request_id,
        OP_PUBLIC_DECRYPT_RESULT,
        DURATION_WAITING_ON_RESULT_SECONDS,
    )
    .await?;
    let PubDecCallValues {
        payload,
        signature,
        external_signature,
        extra_data,
        signatures,
    } = (*dec_res).clone();

    if payload.request_id != Some(request_id.into()) {
        return Err(MetricedError::new(
            OP_PUBLIC_DECRYPT_RESULT,
            Some(request_id),
            anyhow::anyhow!(
                "Request ID mismatch: expected {request_id}, got {:?}",
                payload.request_id
            ),
            tonic::Code::Internal,
        ));
    }

    tracing::debug!(
        "Returning plaintext(s) for request ID {}: {:?}. External signature: {:x?}",
        request_id,
        payload.plaintexts,
        external_signature
    );

    Ok(Response::new(PublicDecryptionResponse {
        signature,
        signatures,
        payload: Some(payload),
        external_signature,
        extra_data,
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{RequestId, kms::v1::TypedCiphertext};
    use tfhe::xof_key_set::CompressedXofKeySet;

    use crate::{
        cryptography::signatures::PublicSigKey,
        engine::centralized::{
            central_kms::RealCentralizedKms,
            service::key_gen::tests::{setup_test_kms_with_preproc, test_standard_keygen},
        },
        util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext, compute_cipher},
        vault::storage::{crypto_material::CryptoMaterialReader, ram::RamStorage},
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

        // at this point the key is generated (compressed by default)
        // We execute in the secure mode, i.e. pretending that the preprocessing is done
        test_standard_keygen(&kms, key_id, Some(&preproc_id), false).await;

        // Read compressed keyset and decompress to get pk + server key
        let compressed_keyset: CompressedXofKeySet = {
            let storage = kms.crypto_storage.inner.public_storage.lock().await;
            CryptoMaterialReader::read_from_storage(&*storage, key_id)
                .await
                .unwrap()
        };
        let (pk, key) = compressed_keyset.decompress().into_raw_parts();
        tfhe::set_server_key(key);

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
    use kms_grpc::{RequestId, kms::v1::TypedCiphertext};
    use kms_grpc::{kms::v1::SigningSchemeType, rpc_types::alloy_to_protobuf_domain};
    use rand::SeedableRng;

    use crate::{
        dummy_domain,
        engine::{
            base::derive_request_id,
            centralized::service::decryption::tests::{make_test_msg_ct, setup_test_kms_with_key},
        },
        testing::utils::poll_result_until_ready,
    };

    use super::*;

    fn make_valid_request(
        request_id: RequestId,
        key_id: RequestId,
        ciphertexts: Vec<TypedCiphertext>,
        domain: &kms_grpc::kms::v1::Eip712DomainMsg,
    ) -> PublicDecryptionRequest {
        PublicDecryptionRequest {
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
            request_id: Some(request_id.into()),
            ciphertexts,
            key_id: Some(key_id.into()),
            domain: Some(domain.clone()),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
        }
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sunshine").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);

        let request = make_valid_request(request_id, key_id, ciphertexts, &domain);

        let _ = public_decrypt_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap();

        let response = poll_result_until_ready(|| {
            get_public_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
        })
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
        let valid_request = make_valid_request(request_id, key_id, ct, &domain);

        // missing request Id
        {
            let mut request = valid_request.clone();
            request.request_id = None;
            let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrong request id
        {
            let mut request = valid_request.clone();
            request.request_id = Some(kms_grpc::kms::v1::RequestId {
                request_id: "wrong_id".to_string(),
            });
            let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let mut request = valid_request.clone();
            request.domain = None;
            let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing ciphertexts
        {
            let mut request = valid_request.clone();
            request.ciphertexts.clear();
            let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
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
            let request = make_valid_request(request_id, wrong_key_id, ct, &domain);

            let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);

            let err = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
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
            let request = make_valid_request(request_id, key_id, ct, &domain);
            let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::ResourceExhausted);

            let err = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
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
        let (msg, ct) = make_test_msg_ct(&pk, true);

        let request = make_valid_request(request_id, key_id, ct, &domain);

        // make a normal request, which should pass
        let _ = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap();

        // this should fail since it's using the same ID
        let err = public_decrypt_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        // The sync endpoint instead attaches to the existing entry and returns its result.
        // Attaching is a success path, so it must not record an error: the `AlreadyExists`
        // signal is defused rather than dropped.
        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let response = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.payload.unwrap().plaintexts[0].clone(), msg.into());
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before,
            "attaching to an already-known request ID must not report a failure"
        );
    }

    #[tokio::test]
    async fn sync_call_shares_request_and_result_counters() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sync_counters").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sync_counters").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let request = make_valid_request(request_id, key_id, ciphertexts, &domain);

        let requests_before = METRICS.request_counter_value(OP_PUBLIC_DECRYPT_REQUEST);
        let results_before = METRICS.request_counter_value(OP_PUBLIC_DECRYPT_RESULT);
        public_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap();
        // Check global growth: the counters are shared at the process level.
        assert!(METRICS.request_counter_value(OP_PUBLIC_DECRYPT_REQUEST) > requests_before);
        assert!(METRICS.request_counter_value(OP_PUBLIC_DECRYPT_RESULT) > results_before);
    }

    #[tokio::test]
    async fn sunshine_sync() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sunshine_sync").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine_sync").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);

        let request = make_valid_request(request_id, key_id, ciphertexts, &domain);

        // The sync endpoint returns the response directly, no polling needed.
        let payload = public_decrypt_sync_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner()
            .payload
            .unwrap();
        assert_eq!(payload.plaintexts[0].clone(), msg.into());

        // The request went through the meta-store, so the result stays
        // retrievable through the async result endpoint...
        let again = get_public_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(Some(&payload), again.payload.as_ref());

        // ...and re-sending the same sync request attaches to the existing
        // entry and returns the result instead of failing with `AlreadyExists`.
        let retry = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(Some(&payload), retry.payload.as_ref());
    }

    /// A `request_id` whose previous attempt failed is redone, exactly as re-sending it to the
    /// async endpoint would be, and the sync call returns the new attempt's outcome.
    #[tokio::test]
    async fn sync_redoes_failed_request() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sync_redo").unwrap();
        let (kms, pk, _) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sync_redo").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);

        let request = make_valid_request(request_id, key_id, ciphertexts, &domain);

        // Leave the request ID in the state a failed attempt would leave it in.
        let permit = kms
            .pub_dec_meta_store
            .write()
            .await
            .insert(&request_id)
            .unwrap();
        crate::util::meta_store::update_err_req_in_meta_store(
            &kms.pub_dec_meta_store,
            permit,
            "forced failure".to_string(),
            OP_PUBLIC_DECRYPT_REQUEST,
        )
        .await;

        // The sync call redoes the decryption instead of returning the stored failure, and the
        // plaintext it produces is the one this request asked for.
        let payload = public_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .payload
            .unwrap();
        assert_eq!(payload.plaintexts[0].clone(), msg.into());
    }
}

#[cfg(test)]
mod test_user_decryption {
    use aes_prng::AesRng;
    use kms_grpc::{RequestId, kms::v1::TypedCiphertext};
    use kms_grpc::{kms::v1::SigningSchemeType, rpc_types::alloy_to_protobuf_domain};
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
        testing::utils::poll_result_until_ready,
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

    fn make_valid_request(
        request_id: RequestId,
        key_id: RequestId,
        ciphertexts: Vec<TypedCiphertext>,
        enc_key: Vec<u8>,
        domain: &kms_grpc::kms::v1::Eip712DomainMsg,
    ) -> UserDecryptionRequest {
        let client_address = alloy_primitives::address!("dadB0d80178819F2319190D340ce9A924f783711");
        UserDecryptionRequest {
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
            request_id: Some(request_id.into()),
            typed_ciphertexts: ciphertexts,
            key_id: Some(key_id.into()),
            client_address: client_address.to_checksum(None),
            enc_key,
            domain: Some(domain.clone()),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
            // This is the EVM test path; the Solana fields are exercised by
            // `validation_solana` and the Solana response tests.
            signing_metadata: vec![],
        }
    }

    /// Decrypts the signcrypted payload with `enc_sk` and checks it holds `expected`.
    fn assert_payload_decrypts_to(
        payload: &kms_grpc::kms::v1::UserDecryptionResponsePayload,
        enc_sk: &UnifiedPrivateEncKey,
        expected: TestingPlaintext,
    ) {
        // LEGACY should have been using safe_deserialize
        let signcrypted_msg: HybridKemCt =
            bc2wrap::deserialize_slice(&payload.signcrypted_ciphertexts[0].signcrypted_ciphertext)
                .unwrap();
        // Extract the DecapsulationKey<MlKem512Params> from UnifiedPrivateDecKey
        let decap_key = match enc_sk {
            UnifiedPrivateEncKey::MlKem512(sk) => sk,
            _ => panic!("Expected UnifiedPrivateDecKey::MlKem512"),
        };
        let res = hybrid_ml_kem::dec::<ml_kem::MlKem512>(signcrypted_msg, &decap_key.0).unwrap();
        assert_eq!(
            TestingPlaintext::from((res, tfhe::FheTypes::Bool)),
            expected
        );
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sunshine").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let (enc_key_buf, enc_sk) = make_test_pk(&mut rng);

        let mut request = make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);
        // no signing scheme defaults to ECDSA256k1
        request.signing_schemes.clear();

        let _ = user_decrypt_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap();

        let response = poll_result_until_ready(|| {
            get_user_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
        })
        .await
        .unwrap()
        .into_inner();
        assert_payload_decrypts_to(&response.payload.unwrap(), &enc_sk, msg);
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_invalid_argument").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);
        let valid_request =
            make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);

        // missing request ID
        {
            let mut request = valid_request.clone();
            request.request_id = None;
            let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrongly formatted request ID
        {
            let mut request = valid_request.clone();
            request.request_id = Some(kms_grpc::kms::v1::RequestId {
                request_id: "wrong_id".to_string(),
            });
            let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let mut request = valid_request.clone();
            request.domain = None;
            let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // wrongly formatted client address
        {
            let mut request = valid_request.clone();
            request.client_address = "wrong_address".to_string();
            let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);

            let err = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
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
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);

        // not found when using a wrong key
        {
            let wrong_key_id = derive_request_id("wrong_keyid_decryption_not_found").unwrap();
            let request =
                make_valid_request(request_id, wrong_key_id, ciphertexts, enc_key_buf, &domain);

            let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);

            let err = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
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
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);

        // set the rate limiter bucket size to 0
        // it won't work if we just set it to 1 like crs/keygen because decryption only uses 1 token
        kms.set_bucket_size(0);

        // make a normal request then it should fail
        {
            let request = make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);
            let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::ResourceExhausted);

            let err = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
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
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let (enc_key_buf, enc_sk) = make_test_pk(&mut rng);

        let request = make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);

        // first request should succeed
        let _ = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap();

        // second one should fail
        let err = user_decrypt_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        // The sync endpoint instead attaches to the existing entry and returns its result.
        // Attaching is a success path, so it must not record an error: the `AlreadyExists`
        // signal is defused rather than dropped.
        let recorded_errors_before = crate::engine::utils::handle_error_call_count();
        let response = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_payload_decrypts_to(&response.payload.unwrap(), &enc_sk, msg);
        assert_eq!(
            crate::engine::utils::handle_error_call_count(),
            recorded_errors_before,
            "attaching to an already-known request ID must not report a failure"
        );
    }

    #[tokio::test]
    async fn sync_call_shares_request_and_result_counters() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sync_counters").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sync_counters").unwrap();
        let (_msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let (enc_key_buf, _enc_sk) = make_test_pk(&mut rng);
        let request = make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);

        let requests_before = METRICS.request_counter_value(OP_USER_DECRYPT_REQUEST);
        let results_before = METRICS.request_counter_value(OP_USER_DECRYPT_RESULT);
        user_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap();
        // Check global growth: the counters are shared at the process level.
        assert!(METRICS.request_counter_value(OP_USER_DECRYPT_REQUEST) > requests_before);
        assert!(METRICS.request_counter_value(OP_USER_DECRYPT_RESULT) > results_before);
    }

    #[tokio::test]
    async fn sunshine_sync() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sunshine_sync").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sunshine_sync").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let (enc_key_buf, enc_sk) = make_test_pk(&mut rng);

        let request = make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);

        // The sync endpoint returns the response directly, no polling needed.
        let payload = user_decrypt_sync_impl(&kms, tonic::Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner()
            .payload
            .unwrap();
        assert_payload_decrypts_to(&payload, &enc_sk, msg);

        // The request went through the meta-store, so the result stays
        // retrievable through the async result endpoint...
        let again = get_user_decryption_result_impl(&kms, tonic::Request::new(request_id.into()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(Some(&payload), again.payload.as_ref());

        // ...and re-sending the same sync request attaches to the existing
        // entry and returns the result instead of failing with `AlreadyExists`.
        let retry = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(Some(&payload), retry.payload.as_ref());
    }

    /// A `request_id` whose previous attempt failed is redone, exactly as re-sending it to the
    /// async endpoint would be, and the sync call returns the new attempt's outcome.
    #[tokio::test]
    async fn sync_redoes_failed_request() {
        let mut rng = AesRng::seed_from_u64(1234);
        let key_id = derive_request_id("keyid_decryption_sync_redo").unwrap();
        let (kms, pk, _verf_key) = setup_test_kms_with_key(&mut rng, &key_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let request_id = derive_request_id("req_id_decryption_sync_redo").unwrap();
        let (msg, ciphertexts) = make_test_msg_ct(&pk, true);
        let (enc_key_buf, enc_sk) = make_test_pk(&mut rng);

        let request = make_valid_request(request_id, key_id, ciphertexts, enc_key_buf, &domain);

        // Leave the request ID in the state a failed attempt would leave it in.
        let permit = kms
            .user_dec_meta_store
            .write()
            .await
            .insert(&request_id)
            .unwrap();
        crate::util::meta_store::update_err_req_in_meta_store(
            &kms.user_dec_meta_store,
            permit,
            "forced failure".to_string(),
            OP_USER_DECRYPT_REQUEST,
        )
        .await;

        // The sync call redoes the decryption instead of returning the stored failure, and the
        // plaintext it produces is the one this request asked for.
        let payload = user_decrypt_sync_impl(&kms, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .payload
            .unwrap();
        assert_payload_decrypts_to(&payload, &enc_sk, msg);
    }
}
