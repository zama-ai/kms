use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use itertools::Itertools;
use kms_grpc::kms::v1::{Empty, KeyDigest, KeyGenRequest, KeyGenResult};
use kms_grpc::rpc_types::optional_protobuf_to_alloy_domain;
use kms_grpc::RequestId;
use observability::metrics::METRICS;
use observability::metrics_names::{ERR_KEYGEN_FAILED, ERR_KEY_EXISTS, OP_KEYGEN};
use std::sync::Arc;
use threshold_fhe::execution::keyset_config::KeySetConfig;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::sync::{OwnedSemaphorePermit, RwLock};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::cryptography::signatures::PrivateSigKey;
use crate::engine::base::{
    compute_info_decompression_keygen, retrieve_parameters, KeyGenMetadata, DSEP_PUBDATA_KEY,
};
use crate::engine::centralized::central_kms::{
    async_generate_decompression_keys, async_generate_fhe_keys, CentralizedKms,
};
use crate::engine::keyset_configuration::InternalKeySetConfig;
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::validation::{
    parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
};
use crate::ok_or_tonic_abort;
use crate::util::meta_store::{handle_res_mapping, MetaStore};
use crate::vault::storage::crypto_material::CentralizedCryptoMaterialStorage;
use crate::vault::storage::Storage;

/// Implementation of the key_gen endpoint
pub async fn key_gen_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<KeyGenRequest>,
    #[cfg(feature = "insecure")] check_preproc_id: bool,
) -> Result<Response<Empty>, Status> {
    let _timer = METRICS.time_operation(OP_KEYGEN).start();

    let inner = request.into_inner();
    tracing::info!(
        "centralized key-gen with request id: {:?}",
        inner.request_id
    );
    let req_id =
        parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::KeyGenRequest)?;
    let preproc_id =
        parse_optional_proto_request_id(&inner.preproc_id, RequestIdParsingErr::PreprocRequest)?;

    // context_id is not used in the centralized KMS, but we validate it if present
    let _context_id = match &inner.context_id {
        Some(ctx) => Some(parse_proto_request_id(ctx, RequestIdParsingErr::Context)?),
        None => None,
    };

    let internal_keyset_config =
        InternalKeySetConfig::new(inner.keyset_config, inner.keyset_added_info).map_err(|e| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse KeySetConfig: {e}"),
            )
        })?;

    let eip712_domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;

    // Check for existance of request preprocessing ID
    // also check that the request ID is not used yet
    // If all is ok write the request ID to the meta store
    // All validation must be done before inserting the request ID
    let (params, permit) = {
        // Note that the keygen meta store should be checked first
        // because we do not want to delete the preprocessing ID
        // if the keygen request cannot proceed.
        let mut guarded_meta_store = service.key_meta_map.write().await;
        if guarded_meta_store.exists(&req_id) {
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                format!("Key with ID {req_id} already exists"),
            ));
        };

        let permit = service.rate_limiter.start_keygen().await?;

        let check_meta_store = {
            #[cfg(feature = "insecure")]
            {
                check_preproc_id
            }
            #[cfg(not(feature = "insecure"))]
            true
        };
        let params = if check_meta_store {
            let mut preproc_meta_store = service.preprocessing_meta_store.write().await;
            if !preproc_meta_store.exists(&preproc_id) {
                return Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Preprocessing ID {preproc_id} not found"),
                ));
            }
            let preproc = preproc_meta_store.delete(&preproc_id);
            let preproc_bucket = handle_res_mapping(preproc, &preproc_id, "Preprocessing").await?;
            if preproc_bucket.preprocessing_id != preproc_id {
                return Err(tonic::Status::new(
                    tonic::Code::Internal,
                    format!(
                        "Preprocessing ID mismatch: expected {}, got {}",
                        preproc_id, preproc_bucket.preprocessing_id
                    ),
                ));
            }
            preproc_bucket.dkg_param
        } else {
            retrieve_parameters(inner.params)?
        };

        // Insert [HandlerStatus::Started] into the meta store.
        // Note that this will fail if the request ID is already in the meta store
        ok_or_tonic_abort(
            guarded_meta_store.insert(&req_id),
            "Could not insert key generation into meta store".to_string(),
        )?;
        (params, permit)
    };

    let meta_store = Arc::clone(&service.key_meta_map);
    let crypto_storage = service.crypto_storage.clone();
    let sk = Arc::clone(&service.base_kms.sig_key);

    let handle = service.tracker.spawn(
        async move {
            let _timer = _timer;
            if let Err(e) = key_gen_background(
                &req_id,
                &preproc_id,
                meta_store,
                crypto_storage,
                sk,
                params,
                internal_keyset_config,
                eip712_domain,
                permit,
            )
            .await
            {
                METRICS.increment_error_counter(OP_KEYGEN, ERR_KEYGEN_FAILED);
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
    service.thread_handles.write().await.add(handle);

    Ok(Response::new(Empty {}))
}

/// Implementation of the get_key_gen_result endpoint
pub async fn get_key_gen_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<KeyGenResult>, Status> {
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::KeyGenResponse)?;
    tracing::debug!("Received get key gen result request with id {}", request_id);

    let status = {
        let guarded_meta_store = service.key_meta_map.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let res = handle_res_mapping(status, &request_id, "Key generation").await?;

    match res {
        KeyGenMetadata::Current(res) => {
            if request_id != res.key_id {
                return Err(Status::internal(format!(
                    "Request ID mismatch: expected {}, got {}",
                    request_id, res.key_id
                )));
            }
            let key_digests = res
                .key_digest_map
                .into_iter()
                .sorted_by_key(|x| x.0)
                .map(|(key, digest)| KeyDigest {
                    key_type: key.to_string(),
                    digest,
                })
                .collect::<Vec<_>>();

            Ok(Response::new(KeyGenResult {
                request_id: Some(request_id.into()),
                preprocessing_id: Some(res.preprocessing_id.into()),
                key_digests,
                external_signature: res.external_signature,
            }))
        }
        KeyGenMetadata::LegacyV0(_res) => {
            tracing::warn!(
                "Legacy key generation result for request ID: {}",
                request_id
            );
            // Because this is a legacy result and the call path will not reach here
            // (because a restart is needed to upgrade to the new version and the meta store is deleted from RAM),
            // we just return empty values for the fields below.
            Ok(Response::new(KeyGenResult {
                request_id: Some(request_id.into()),
                preprocessing_id: None,
                // we do not attempt to convert the legacy key digest map
                // because it does not match the format to the current one
                // since no domain separation is used
                key_digests: Vec::new(),
                external_signature: vec![],
            }))
        }
    }
}

/// Background task for key generation
#[allow(clippy::too_many_arguments)]
pub(crate) async fn key_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
>(
    req_id: &RequestId,
    preproc_id: &RequestId,
    meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    sk: Arc<PrivateSigKey>,
    params: DKGParams,
    internal_keyset_config: InternalKeySetConfig,
    eip712_domain: Eip712Domain,
    permit: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
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
            METRICS.increment_error_counter(OP_KEYGEN, ERR_KEY_EXISTS);
            let _ = guarded_meta_store.update(
                req_id,
                Err(format!(
                    "Failed key generation: Key with ID {req_id} already exists!"
                )),
            );
            return Ok(());
        }
    }
    match internal_keyset_config.keyset_config() {
        KeySetConfig::Standard(standard_key_set_config) => {
            let (fhe_key_set, key_info) = match async_generate_fhe_keys(
                &sk,
                crypto_storage.clone(),
                params,
                standard_key_set_config.to_owned(),
                internal_keyset_config.get_compression_id()?,
                req_id,
                preproc_id,
                None,
                eip712_domain,
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

        KeySetConfig::DecompressionOnly => {
            let (from, to) = internal_keyset_config.get_from_and_to()?;
            let decompression_key =
                async_generate_decompression_keys(crypto_storage.clone(), &from, &to).await?;
            let info = match compute_info_decompression_keygen(
                &sk,
                &DSEP_PUBDATA_KEY,
                preproc_id,
                req_id,
                &decompression_key,
                &eip712_domain,
            ) {
                Ok(info) => info,
                Err(e) => {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let err_msg = format!("Failed to compute decompression key info: {e}");
                    let _ = guarded_meta_storage.update(req_id, Err(err_msg.clone()));
                    anyhow::bail!(err_msg);
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
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::{FheParameter, KeyGenPreprocRequest},
        rpc_types::alloy_to_protobuf_domain,
    };
    use rand::SeedableRng;

    use crate::{
        cryptography::signatures::PublicSigKey,
        dummy_domain,
        engine::{
            base::derive_request_id,
            centralized::{
                central_kms::RealCentralizedKms,
                service::{preprocessing_impl, tests::setup_central_test_kms},
            },
        },
        vault::storage::ram::RamStorage,
    };

    use super::*;

    pub(crate) async fn setup_test_kms_with_preproc(
        rng: &mut AesRng,
        preproc_id: &RequestId,
    ) -> (RealCentralizedKms<RamStorage, RamStorage>, PublicSigKey) {
        let (kms, verf_key) = setup_central_test_kms(rng).await;

        // insert a preproc ID
        let preproc_req = KeyGenPreprocRequest {
            params: FheParameter::Test.into(),
            keyset_config: None,
            request_id: Some((*preproc_id).into()),
            context_id: None,
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
        };

        // Because preprocessing does not do anything useful in the centralized KMS,
        // it is here only to make sure the API is consistent with the threshold KMS,
        // so the grpc call is fast and we do not need to check the result if the call succeeded.
        preprocessing_impl(&kms, tonic::Request::new(preproc_req))
            .await
            .unwrap();
        (kms, verf_key)
    }

    pub(crate) async fn test_standard_keygen(
        kms: &RealCentralizedKms<RamStorage, RamStorage>,
        req_id: &RequestId,
        preproc_id: &RequestId,
    ) {
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some((*req_id).into()),
            context_id: None,
            preproc_id: Some((*preproc_id).into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
        };
        let _ = key_gen_impl(
            kms,
            tonic::Request::new(request),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap();

        // no need to wait because get result is semi-blocking
        let _res = get_key_gen_result_impl(kms, tonic::Request::new((*req_id).into()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_sunshine_preproc").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let request_id = derive_request_id("test_keygen_sunshine").unwrap();
        test_standard_keygen(&kms, &request_id, &preproc_id).await
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_sunshine_preproc").unwrap();
        let (mut kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        kms.set_bucket_size(1);

        let request_id = derive_request_id("test_keygen_sunshine").unwrap();
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: Some(preproc_id.into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            epoch_id: None,
        };
        let err = key_gen_impl(
            &kms,
            tonic::Request::new(request),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_invalid_arg_preproc_id").unwrap();
        let request_id = derive_request_id("test_keygen_invalid_arg_key_id").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // wrong params
        {
            let request = KeyGenRequest {
                params: Some(12), // wrong param
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                //If we set a preproc_id here, params will be ignored and thus this request wont fail
                preproc_id: None,
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing request ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: None, // missing
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid request ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-id".to_string(),
                }),
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid preprocessing ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                preproc_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-preproc-id".to_string(),
                }),
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // missing domain
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: None,
                preproc_id: Some(preproc_id.into()),
                domain: None, // missing
                epoch_id: None,
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }

        // invalid context ID
        {
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some(request_id.into()),
                context_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid-context-id".to_string(),
                }),
                preproc_id: Some(preproc_id.into()),
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_already_exists_preproc_id").unwrap();
        let request_id = derive_request_id("test_keygen_already_exists_key_id").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // we try to generate the same key twice
        // it should fail the second time
        let request = KeyGenRequest {
            params: Some(FheParameter::Test.into()),
            keyset_config: None,
            keyset_added_info: None,
            request_id: Some(request_id.into()),
            context_id: None,
            preproc_id: Some(preproc_id.into()),
            domain: Some(domain.clone()),
            epoch_id: None,
        };
        let _ = key_gen_impl(
            &kms,
            tonic::Request::new(request.clone()),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap();
        let _res = get_key_gen_result_impl(&kms, tonic::Request::new(request_id.into()))
            .await
            .unwrap();

        let err = key_gen_impl(
            &kms,
            tonic::Request::new(request.clone()),
            #[cfg(feature = "insecure")]
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(42);
        let preproc_id = derive_request_id("test_keygen_already_exists_preproc_id").unwrap();
        let request_id = derive_request_id("test_keygen_already_exists_key_id").unwrap();
        let (kms, _) = setup_test_kms_with_preproc(&mut rng, &preproc_id).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        // try to generate a key twice using the same preprocessing ID
        // the second one should fail with not found because the preprocessing ID is removed after use
        {
            test_standard_keygen(&kms, &request_id, &preproc_id).await;

            let new_request_id = derive_request_id("test_keygen_already_exists_key_id_2").unwrap();
            let request = KeyGenRequest {
                params: Some(FheParameter::Test.into()),
                keyset_config: None,
                keyset_added_info: None,
                request_id: Some((new_request_id).into()),
                context_id: None,
                preproc_id: Some((preproc_id).into()), // same preproc ID
                domain: Some(domain),
                epoch_id: None,
            };
            // this time it should fail
            let err = key_gen_impl(
                &kms,
                tonic::Request::new(request),
                #[cfg(feature = "insecure")]
                true,
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }

        // we try to get a key that does not exist
        {
            let bad_key_id = derive_request_id("test_keygen_not_found").unwrap();
            let get_result = get_key_gen_result_impl(&kms, Request::new(bad_key_id.into())).await;
            assert_eq!(get_result.unwrap_err().code(), tonic::Code::NotFound);
        }
    }
}
