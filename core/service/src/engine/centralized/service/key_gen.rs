use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use kms_grpc::kms::v1::{Empty, KeyGenRequest, KeyGenResult};
use kms_grpc::rpc_types::{optional_protobuf_to_alloy_domain, PubDataType};
use kms_grpc::RequestId;
use observability::metrics::METRICS;
use observability::metrics_names::{ERR_KEYGEN_FAILED, ERR_KEY_EXISTS, OP_KEYGEN};
use std::collections::HashMap;
use std::sync::Arc;
use threshold_fhe::execution::keyset_config::KeySetConfig;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::sync::{OwnedSemaphorePermit, RwLock};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::engine::base::{
    compute_info, convert_key_response, retrieve_parameters, KeyGenCallValues, DSEP_PUBDATA_KEY,
};
use crate::engine::centralized::central_kms::{
    async_generate_decompression_keys, async_generate_fhe_keys,
    async_generate_sns_compression_keys, RealCentralizedKms,
};
use crate::engine::keyset_configuration::InternalKeySetConfig;
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
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<KeyGenRequest>,
) -> Result<Response<Empty>, Status> {
    let _timer = METRICS.time_operation(OP_KEYGEN).start();

    let permit = service.rate_limiter.start_keygen().await?;
    let inner = request.into_inner();
    tracing::info!(
        "centralized key-gen with request id: {:?}",
        inner.request_id
    );
    let req_id =
        parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::KeyGenRequest)?;
    let params = retrieve_parameters(inner.params)?;
    let internal_keyset_config = ok_or_tonic_abort(
        InternalKeySetConfig::new(inner.keyset_config, inner.keyset_added_info),
        "Invalid keyset config".to_string(),
    )?;

    {
        let mut guarded_meta_store = service.key_meta_map.write().await;
        // Insert [HandlerStatus::Started] into the meta store. Note that this will fail if the request ID is already in the meta store
        ok_or_tonic_abort(
            guarded_meta_store.insert(&req_id),
            "Could not insert key generation into meta store".to_string(),
        )?;
    }

    let meta_store = Arc::clone(&service.key_meta_map);
    let crypto_storage = service.crypto_storage.clone();
    let sk = Arc::clone(&service.base_kms.sig_key);

    let eip712_domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;
    let handle = service.tracker.spawn(
        async move {
            let _timer = _timer;
            if let Err(e) = key_gen_background(
                &req_id,
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
>(
    service: &RealCentralizedKms<PubS, PrivS>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<KeyGenResult>, Status> {
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::KeyGenResponse)?;
    tracing::debug!("Received get key gen result request with id {}", request_id);

    let status = {
        let guarded_meta_store = service.key_meta_map.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let pub_key_handles = handle_res_mapping(status, &request_id, "Key generation").await?;

    Ok(Response::new(KeyGenResult {
        request_id: Some(request_id.into()),
        key_results: convert_key_response(pub_key_handles),
    }))
}

/// Background task for key generation
#[allow(clippy::too_many_arguments)]
pub(crate) async fn key_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
>(
    req_id: &RequestId,
    meta_store: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
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
            let info =
                match compute_info(&sk, &DSEP_PUBDATA_KEY, &decompression_key, &eip712_domain) {
                    Ok(info) => HashMap::from_iter(vec![(PubDataType::DecompressionKey, info)]),
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
        KeySetConfig::AddSnsCompressionKey => {
            let overwrite_key_id =
                internal_keyset_config.get_base_key_id_for_sns_compression_key()?;
            tracing::info!("Starting key generation for SNS compression key with request ID: {}, base key ID: {}", req_id, overwrite_key_id);
            let (fhe_key_set, key_info) = match async_generate_sns_compression_keys(
                &sk,
                crypto_storage.clone(),
                params,
                &overwrite_key_id,
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

            tracing::info!(
                "⏱️ Core Event Time for SNS compression Keygen: {:?}",
                start.elapsed()
            );
        }
    }
    Ok(())
}
