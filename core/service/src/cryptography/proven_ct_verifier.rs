use alloy_primitives::keccak256;
use conf_trace::{
    metrics::METRICS,
    metrics_names::{
        ERR_VERIFICATION_FAILED, OP_TYPE_CT_PROOF, OP_TYPE_LOAD_CRS_PK, OP_TYPE_PROOF_VERIFICATION,
        OP_TYPE_TOTAL, OP_VERIFY_PROVEN_CT, TAG_OPERATION_TYPE,
    },
};
use std::sync::Arc;
use tfhe::{
    safe_serialization::safe_deserialize, zk::CompactPkePublicParams, ProvenCompactCiphertextList,
};
use tokio::sync::{OwnedSemaphorePermit, RwLock};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::{
    anyhow_error_and_log,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::internal_crypto_types::PrivateSigKey,
    kms::{
        RequestId, VerifyProvenCtRequest, VerifyProvenCtResponse, VerifyProvenCtResponsePayload,
    },
    rpc::{
        central_rpc::{tonic_handle_potential_err, tonic_some_or_err_ref, validate_request_id},
        rpc_types::{compute_external_verify_proven_ct_signature, BaseKms, WrappedPublicKeyOwned},
    },
    storage::{crypto_material::CryptoMaterialStorage, Storage},
    util::meta_store::{handle_res_mapping, HandlerStatus, MetaStore},
};

pub(crate) async fn non_blocking_verify_proven_ct<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
>(
    crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
    meta_store: Arc<RwLock<MetaStore<VerifyProvenCtResponsePayload>>>,
    request_id: RequestId,
    request: VerifyProvenCtRequest,
    client_sk: Arc<PrivateSigKey>,
    permit: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    {
        let mut guarded_meta_store = meta_store.write().await;
        guarded_meta_store.insert(&request_id)?;
    }
    let sigkey = Arc::clone(&client_sk);
    let _handle = tokio::spawn(
        async move {
            let _permit = permit;
            let verify_proven_ct_start_instant = tokio::time::Instant::now();
            let res = verify_proven_ct_and_sign(crypto_storage, request, &sigkey).await;

            let mut guarded_meta_store = meta_store.write().await;
            match res {
                Ok(inner_res) => {
                    tracing::debug!(
                        "storing verify proven ct result for request_id {}",
                        request_id
                    );
                    let _ = guarded_meta_store.update(&request_id, HandlerStatus::Done(inner_res));
                    let duration = verify_proven_ct_start_instant.elapsed();
                    METRICS
                        .observe_duration_with_tags(
                            OP_VERIFY_PROVEN_CT,
                            duration,
                            &[(TAG_OPERATION_TYPE, OP_TYPE_TOTAL.to_string())],
                        )
                        .expect("Failed to record total verification time");
                    tracing::info!(
                        "verify proven ct result for request_id {} done, it took {:?} ms",
                        request_id,
                        duration.as_millis(),
                    );
                }
                Err(e) => {
                    let _ = guarded_meta_store.update(
                        &request_id,
                        HandlerStatus::Error(format!(
                            "Proven ciphertext verification failed for ID {} with error {e}",
                            request_id
                        )),
                    );
                    METRICS
                        .increment_error_counter(OP_VERIFY_PROVEN_CT, ERR_VERIFICATION_FAILED)
                        .ok();
                }
            }
        }
        .instrument(tracing::Span::current()),
    );
    Ok(())
}

pub(crate) async fn get_verify_proven_ct_result<KMS>(
    base_kms: &KMS,
    meta_store: Arc<RwLock<MetaStore<VerifyProvenCtResponsePayload>>>,
    request: Request<RequestId>,
) -> Result<Response<VerifyProvenCtResponse>, Status>
where
    KMS: BaseKms,
{
    let request_id = request.into_inner();
    validate_request_id(&request_id)?;

    let status = {
        let guarded_meta_store = meta_store.read().await;
        guarded_meta_store.retrieve(&request_id).cloned()
    };

    let payload: VerifyProvenCtResponsePayload = { handle_res_mapping(status, &request_id, "ZK")? };

    let sig_payload_vec = tonic_handle_potential_err(
        bincode::serialize(&payload),
        format!("Could not convert payload to bytes {:?}", payload),
    )?;

    let sig = tonic_handle_potential_err(
        base_kms.sign(&sig_payload_vec),
        format!("Could not sign payload {:?}", payload),
    )?;

    Ok(Response::new(VerifyProvenCtResponse {
        payload: Some(payload),
        signature: sig.sig.to_vec(),
    }))
}

// Verifies the ZK proof and returns the metadata payload, including a KMS signature, if the proof is valid
async fn verify_proven_ct_and_sign<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
>(
    crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
    req: VerifyProvenCtRequest,
    client_sk: &PrivateSigKey,
) -> anyhow::Result<VerifyProvenCtResponsePayload> {
    let crs_handle = tonic_some_or_err_ref(&req.crs_handle, "CRS handle is not set".to_string())?;
    validate_request_id(crs_handle)?;

    let key_handle = tonic_some_or_err_ref(&req.key_handle, "Key handle is not set".to_string())?;
    validate_request_id(key_handle)?;

    let request_id = tonic_some_or_err_ref(&req.request_id, "Request ID is not set".to_string())?;
    validate_request_id(request_id)?;

    tracing::info!("starting proof verification for request {}", request_id);
    tracing::debug!(
        "proof verification request: crs_handle: {:?}, key_handle: {:?}, contract_address: {}, client_address: {}, acl_address: {}, domain: {:?}",
        req.crs_handle,
        req.key_handle,
        req.contract_address,
        req.client_address,
        req.acl_address,
        req.domain
    );
    let mut cursor = std::io::Cursor::new(&req.ct_bytes);
    let proven_ct: ProvenCompactCiphertextList = safe_deserialize(&mut cursor, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow::anyhow!(e))
        .inspect_err(|e| {
            tracing::error!("could not deserialize the ciphertext list ({e})");
        })?;

    let load_crs_pk_start_instant = tokio::time::Instant::now();
    let wrapped_pk = crypto_storage.read_cloned_pk(key_handle).await?;

    // NOTE: CRS is a bit big so we try to avoid cloning
    // but this will highly depend on how often we generate a CRS,
    // if there are a lot of verification requests along with CRS generation
    // requests, then the CRS generation endpoint might not be able to
    // make a write lock.
    crypto_storage.refresh_crs(crs_handle).await?;
    let pp_guard = crypto_storage
        .read_guarded_crs_from_cache(crs_handle)
        .await?;

    let duration = load_crs_pk_start_instant.elapsed();
    METRICS
        .observe_duration_with_tags(
            OP_VERIFY_PROVEN_CT,
            duration,
            &[(TAG_OPERATION_TYPE, OP_TYPE_LOAD_CRS_PK.to_string())],
        )
        .expect("Failed to record CRS and PK load time");
    tracing::info!("It took {:?} ms to load crs and pk", duration.as_millis());

    let metadata = tonic_handle_potential_err(
        crate::client::assemble_metadata_req(&req),
        "Error assembling proven ciphertext metadata".to_string(),
    )?;

    let proof_start_instant = tokio::time::Instant::now();
    let (send, recv) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let ok = verify_ct_proofs(&proven_ct, &pp_guard, &wrapped_pk, &metadata);
        let _ = send.send(ok);
    });
    let signature_ok = recv.await.inspect_err(|e| {
        tracing::error!("channel error for key handle {} ({e})", key_handle);
    })?;
    let duration = proof_start_instant.elapsed();
    METRICS
        .observe_duration_with_tags(
            OP_VERIFY_PROVEN_CT,
            duration,
            &[(TAG_OPERATION_TYPE, OP_TYPE_PROOF_VERIFICATION.to_string())],
        )
        .expect("Failed to record proof verification time");
    tracing::info!("It took {:?} ms to verify", duration.as_millis());

    let ct_digest = keccak256(&req.ct_bytes).to_vec();
    if signature_ok {
        // REMARK: usually we should use `serialize_hash_element(proven_ct)`
        // but because the hash is checked on chain, we'll use keccak,
        // which is what is supported in solidity.

        let external_signature =
            compute_external_verify_proven_ct_signature(client_sk, &ct_digest, &req)?;

        tracing::info!("finished proof verification for request {}", request_id);

        let payload = VerifyProvenCtResponsePayload {
            request_id: req.request_id,
            contract_address: req.contract_address,
            client_address: req.client_address,
            ct_digest,
            external_signature,
        };

        Ok(payload)
    } else {
        tracing::error!(
            "verification failed using medatata: {:x?} and digest {:x?}",
            &metadata,
            &ct_digest
        );
        Err(anyhow_error_and_log(format!(
            "proven ciphertext verification failed for ciphertext request: {}",
            request_id
        )))
    }
}

fn verify_ct_proofs(
    proven_ct: &ProvenCompactCiphertextList,
    pp: &CompactPkePublicParams,
    wrapped_pk: &WrappedPublicKeyOwned,
    metadata: &[u8],
) -> bool {
    let _guard = METRICS
        .time_operation(OP_VERIFY_PROVEN_CT)
        .expect("Failed to create timing metric")
        .tag(TAG_OPERATION_TYPE, OP_TYPE_CT_PROOF)
        .expect("Failed to add tag")
        .start();
    match wrapped_pk {
        WrappedPublicKeyOwned::Compact(pk) => {
            if let tfhe::zk::ZkVerificationOutCome::Invalid = proven_ct.verify(pp, pk, metadata) {
                return false;
            }
        }
    }
    true
}
