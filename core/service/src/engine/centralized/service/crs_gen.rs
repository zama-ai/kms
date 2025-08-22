use std::sync::Arc;

use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use anyhow::Result;
use kms_grpc::kms::v1::{CrsGenRequest, CrsGenResult, Empty};
use kms_grpc::rpc_types::{optional_protobuf_to_alloy_domain, SignedPubDataHandleInternal};
use kms_grpc::RequestId;
use observability::metrics::METRICS;
use observability::metrics_names::{ERR_CRS_GEN_FAILED, OP_CRS_GEN_REQUEST};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::session_id::SessionId;
use tokio::sync::{OwnedSemaphorePermit, RwLock};
use tonic::{Request, Response, Status};
use tracing::Instrument;

use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::engine::base::retrieve_parameters;
use crate::engine::centralized::central_kms::{async_generate_crs, CentralizedKms};
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::validation::{
    parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
};
use crate::tonic_handle_potential_err;
use crate::util::meta_store::{handle_res_mapping, MetaStore};
use crate::vault::storage::crypto_material::CentralizedCryptoMaterialStorage;
use crate::vault::storage::Storage;

/// Implementation of the crs_gen endpoint
pub async fn crs_gen_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<CrsGenRequest>,
) -> Result<Response<Empty>, Status> {
    tracing::info!("Received CRS generation request");
    let _timer = METRICS.time_operation(OP_CRS_GEN_REQUEST).start();

    let permit = service.rate_limiter.start_crsgen().await?;

    let inner = request.into_inner();
    let req_id =
        parse_optional_proto_request_id(&inner.request_id, RequestIdParsingErr::CrsGenRequest)?;
    let params = retrieve_parameters(inner.params)?;

    {
        let mut guarded_meta_store = service.crs_meta_map.write().await;
        tonic_handle_potential_err(
            guarded_meta_store.insert(&req_id),
            "Could not insert CRS generation into meta store".to_string(),
        )?;
    }

    let meta_store = Arc::clone(&service.crs_meta_map);
    let crypto_storage = service.crypto_storage.clone();
    let sk = Arc::clone(&service.base_kms.sig_key);
    let rng = service.base_kms.new_rng().await;

    let eip712_domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;
    let handle = service.tracker.spawn(
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
                METRICS.increment_error_counter(OP_CRS_GEN_REQUEST, ERR_CRS_GEN_FAILED);
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
    service.thread_handles.write().await.add(handle);
    Ok(Response::new(Empty {}))
}

/// Implementation of the get_crs_gen_result endpoint
pub async fn get_crs_gen_result_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
>(
    service: &CentralizedKms<PubS, PrivS, CM, BO>,
    request: Request<kms_grpc::kms::v1::RequestId>,
) -> Result<Response<CrsGenResult>, Status> {
    let request_id =
        parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::CrsGenResponse)?;
    tracing::debug!("Received CRS gen result request with id {}", request_id);

    let status = {
        let guarded_meta_store = service.crs_meta_map.read().await;
        guarded_meta_store.retrieve(&request_id)
    };
    let crs_info = handle_res_mapping(status, &request_id, "CRS").await?;

    Ok(Response::new(CrsGenResult {
        request_id: Some(request_id.into()),
        crs_results: Some(crs_info.into()),
    }))
}

/// Background task for CRS generation
#[allow(clippy::too_many_arguments)]
pub(crate) async fn crs_gen_background<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
>(
    req_id: &RequestId,
    rng: AesRng,
    meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    sk: Arc<PrivateSigKey>,
    params: DKGParams,
    eip712_domain: Eip712Domain,
    max_number_bits: Option<u32>,
    permit: OwnedSemaphorePermit,
) -> Result<(), anyhow::Error> {
    let _permit = permit;
    let start = tokio::time::Instant::now();

    let sid = SessionId::from(0);
    let (pp, crs_info) =
        match async_generate_crs(&sk, params, max_number_bits, eip712_domain, sid, rng).await {
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
                return Err(anyhow::anyhow!("Failed CRS generation: {}", e));
            }
        };

    crypto_storage
        .write_crs_with_meta_store(req_id, pp, crs_info, meta_store)
        .await;

    tracing::info!("⏱️ Core Event Time for CRS-gen: {:?}", start.elapsed());
    Ok(())
}
