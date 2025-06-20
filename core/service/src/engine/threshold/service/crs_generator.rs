// === Standard Library ===
use std::{collections::HashMap, sync::Arc, time::Instant};

// === External Crates ===
use aes_prng::AesRng;
use kms_grpc::{
    kms::v1::{self, CrsGenRequest, CrsGenResult, Empty},
    rpc_types::{protobuf_to_alloy_domain_option, SignedPubDataHandleInternal},
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{OP_CRS_GEN, OP_INSECURE_CRS_GEN, TAG_PARTY_ID},
};
use threshold_fhe::{
    algebra::base_ring::Z64,
    execution::{
        runtime::session::{BaseSession, ParameterHandles, ToBaseSession},
        tfhe_internals::parameters::DKGParams,
        zk::ceremony::{compute_witness_dim, Ceremony, SecureCeremony},
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Request, Response, Status};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    anyhow_error_and_log,
    cryptography::internal_crypto_types::PrivateSigKey,
    engine::{
        base::{compute_info, retrieve_parameters, BaseKmsStruct, DSEP_PUBDATA_CRS},
        threshold::{service::session::DEFAULT_CONTEXT_ID_ARR, traits::CrsGenerator},
    },
    tonic_handle_potential_err,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};

// === Current Module Imports ===
use super::session::SessionPreparerGetter;

// === Insecure Feature-Specific Imports ===
cfg_if::cfg_if! {
    if #[cfg(feature = "insecure")] {
        use crate::engine::{centralized::central_kms::async_generate_crs, threshold::traits::InsecureCrsGenerator};
        use threshold_fhe::execution::{tfhe_internals::test_feature::transfer_crs};
    }
}

pub struct RealCrsGenerator<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
    pub crs_meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    pub session_preparer_getter: SessionPreparerGetter,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    // Map of ongoing crs generation tasks
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealCrsGenerator<PubS, PrivS, BackS>
{
    async fn inner_crs_gen_from_request(
        &self,
        request: Request<CrsGenRequest>,
        insecure: bool,
    ) -> Result<Response<Empty>, Status> {
        let permit = self
            .rate_limiter
            .start_crsgen()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let inner = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            inner.request_id
        );

        let dkg_params = retrieve_parameters(inner.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::NotFound,
                format!("Can not retrieve fhe parameters with error {e}"),
            )
        })?;
        let crs_params = dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let witness_dim = tonic_handle_potential_err(
            compute_witness_dim(&crs_params, inner.max_num_bits.map(|x| x as usize)),
            "witness dimension computation failed".to_string(),
        )?;

        let req_id = inner.request_id.ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                "missing request ID in CRS generation",
            )
        })?;

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref());

        self.inner_crs_gen(
            req_id.into(),
            witness_dim,
            inner.max_num_bits,
            dkg_params,
            eip712_domain.as_ref(),
            permit,
            inner.context_id.map(|id| id.into()),
            insecure,
        )
        .await
        .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    #[allow(clippy::too_many_arguments)]
    async fn inner_crs_gen(
        &self,
        req_id: RequestId,
        witness_dim: usize,
        max_num_bits: Option<u32>,
        dkg_params: DKGParams,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
        context_id: Option<RequestId>,
        insecure: bool,
    ) -> anyhow::Result<()> {
        // TODO find the session from context ID
        let session_preparer = self
            .session_preparer_getter
            .get(
                context_id
                    .as_ref()
                    .unwrap_or(&RequestId::from_bytes(DEFAULT_CONTEXT_ID_ARR)),
            )
            .await?;

        // Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_CRS_GEN
        } else {
            OP_CRS_GEN
        };

        let _request_counter = metrics::METRICS
            .increment_request_counter(op_tag)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(op_tag)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, session_preparer.my_role_string_unchecked())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });
        {
            let mut guarded_meta_store = self.crs_meta_store.write().await;
            guarded_meta_store.insert(&req_id).map_err(|e| {
                anyhow_error_and_log(format!(
                    "failed to insert to meta store in inner_crs_gen with error: {e}"
                ))
            })?;
        }

        let session_id = req_id.derive_session_id()?;
        let session = session_preparer
            .prepare_ddec_data_from_sessionid_z128(session_id)
            .await?
            .to_base_session();

        let meta_store = Arc::clone(&self.crs_meta_store);
        let meta_store_cancelled = Arc::clone(&self.crs_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let crypto_storage_cancelled = self.crypto_storage.clone();
        let eip712_domain_copy = eip712_domain.cloned();

        // we need to clone the signature key because it needs to be given
        // the thread that spawns the CRS ceremony
        let sk = self.base_kms.sig_key.clone();

        // we do not need to hold the handle,
        // the result of the computation is tracked the crs_meta_store
        let rng = self.base_kms.new_rng().await.to_owned();

        let token = CancellationToken::new();
        {
            self.ongoing.lock().await.insert(req_id, token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);
        self.tracker
            .spawn(async move {
                //Start the metric timer, it will end on drop
                let _timer = timer.map(|b| b.start());
                tokio::select! {
                    () = Self::crs_gen_background(&req_id, witness_dim, max_num_bits, session, rng, meta_store, crypto_storage, sk, dkg_params.to_owned(), eip712_domain_copy, permit, insecure) => {
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&req_id);
                        tracing::info!("CRS generation of request {} exiting normally.", req_id);
                    },
                    () = token.cancelled() => {
                        tracing::error!("CRS generation of request {} exiting before completion because of a cancellation event.", req_id);
                        // Delete any persistant data. Since we only cancel during shutdown we can ignore cleaning up the meta store since it is only in RAM
                        let guarded_meta_store= meta_store_cancelled.write().await;
                        crypto_storage_cancelled.purge_crs_material(&req_id, guarded_meta_store).await;
                        tracing::info!("Trying to clean up any already written material.")
                    },
                }
            }.instrument(tracing::Span::current()));
        Ok(())
    }

    async fn inner_get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner().into();
        let status = {
            let guarded_meta_store = self.crs_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let crs_data = handle_res_mapping(status, &request_id, "CRS generation").await?;
        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id.into()),
            crs_results: Some(crs_data.into()),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn crs_gen_background(
        req_id: &RequestId,
        witness_dim: usize,
        max_num_bits: Option<u32>,
        mut base_session: BaseSession,
        rng: AesRng,
        meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        eip712_domain: Option<alloy_sol_types::Eip712Domain>,
        permit: OwnedSemaphorePermit,
        insecure: bool,
    ) {
        tracing::info!(
            "Starting crs gen background process for req_id={req_id:?} with witness_dim={witness_dim} and max_num_bits={max_num_bits:?}"
        );
        let _permit = permit;
        let crs_start_timer = Instant::now();
        let pke_params = params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        let pp = if insecure {
            // sanity check to make sure we're using the insecure feature
            #[cfg(not(feature = "insecure"))]
            {
                let _ = rng; // stop clippy from complaining
                panic!("attempting to call insecure crsgen when the insecure feature is not set");
            }
            #[cfg(feature = "insecure")]
            {
                let my_role = base_session.my_role();
                // We let the first party sample the seed (we are using 1-based party IDs)
                let input_party_id = 1;
                if my_role.one_based() == input_party_id {
                    let crs_res = async_generate_crs(
                        &sk,
                        params,
                        max_num_bits,
                        eip712_domain.as_ref(),
                        base_session.session_id(),
                        rng,
                    )
                    .await;
                    let crs = match crs_res {
                        Ok((crs, _)) => crs,
                        Err(e) => {
                            let mut guarded_meta_store = meta_store.write().await;
                            let _ = guarded_meta_store.update(req_id, Err(e.to_string()));
                            return;
                        }
                    };
                    transfer_crs(&base_session, Some(crs), input_party_id).await
                } else {
                    transfer_crs(&base_session, None, input_party_id).await
                }
            }
        } else {
            // secure ceremony (insecure = false)
            let real_ceremony = SecureCeremony::default();
            let internal_pp = real_ceremony
                .execute::<Z64, _>(&mut base_session, witness_dim, max_num_bits)
                .await;
            internal_pp.and_then(|internal| {
                internal.try_into_tfhe_zk_pok_pp(&pke_params, base_session.session_id())
            })
        };
        let res_info_pp = pp.and_then(|pp| {
            compute_info(&sk, &DSEP_PUBDATA_CRS, &pp, eip712_domain.as_ref()).map(|info| (pp, info))
        });

        let (pp_id, meta_data) = match res_info_pp {
            Ok((meta, pp_id)) => (meta, pp_id),
            Err(e) => {
                let mut guarded_meta_store = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_store.update(req_id, Err(e.to_string()));
                return;
            }
        };

        tracing::info!("CRS generation completed for req_id={req_id:?}, storing the CRS.");
        crypto_storage
            .write_crs_with_meta_store(req_id, pp_id, meta_data, meta_store)
            .await;

        let crs_stop_timer = Instant::now();
        let elapsed_time = crs_stop_timer.duration_since(crs_start_timer);
        tracing::info!(
            "CRS stored. CRS ceremony time was {:?} ms",
            (elapsed_time).as_millis()
        );
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > CrsGenerator for RealCrsGenerator<PubS, PrivS, BackS>
{
    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        self.inner_crs_gen_from_request(request, false).await
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        self.inner_get_result(request).await
    }
}

#[cfg(feature = "insecure")]
pub struct RealInsecureCrsGenerator<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    pub real_crs_generator: RealCrsGenerator<PubS, PrivS, BackS>,
}

#[cfg(feature = "insecure")]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > RealInsecureCrsGenerator<PubS, PrivS, BackS>
{
    pub async fn from_real_crsgen(value: &RealCrsGenerator<PubS, PrivS, BackS>) -> Self {
        Self {
            real_crs_generator: RealCrsGenerator {
                base_kms: value.base_kms.new_instance().await,
                crypto_storage: value.crypto_storage.clone(),
                crs_meta_store: Arc::clone(&value.crs_meta_store),
                session_preparer_getter: value.session_preparer_getter.clone(),
                tracker: Arc::clone(&value.tracker),
                ongoing: Arc::clone(&value.ongoing),
                rate_limiter: value.rate_limiter.clone(),
            },
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > InsecureCrsGenerator for RealInsecureCrsGenerator<PubS, PrivS, BackS>
{
    async fn insecure_crs_gen(
        &self,
        request: Request<CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        tracing::info!("starting insecure crs gen in RealInsecureCrsGenerator");
        self.real_crs_generator
            .inner_crs_gen_from_request(request, true)
            .await
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        self.real_crs_generator.inner_get_result(request).await
    }
}
