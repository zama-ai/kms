// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Instant};

// === External Crates ===
use aes_prng::AesRng;
use kms_grpc::{
    kms::v1::{self, CrsGenRequest, CrsGenResult, Empty},
    rpc_types::{protobuf_to_alloy_domain_option, SignedPubDataHandleInternal},
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{ERR_RATE_LIMIT_EXCEEDED, OP_CRS_GEN, OP_INSECURE_CRS_GEN, TAG_PARTY_ID},
};
use threshold_fhe::{
    algebra::base_ring::Z64,
    execution::{
        runtime::session::{BaseSession, ParameterHandles},
        tfhe_internals::parameters::DKGParams,
        zk::ceremony::{compute_witness_dim, Ceremony},
    },
    networking::NetworkMode,
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
        threshold::traits::CrsGenerator,
        validation::validate_request_id,
    },
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};

// === Current Module Imports ===
use super::session::SessionPreparer;

// === Insecure Feature-Specific Imports ===
cfg_if::cfg_if! {
    if #[cfg(feature = "insecure")] {
        use crate::engine::{centralized::central_kms::async_generate_crs, threshold::traits::InsecureCrsGenerator};
        use threshold_fhe::execution::{tfhe_internals::test_feature::transfer_crs};
    }
}

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use crate::vault::storage::ram;
        use threshold_fhe::malicious_execution::zk::ceremony::InsecureCeremony;
    }
}

pub struct RealCrsGenerator<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    C: Ceremony + Send + Sync + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub crs_meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    pub session_preparer: SessionPreparer,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub tracker: Arc<TaskTracker>,
    // Map of ongoing crs generation tasks
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
    pub(crate) _ceremony: PhantomData<C>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        C: Ceremony + Send + Sync + 'static,
    > RealCrsGenerator<PubS, PrivS, C>
{
    async fn inner_crs_gen_from_request(
        &self,
        request: Request<CrsGenRequest>,
        insecure: bool,
    ) -> Result<Response<Empty>, Status> {
        let permit = self.rate_limiter.start_crsgen().await.inspect_err(|_e| {
            if let Err(e) =
                metrics::METRICS.increment_error_counter(OP_CRS_GEN, ERR_RATE_LIMIT_EXCEEDED)
            {
                tracing::warn!("Failed to increment error counter: {:?}", e);
            }
        })?;

        let inner = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            inner.request_id
        );

        let dkg_params = retrieve_parameters(inner.params)?;
        let crs_params = dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();

        let witness_dim = compute_witness_dim(&crs_params, inner.max_num_bits.map(|x| x as usize))
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    format!("witness dimension computation failed: {e}"),
                )
            })?;

        let req_id = inner
            .request_id
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "missing request ID in CRS generation",
                )
            })?
            .into();
        validate_request_id(&req_id)?;

        let eip712_domain = protobuf_to_alloy_domain_option(inner.domain.as_ref())?;

        // NOTE: everything inside this function will cause an Aborted error code
        self.inner_crs_gen(
            req_id,
            witness_dim,
            inner.max_num_bits,
            dkg_params,
            &eip712_domain,
            permit,
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
        eip712_domain: &alloy_sol_types::Eip712Domain,
        permit: OwnedSemaphorePermit,
        insecure: bool,
    ) -> anyhow::Result<()> {
        //Retrieve the correct tag
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
                b.tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string())
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
        // CRS ceremony requires a sync network
        let session = self
            .session_preparer
            .make_base_session(session_id, NetworkMode::Sync)
            .await?;

        let meta_store = Arc::clone(&self.crs_meta_store);
        let meta_store_cancelled = Arc::clone(&self.crs_meta_store);
        let crypto_storage = self.crypto_storage.clone();
        let crypto_storage_cancelled = self.crypto_storage.clone();
        let eip712_domain_copy = eip712_domain.clone();

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
        validate_request_id(&request_id)?;
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
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        eip712_domain: alloy_sol_types::Eip712Domain,
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
                let domain = eip712_domain.clone();
                if my_role.one_based() == input_party_id {
                    let crs_res = async_generate_crs(
                        &sk,
                        params,
                        max_num_bits,
                        domain,
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
            let real_ceremony = C::default();
            let internal_pp = real_ceremony
                .execute::<Z64, _>(&mut base_session, witness_dim, max_num_bits)
                .await;
            internal_pp.and_then(|internal| {
                internal.try_into_tfhe_zk_pok_pp(&pke_params, base_session.session_id())
            })
        };
        let res_info_pp = pp.and_then(|pp| {
            compute_info(&sk, &DSEP_PUBDATA_CRS, &pp, &eip712_domain).map(|info| (pp, info))
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
        C: Ceremony + Send + Sync + 'static,
    > CrsGenerator for RealCrsGenerator<PubS, PrivS, C>
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
    C: Ceremony + Send + Sync + 'static,
> {
    pub real_crs_generator: RealCrsGenerator<PubS, PrivS, C>,
}

#[cfg(feature = "insecure")]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        C: Ceremony + Send + Sync + 'static,
    > RealInsecureCrsGenerator<PubS, PrivS, C>
{
    pub async fn from_real_crsgen(value: &RealCrsGenerator<PubS, PrivS, C>) -> Self {
        Self {
            real_crs_generator: RealCrsGenerator {
                base_kms: value.base_kms.new_instance().await,
                crypto_storage: value.crypto_storage.clone(),
                crs_meta_store: Arc::clone(&value.crs_meta_store),
                session_preparer: value.session_preparer.new_instance().await,
                tracker: Arc::clone(&value.tracker),
                ongoing: Arc::clone(&value.ongoing),
                rate_limiter: value.rate_limiter.clone(),
                _ceremony: PhantomData,
            },
        }
    }
}

#[cfg(feature = "insecure")]
#[tonic::async_trait]
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        C: Ceremony + Send + Sync + 'static,
    > InsecureCrsGenerator for RealInsecureCrsGenerator<PubS, PrivS, C>
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kms_grpc::{kms::v1::FheParameter, rpc_types::alloy_to_protobuf_domain};
    use threshold_fhe::{
        algebra::structure_traits::Ring,
        execution::{
            runtime::session::BaseSessionHandles, zk::ceremony::FinalizedInternalPublicParameter,
        },
    };

    use crate::{consts::DURATION_WAITING_ON_RESULT_SECONDS, dummy_domain};

    use super::*;

    impl<
            PubS: Storage + Send + Sync + 'static,
            PrivS: Storage + Send + Sync + 'static,
            C: Ceremony + Send + Sync + 'static,
        > RealCrsGenerator<PubS, PrivS, C>
    {
        async fn init_test(
            pub_storage: PubS,
            priv_storage: PrivS,
            session_preparer: SessionPreparer,
        ) -> Self {
            let crypto_storage = ThresholdCryptoMaterialStorage::new(
                pub_storage,
                priv_storage,
                None,
                HashMap::new(),
                HashMap::new(),
            );

            let tracker = Arc::new(TaskTracker::new());
            let ongoing = Arc::new(Mutex::new(HashMap::new()));
            let rate_limiter = RateLimiter::default();
            Self {
                base_kms: session_preparer.base_kms.new_instance().await,
                crypto_storage,
                crs_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                session_preparer,
                tracker,
                ongoing,
                rate_limiter,
                _ceremony: PhantomData,
            }
        }

        fn set_bucket_size(&mut self, bucket_size: usize) {
            let config = crate::util::rate_limiter::RateLimiterConfig {
                bucket_size,
                ..Default::default()
            };
            self.rate_limiter = RateLimiter::new(config);
        }
    }

    #[derive(Clone, Default)]
    pub struct BrokenCeremony {}

    #[tonic::async_trait]
    impl Ceremony for BrokenCeremony {
        async fn execute<Z: Ring, S: BaseSessionHandles>(
            &self,
            _session: &mut S,
            _witness_dim: usize,
            _max_num_bits: Option<u32>,
        ) -> anyhow::Result<FinalizedInternalPublicParameter> {
            Err(anyhow::anyhow!("this is a broken ceremony"))
        }
    }

    #[derive(Clone, Default)]
    pub struct SlowCeremony {}

    #[tonic::async_trait]
    impl Ceremony for SlowCeremony {
        async fn execute<Z: Ring, S: BaseSessionHandles>(
            &self,
            session: &mut S,
            witness_dim: usize,
            max_num_bits: Option<u32>,
        ) -> anyhow::Result<FinalizedInternalPublicParameter> {
            // We need to sleep for more than 60 seconds because
            // the get response call blocks for 60 seconds if there is potentially a result
            tokio::time::sleep(Duration::from_secs(DURATION_WAITING_ON_RESULT_SECONDS + 10)).await;
            let ceremony = InsecureCeremony {};
            ceremony
                .execute::<Z64, _>(session, witness_dim, max_num_bits)
                .await
        }
    }

    impl RealCrsGenerator<ram::RamStorage, ram::RamStorage, InsecureCeremony> {
        async fn init_test_insecure_ceremony(session_preparer: SessionPreparer) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, InsecureCeremony>::init_test(
                pub_storage,
                priv_storage,
                session_preparer,
            )
            .await
        }
    }

    impl RealCrsGenerator<ram::RamStorage, ram::RamStorage, BrokenCeremony> {
        async fn init_test_broken_ceremony(session_preparer: SessionPreparer) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, BrokenCeremony>::init_test(
                pub_storage,
                priv_storage,
                session_preparer,
            )
            .await
        }
    }

    impl RealCrsGenerator<ram::RamStorage, ram::RamStorage, SlowCeremony> {
        async fn init_test_slow_ceremony(session_preparer: SessionPreparer) -> Self {
            let pub_storage = ram::RamStorage::new();
            let priv_storage = ram::RamStorage::new();
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, SlowCeremony>::init_test(
                pub_storage,
                priv_storage,
                session_preparer,
            )
            .await
        }
    }

    #[tokio::test]
    async fn invalid_argument() {
        let session_preparer = SessionPreparer::new_test_session(true);

        let crs_gen =
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, InsecureCeremony>::init_test_insecure_ceremony(
                session_preparer,
            )
            .await;

        // `InvalidArgument` - If the request ID is not present, valid or does not match the expected format.
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: None,
            domain: Some(domain),
        };

        let request = Request::new(req);
        let res = crs_gen.crs_gen(request).await;

        assert_eq!(res.unwrap_err().code(), tonic::Code::InvalidArgument);

        // same for the result, should give us an error with a bad request ID
        assert_eq!(
            crs_gen
                .get_result(Request::new(kms_grpc::kms::v1::RequestId {
                    request_id: "xyz".to_string(),
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn not_found() {
        let session_preparer = SessionPreparer::new_test_session(true);

        let crs_gen =
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, InsecureCeremony>::init_test_insecure_ceremony(
                session_preparer,
            )
            .await;

        // `NotFound` - If the parameters in the request are not valid.
        let req_id = RequestId::new_random(&mut rand::rngs::OsRng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: 2,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
        };

        let request = Request::new(req);
        let res = crs_gen.crs_gen(request).await;

        assert_eq!(res.unwrap_err().code(), tonic::Code::NotFound);

        // `NotFound` - If the CRS generation does not exist for `request`.
        assert_eq!(
            crs_gen
                .get_result(Request::new(req_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    #[tokio::test]
    async fn resource_exhausted() {
        let session_preparer = SessionPreparer::new_test_session(true);

        let mut crs_gen =
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, InsecureCeremony>::init_test_insecure_ceremony(
                session_preparer,
            )
            .await;
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        crs_gen.set_bucket_size(1);

        let req_id = RequestId::new_random(&mut rand::rngs::OsRng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
        };

        let request = Request::new(req);
        let res = crs_gen.crs_gen(request).await;

        assert_eq!(res.unwrap_err().code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn aborted() {
        // We use non existing PRSS to simulate an abort failure
        let session_preparer = SessionPreparer::new_test_session(false);

        let crs_gen =
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, InsecureCeremony>::init_test_insecure_ceremony(
                session_preparer,
            )
            .await;
        let req_id = RequestId::new_random(&mut rand::rngs::OsRng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
        };

        let request = Request::new(req);
        let _ = crs_gen.crs_gen(request).await.unwrap();

        // Send a the request again, it should return an error
        // because the session has already been used.
        let req = CrsGenRequest {
            params: 0,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: None,
        };

        let request = Request::new(req);

        assert_eq!(
            crs_gen.crs_gen(request).await.unwrap_err().code(),
            tonic::Code::Aborted
        );
    }

    #[tokio::test]
    async fn internal_failure() {
        // Even if the CRS ceremony fails, we should not return an error
        // because it's happening in the background.
        let session_preparer = SessionPreparer::new_test_session(true);

        let crs_gen =
                RealCrsGenerator::<ram::RamStorage, ram::RamStorage, BrokenCeremony>::init_test_broken_ceremony(
                    session_preparer,
                )
                .await;

        let req_id = RequestId::new_random(&mut rand::rngs::OsRng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
        };

        // we expect the CRS generation call to pass, but only get an error when we try to retrieve the result
        crs_gen.crs_gen(Request::new(req)).await.unwrap();

        assert_eq!(
            crs_gen
                .get_result(Request::new(req_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
    }

    #[tokio::test]
    async fn unavailable() {
        let session_preparer = SessionPreparer::new_test_session(true);

        let crs_gen =
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, SlowCeremony>::init_test_slow_ceremony(
                session_preparer,
            )
            .await;

        let req_id = RequestId::new_random(&mut rand::rngs::OsRng);

        // start the ceremony but immediately fetch the result, it should be not found too
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
        };

        let request = Request::new(req);
        crs_gen.crs_gen(request).await.unwrap();
        assert_eq!(
            crs_gen
                .get_result(Request::new(req_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }

    #[tokio::test]
    async fn sunshine() {
        let session_preparer = SessionPreparer::new_test_session(true);

        let crs_gen =
            RealCrsGenerator::<ram::RamStorage, ram::RamStorage, InsecureCeremony>::init_test_insecure_ceremony(
                session_preparer,
            )
            .await;

        // Test that we can successfully generate a CRS
        let req_id = RequestId::new_random(&mut rand::rngs::OsRng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
        };

        let request = Request::new(req);
        crs_gen.crs_gen(request).await.unwrap();
        let _crs = crs_gen
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap();
    }
}
