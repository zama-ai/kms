// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Instant};

// === External Crates ===
use aes_prng::AesRng;
use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{self, CrsGenRequest, CrsGenResult, Empty},
    utils::tonic_result::ok_or_tonic_abort,
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        ERR_CANCELLED, ERR_CRS_GEN_FAILED, OP_CRS_GEN_REQUEST, OP_INSECURE_CRS_GEN_REQUEST,
        TAG_PARTY_ID,
    },
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
    consts::DEFAULT_MPC_CONTEXT,
    cryptography::internal_crypto_types::PrivateSigKey,
    engine::{
        base::{compute_info_crs, BaseKmsStruct, CrsGenMetadata, DSEP_PUBDATA_CRS},
        threshold::traits::CrsGenerator,
        validation::{parse_proto_request_id, validate_crs_gen_request, RequestIdParsingErr},
    },
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
    pub crs_meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
    pub session_preparer_getter: SessionPreparerGetter,
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
        let permit = self.rate_limiter.start_crsgen().await?;

        let inner = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            inner.request_id
        );
        let (req_id, dkg_params, eip712_domain, context_id) =
            validate_crs_gen_request(inner.clone())?;

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

        // Validate the request ID before proceeding
        {
            let guarded_meta_store = self.crs_meta_store.read().await;

            if guarded_meta_store.exists(&req_id) {
                return Err(Status::already_exists(format!(
                    "CRS gen request with ID {req_id} already exists"
                )));
            }

            if ok_or_tonic_abort(
                self.crypto_storage.crs_exists(&req_id).await,
                "Could not check crs existance in storage".to_string(),
            )? {
                return Err(Status::already_exists(format!(
                    "CRS with key ID {req_id} already exists"
                )));
            }
        }

        // NOTE: everything inside this function will cause an Aborted error code
        // so before calling it we should do as much validation as possible without modifying state
        self.inner_crs_gen(
            req_id,
            witness_dim,
            inner.max_num_bits,
            dkg_params,
            &eip712_domain,
            permit,
            context_id,
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
        context_id: Option<ContextId>,
        insecure: bool,
    ) -> anyhow::Result<()> {
        let context_id = context_id.as_ref().unwrap_or(&DEFAULT_MPC_CONTEXT);
        let session_preparer = self.session_preparer_getter.get(context_id).await?;

        // Retrieve the correct tag
        let op_tag = if insecure {
            OP_INSECURE_CRS_GEN_REQUEST
        } else {
            OP_CRS_GEN_REQUEST
        };

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(op_tag)
            .tag(TAG_PARTY_ID, session_preparer.my_role()?.to_string());
        {
            let mut guarded_meta_store = self.crs_meta_store.write().await;
            guarded_meta_store.insert(&req_id)?;
        }

        let session_id = req_id.derive_session_id()?;
        // CRS ceremony requires a sync network
        let session = session_preparer
            .make_base_session(session_id, *context_id, NetworkMode::Sync)
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
                let _timer = timer.start();
                tokio::select! {
                   res  = Self::crs_gen_background(&req_id, witness_dim, max_num_bits, session, rng, meta_store, crypto_storage, sk, dkg_params.to_owned(), eip712_domain_copy, permit, insecure) => {
                        // Increment the error counter if ever the task fails
                        if res.is_err() {
                            metrics::METRICS.increment_error_counter(op_tag, ERR_CRS_GEN_FAILED);
                        }
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&req_id);
                        tracing::info!("CRS generation of request {} exiting normally.", req_id);
                    },
                    () = token.cancelled() => {
                        tracing::error!("CRS generation of request {} exiting before completion because of a cancellation event.", req_id);
                        // Delete any persistant data. Since we only cancel during shutdown we can ignore cleaning up the meta store since it is only in RAM
                        let guarded_meta_store= meta_store_cancelled.write().await;
                        crypto_storage_cancelled.purge_crs_material(&req_id, guarded_meta_store).await;
                        metrics::METRICS.increment_error_counter(op_tag, ERR_CANCELLED);
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
        let request_id =
            parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::CrsGenResponse)?;
        let status = {
            let guarded_meta_store = self.crs_meta_store.read().await;
            guarded_meta_store.retrieve(&request_id)
        };
        let crs_data = handle_res_mapping(status, &request_id, "CRS generation").await?;

        match crs_data {
            CrsGenMetadata::Current(crs_data) => {
                if crs_data.crs_id != request_id {
                    return Err(Status::new(
                        tonic::Code::Internal,
                        format!(
                            "Request ID mismatch: expected {}, got {}",
                            request_id, crs_data.crs_id
                        ),
                    ));
                }
                Ok(Response::new(CrsGenResult {
                    request_id: Some(request_id.into()),
                    crs_digest: crs_data.crs_digest,
                    max_num_bits: crs_data.max_num_bits,
                    external_signature: crs_data.external_signature,
                }))
            }
            CrsGenMetadata::LegacyV0(_) => {
                // This is a legacy result, we cannot return the crs_digest or external_signature
                // as they're signed using a different SolStruct and hashed using a different domain separator
                tracing::warn!(
                    "Received a legacy CRS generation result,
                not returning crs_digest or external_signature"
                );
                // The old SignedPubDataHandleInternal does not store max_num_bits
                // so we have to read it from storage if we want to return it.
                // But because this is a legacy result and the call path will not reach here
                // (because a restart is needed to upgrade to the new version and the meta store is deleted from RAM)
                // it is never needed, so we just return 0 for max_num_bits.
                Ok(Response::new(CrsGenResult {
                    request_id: Some(request_id.into()),
                    crs_digest: vec![],
                    max_num_bits: 0,
                    external_signature: vec![],
                }))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn crs_gen_background(
        req_id: &RequestId,
        witness_dim: usize,
        max_num_bits: Option<u32>,
        mut base_session: BaseSession,
        rng: AesRng,
        meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
        crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
        sk: Arc<PrivateSigKey>,
        params: DKGParams,
        eip712_domain: alloy_sol_types::Eip712Domain,
        permit: OwnedSemaphorePermit,
        insecure: bool,
    ) -> Result<(), ()> {
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
                    let crs_res =
                        async_generate_crs(&sk, params, max_num_bits, domain, req_id, rng).await;
                    let crs = match crs_res {
                        Ok((crs, _)) => crs,
                        Err(e) => {
                            let mut guarded_meta_store = meta_store.write().await;
                            let _ = guarded_meta_store.update(req_id, Err(e.to_string()));
                            return Err(());
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
            compute_info_crs(&sk, &DSEP_PUBDATA_CRS, req_id, &pp, &eip712_domain)
                .map(|pub_info| (pp, pub_info))
        });

        let (pp, crs_info) = match res_info_pp {
            Ok((pp, pp_id)) => (pp, pp_id),
            Err(e) => {
                let mut guarded_meta_store = meta_store.write().await;
                // We cannot do much if updating the storage fails at this point...
                let _ = guarded_meta_store.update(req_id, Err(e.to_string()));
                return Err(());
            }
        };

        tracing::info!("CRS generation completed for req_id={req_id}, storing the CRS.");
        //Note: We can't easily check here whether we succeeded writing to the meta store
        //thus we can't increment the error counter if it fails
        crypto_storage
            .write_crs_with_meta_store(req_id, pp, crs_info, meta_store)
            .await;

        let crs_stop_timer = Instant::now();
        let elapsed_time = crs_stop_timer.duration_since(crs_start_timer);
        tracing::info!(
            "CRS stored. CRS ceremony time was {:?} ms",
            (elapsed_time).as_millis()
        );
        Ok(())
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
                session_preparer_getter: value.session_preparer_getter.clone(),
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

    use kms_grpc::{
        kms::v1::FheParameter,
        rpc_types::{alloy_to_protobuf_domain, KMSType},
    };
    use rand::SeedableRng;
    use threshold_fhe::{
        algebra::structure_traits::Ring,
        execution::{
            runtime::session::BaseSessionHandles, small_execution::prss::PRSSSetup,
            zk::ceremony::FinalizedInternalPublicParameter,
        },
    };

    use crate::{
        consts::DURATION_WAITING_ON_RESULT_SECONDS,
        cryptography::internal_crypto_types::gen_sig_keys,
        dummy_domain,
        engine::threshold::service::session::{SessionPreparer, SessionPreparerManager},
    };

    use super::*;

    impl<
            PubS: Storage + Send + Sync + 'static,
            PrivS: Storage + Send + Sync + 'static,
            C: Ceremony + Send + Sync + 'static,
        > RealCrsGenerator<PubS, PrivS, C>
    {
        async fn init_test(
            base_kms: BaseKmsStruct,
            pub_storage: PubS,
            priv_storage: PrivS,
            session_preparer_getter: SessionPreparerGetter,
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
                base_kms,
                crypto_storage,
                crs_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                session_preparer_getter,
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

    async fn make_crs_gen<C: Ceremony + 'static>(
        rng: &mut AesRng,
    ) -> RealCrsGenerator<ram::RamStorage, ram::RamStorage, C> {
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk).unwrap();
        let prss_setup_z128 = Arc::new(RwLock::new(Some(PRSSSetup::new_testing_prss(
            vec![],
            vec![],
        ))));
        let prss_setup_z64 = Arc::new(RwLock::new(Some(PRSSSetup::new_testing_prss(
            vec![],
            vec![],
        ))));
        let session_preparer_manager = SessionPreparerManager::new_test_session();
        let session_preparer = SessionPreparer::new_test_session(
            base_kms.new_instance().await,
            prss_setup_z128,
            prss_setup_z64,
        );
        session_preparer_manager
            .insert(*DEFAULT_MPC_CONTEXT, session_preparer)
            .await;

        let pub_storage = ram::RamStorage::new();
        let priv_storage = ram::RamStorage::new();
        RealCrsGenerator::<ram::RamStorage, ram::RamStorage, C>::init_test(
            base_kms,
            pub_storage,
            priv_storage,
            session_preparer_manager.make_getter(),
        )
        .await
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(123);
        let crs_gen = make_crs_gen::<InsecureCeremony>(&mut rng).await;

        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        {
            // missing request ID
            let req = CrsGenRequest {
                params: FheParameter::Default as i32,
                max_num_bits: None,
                request_id: None,
                domain: Some(domain),
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
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

        {
            // use the wrong fhe parameter
            let req_id = RequestId::new_random(&mut rng);
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            let req = CrsGenRequest {
                params: 200, // wrong parameter
                max_num_bits: None,
                request_id: Some(req_id.into()),
                domain: Some(domain),
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            };

            let request = Request::new(req);
            let res = crs_gen.crs_gen(request).await;

            assert_eq!(res.unwrap_err().code(), tonic::Code::InvalidArgument);
        }

        {
            // missing domain
            let req_id = RequestId::new_random(&mut rng);
            let req = CrsGenRequest {
                params: FheParameter::Default as i32,
                max_num_bits: None,
                request_id: Some(req_id.into()),
                domain: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            };

            let request = Request::new(req);
            assert_eq!(
                crs_gen.crs_gen(request).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }

        {
            // wrong domain
            let mut domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
            domain.verifying_contract = "wrong_contract".to_string();
            let req_id = RequestId::new_random(&mut rng);
            let req = CrsGenRequest {
                params: FheParameter::Default as i32,
                max_num_bits: None,
                request_id: Some(req_id.into()),
                domain: Some(domain),
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            };

            let request = Request::new(req);
            assert_eq!(
                crs_gen.crs_gen(request).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn not_found() {
        let mut rng = AesRng::seed_from_u64(123);
        let crs_gen = make_crs_gen::<InsecureCeremony>(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
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
        let mut rng = AesRng::seed_from_u64(123);
        let mut crs_gen = make_crs_gen::<InsecureCeremony>(&mut rng).await;

        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        crs_gen.set_bucket_size(1);

        let req_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
        };

        let request = Request::new(req);
        let res = crs_gen.crs_gen(request).await;

        assert_eq!(res.unwrap_err().code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn internal_failure() {
        // Even if the CRS ceremony fails, we should not return an error
        // because it's happening in the background.
        let mut rng = AesRng::seed_from_u64(123);
        let crs_gen = make_crs_gen::<BrokenCeremony>(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
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
        let mut rng = AesRng::seed_from_u64(123);
        // use the slow CRS gen
        let crs_gen = make_crs_gen::<SlowCeremony>(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);

        // start the ceremony but immediately fetch the result, it should be not found too
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
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
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(123);
        let crs_gen = make_crs_gen::<InsecureCeremony>(&mut rng).await;

        let req_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
        };

        crs_gen.crs_gen(Request::new(req.clone())).await.unwrap();

        // we send the same request again, it should return an error
        assert_eq!(
            crs_gen.crs_gen(Request::new(req)).await.unwrap_err().code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(123);
        let crs_gen = make_crs_gen::<InsecureCeremony>(&mut rng).await;

        // Test that we can successfully generate a CRS
        let req_id = RequestId::new_random(&mut rng);
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        let req = CrsGenRequest {
            params: FheParameter::Default as i32,
            max_num_bits: None,
            request_id: Some(req_id.into()),
            domain: Some(domain),
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
        };

        let request = Request::new(req);
        crs_gen.crs_gen(request).await.unwrap();
        let _crs = crs_gen
            .get_result(Request::new(req_id.into()))
            .await
            .unwrap();
    }
}
