// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

// === External Crates ===
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult},
    RequestId,
};
use observability::{
    metrics::{self, DurationGuard, METRICS},
    metrics_names::{
        ERR_CANCELLED, OP_KEYGEN_PREPROC_REQUEST, OP_KEYGEN_PREPROC_RESULT, TAG_CONTEXT_ID,
        TAG_EPOCH_ID, TAG_PARTY_ID,
    },
};
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring},
    execution::{
        keyset_config as ddec_keyset_config,
        online::preprocessing::{
            orchestration::{
                dkg_orchestrator::PreprocessingOrchestrator, producer_traits::ProducerFactory,
            },
            PreprocessorFactory,
        },
        runtime::{party::Identity, sessions::small_session::SmallSession},
        tfhe_internals::parameters::DKGParams,
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Request, Response};
use tracing::Instrument;

// === Internal Crate ===
use crate::{
    cryptography::signatures::PrivateSigKey,
    engine::{
        base::{compute_external_signature_preprocessing, BaseKmsStruct},
        threshold::{service::session::ImmutableSessionMaker, traits::KeyGenPreprocessor},
        utils::MetricedError,
        validation::{parse_grpc_request_id, validate_preproc_request, RequestIdParsingErr},
    },
    util::{
        meta_store::{add_req_to_meta_store, retrieve_from_meta_store, MetaStore},
        rate_limiter::RateLimiter,
    },
};

// === Current Module Imports ===
use super::BucketMetaStore;

pub struct RealPreprocessor<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>>
{
    // TODO eventually add mode to allow for nlarge as well.
    pub(crate) base_kms: BaseKmsStruct,
    pub preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    pub preproc_factory:
        Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
    pub num_sessions_preproc: u16,
    pub(crate) session_maker: ImmutableSessionMaker,
    pub tracker: Arc<TaskTracker>,
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
    pub(crate) _producer_factory: PhantomData<P>,
}

impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>> RealPreprocessor<P> {
    #[allow(clippy::too_many_arguments)]
    async fn launch_dkg_preproc(
        &self,
        dkg_params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        request_id: RequestId,
        context_id: ContextId,
        epoch_id: EpochId,
        domain: &alloy_sol_types::Eip712Domain,
        timer: DurationGuard<'static>,
        permit: OwnedSemaphorePermit,
        #[cfg(feature = "insecure")] percentage_offline: Option<
            kms_grpc::kms::v1::PartialKeyGenPreprocParams,
        >,
    ) -> anyhow::Result<()> {
        let my_identity = self.session_maker.my_identity(&context_id).await?;

        // Derive a sequence of sessionId from request_id
        let sids = (0..self.num_sessions_preproc)
            .map(|ctr| request_id.derive_session_id_with_counter(ctr as u64))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let small_sessions = {
            let mut res = Vec::with_capacity(sids.len());
            for sid in sids {
                let session = self
                    .session_maker
                    .make_small_sync_session_z128(sid, context_id, epoch_id)
                    .await?;
                res.push(session)
            }
            res
        };

        let factory = Arc::clone(&self.preproc_factory);
        let bucket_store = Arc::clone(&self.preproc_buckets);
        let bucket_store_cancellation = Arc::clone(&self.preproc_buckets);

        let token = CancellationToken::new();
        {
            self.ongoing.lock().await.insert(request_id, token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);

        let sk = self.base_kms.sig_key()?;
        let domain_clone = domain.clone();
        self.tracker.spawn(
            async move {
                // Keep timer in the async task, will drop at the end of the task
                let _timer = timer;
                 tokio::select! {
                    res = Self::preprocessing_background(
                        sk,
                        &request_id,
                        &domain_clone,
                        small_sessions,
                        bucket_store,
                        my_identity,
                        dkg_params,
                        keyset_config,
                        factory,
                        permit,
                        #[cfg(feature = "insecure")] percentage_offline
                    ) => {
                        match res {
                            Ok(()) => {
                                tracing::info!("Preprocessing of request {} exiting normally.", &request_id);
                            },
                            Err(()) => {
                                MetricedError::handle_unreturnable_error(
                                    OP_KEYGEN_PREPROC_REQUEST,
                                    Some(request_id),
                                    "Preprocessing background task failed".to_string(),
                                );
                            }
                        }
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&request_id);
                    },
                    () = token.cancelled() => {
                        // NOTE: Any correlated randomness that was already generated should be cleaned up from Redis on drop.
                        tracing::error!("Preprocessing of request {} exiting before completion because of a cancellation event.", &request_id);
                        let mut guarded_bucket_store = bucket_store_cancellation.write().await;
                        let _ = guarded_bucket_store.update(&request_id, Result::Err("Preprocessing was cancelled".to_string()));
                        metrics::METRICS.increment_error_counter(OP_KEYGEN_PREPROC_REQUEST, ERR_CANCELLED);
                    },
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn preprocessing_background(
        sk: Arc<PrivateSigKey>,
        req_id: &RequestId,
        domain: &alloy_sol_types::Eip712Domain,
        sessions: Vec<SmallSession<ResiduePolyF4Z128>>,
        bucket_store: Arc<RwLock<MetaStore<BucketMetaStore>>>,
        own_identity: Identity,
        params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        factory: Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
        permit: OwnedSemaphorePermit,
        #[cfg(feature = "insecure")] partial_params: Option<
            kms_grpc::kms::v1::PartialKeyGenPreprocParams,
        >,
    ) -> Result<(), ()> {
        // dropped at the end of the function
        let _permit = permit;

        // Create the orchestrator
        // !! If insecure we allow generating partial preprocessing !!
        #[cfg(feature = "insecure")]
        let orchestrator_result = {
            let mut factory_guard = factory.lock().await;
            let factory = factory_guard.as_mut();
            match partial_params {
                Some(partial_params) => {
                    PreprocessingOrchestrator::<ResiduePolyF4Z128>::new_partial(
                        factory,
                        params,
                        keyset_config,
                        partial_params.percentage_offline as usize,
                    )
                }
                None => PreprocessingOrchestrator::<ResiduePolyF4Z128>::new(
                    factory,
                    params,
                    keyset_config,
                ),
            }
        };

        #[cfg(not(feature = "insecure"))]
        let orchestrator_result = {
            let mut factory_guard = factory.lock().await;
            let factory = factory_guard.as_mut();
            PreprocessingOrchestrator::<ResiduePolyF4Z128>::new(factory, params, keyset_config)
        };

        // Process the result of orchestration or orchestrator creation
        let handle_update = match orchestrator_result {
            Ok(orchestrator) => {
                tracing::info!("Starting Preproc Orchestration on P[{:?}]", own_identity);
                // Execute the orchestration with the successfully created orchestrator
                match orchestrator
                    .orchestrate_dkg_processing_small_session::<P>(sessions)
                    .await
                {
                    Ok((sessions, preproc_handle)) => {
                        Ok((sessions, Arc::new(Mutex::new(preproc_handle))))
                    }
                    Err(error) => {
                        tracing::error!("Failed during preprocessing orchestration: {}", error);
                        Err(error.to_string())
                    }
                }
            }
            Err(err) => {
                tracing::error!("Failed to create preprocessing orchestrator: {}", err);
                Err(err.to_string())
            }
        };

        #[cfg(feature = "insecure")]
        let handle_update = {
            use threshold_fhe::execution::online::preprocessing::{
                dummy::DummyPreprocessing, DKGPreprocessing,
            };

            match (handle_update, partial_params) {
                (Err(e), _) => Err(e),
                (Ok((sessions, handle)), Some(partial_params)) => {
                    if partial_params.store_dummy_preprocessing {
                        let preproc = Box::new(DummyPreprocessing::new(
                            0,
                            sessions.first().ok_or_else(|| {
                                tracing::error!(
                                    "Could not retrieve any session after partial preprocessing"
                                )
                            })?,
                        ));
                        let preproc: Box<dyn DKGPreprocessing<ResiduePolyF4Z128>> = preproc;
                        Ok((sessions, Arc::new(Mutex::new(preproc))))
                    } else {
                        Ok((sessions, handle))
                    }
                }
                (Ok((sessions, handle)), None) => Ok((sessions, handle)),
            }
        };

        let external_signature = match compute_external_signature_preprocessing(&sk, req_id, domain)
        {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("Failed to compute external signature: {}", e);
                return Err(());
            }
        };

        let mut guarded_meta_store = bucket_store.write().await;

        let handle_update = handle_update.map(|(_sessions, inner)| inner);
        // We cannot do much if updating the storage fails at this point...
        let meta_store_write = guarded_meta_store.update(
            req_id,
            handle_update.clone().map(|inner| BucketMetaStore {
                external_signature,
                preprocessing_id: *req_id,
                preprocessing_store: inner,
                dkg_param: params,
            }),
        );

        // Log completion status
        match (handle_update, meta_store_write) {
            (Ok(_), Ok(_)) => tracing::info!("Preproc Finished Successfully P[{:?}]", own_identity),
            (Err(e), _) => {
                tracing::error!("Preproc Failed P[{:?}] with error: {}", own_identity, e);
                return Err(());
            }
            (_, Err(e)) => {
                tracing::info!(
                    "Preproc Failed due to meta store issue P[{:?}] with error: {}",
                    own_identity,
                    e
                );
                return Err(());
            }
        }
        Ok(())
    }

    async fn inner_key_gen_preproc(
        &self,
        request: KeyGenPreprocRequest,
        #[cfg(feature = "insecure")] partial_params: Option<
            kms_grpc::kms::v1::PartialKeyGenPreprocParams,
        >,
    ) -> Result<Response<Empty>, MetricedError> {
        let permit = self.rate_limiter.start_preproc().await.map_err(|e| {
            MetricedError::new(
                OP_KEYGEN_PREPROC_REQUEST,
                None,
                e,
                tonic::Code::ResourceExhausted,
            )
        })?;
        let mut timer = METRICS.time_operation(OP_KEYGEN_PREPROC_REQUEST).start();

        let (request_id, context_id, epoch_id, dkg_params, keyset_config, eip712_domain) =
            validate_preproc_request(request).map_err(|e| {
                MetricedError::new(
                    OP_KEYGEN_PREPROC_REQUEST,
                    None,
                    e, // Validation error
                    tonic::Code::InvalidArgument,
                )
            })?;
        // Find the role of the current server for the given context and implicitely validate the context exists
        let my_role = self.session_maker.my_role(&context_id).await.map_err(|e| {
            MetricedError::new(
                OP_KEYGEN_PREPROC_REQUEST,
                Some(request_id),
                anyhow::anyhow!("Context {context_id} not found: {e}"),
                tonic::Code::NotFound,
            )
        })?;
        let metric_tags = vec![
            (TAG_PARTY_ID, my_role.to_string()),
            (TAG_CONTEXT_ID, context_id.as_str()),
            (TAG_EPOCH_ID, epoch_id.as_str()),
        ];
        timer.tags(metric_tags);

        if !self.session_maker.epoch_exists(&epoch_id).await {
            return Err(MetricedError::new(
                OP_KEYGEN_PREPROC_REQUEST,
                Some(request_id),
                format!("Epoch {epoch_id} not found"),
                tonic::Code::NotFound,
            ));
        }

        // Add preprocessing to metastore and fail in case it is already present
        add_req_to_meta_store(
            &mut self.preproc_buckets.write().await,
            &request_id,
            OP_KEYGEN_PREPROC_REQUEST,
        )?;

        tracing::info!("Starting preproc generation for Request ID {}", request_id);

        self.launch_dkg_preproc(
                dkg_params,
                keyset_config,
                request_id,
                context_id,
                epoch_id,
                &eip712_domain,
                timer,
                permit,
            #[cfg(feature = "insecure")] partial_params
        ).await.map_err(|e| MetricedError::new(OP_KEYGEN_PREPROC_REQUEST, Some(request_id), anyhow::anyhow!("Error launching dkg preprocessing for Request ID {request_id} and parameters {dkg_params:?}: {e}"), tonic::Code::Internal))?;
        Ok(Response::new(Empty {}))
    }
}

#[tonic::async_trait]
impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>> + Send + Sync>
    KeyGenPreprocessor for RealPreprocessor<P>
{
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        self.inner_key_gen_preproc(
            request.into_inner(),
            #[cfg(feature = "insecure")]
            None,
        )
        .await
    }

    #[cfg(feature = "insecure")]
    async fn partial_key_gen_preproc(
        &self,
        request: Request<kms_grpc::kms::v1::PartialKeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        let inner = request.into_inner();
        let base_request = inner.base_request.ok_or_else(|| {
            MetricedError::new(
                OP_KEYGEN_PREPROC_REQUEST,
                None,
                anyhow::anyhow!("Missing preproc base_request"),
                tonic::Code::InvalidArgument,
            )
        })?;
        self.inner_key_gen_preproc(base_request, inner.partial_params)
            .await
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, MetricedError> {
        let request_id =
            parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::PreprocResponse)
                .map_err(|e| {
                    MetricedError::new(
                        OP_KEYGEN_PREPROC_RESULT,
                        None,
                        e,
                        tonic::Code::InvalidArgument,
                    )
                })?;

        let preproc_data = retrieve_from_meta_store(
            self.preproc_buckets.read().await,
            &request_id,
            OP_KEYGEN_PREPROC_RESULT,
        )
        .await?;

        if preproc_data.preprocessing_id != request_id {
            return Err(MetricedError::new(
                        OP_KEYGEN_PREPROC_RESULT,
                        Some(request_id),
                        anyhow::anyhow!(
                            "Internal error: preprocessing ID mismatch for request ID, expecting {}, got {}",
                            request_id,
                            preproc_data.preprocessing_id
                        ),
                        tonic::Code::Internal,
                    ));
        }

        Ok(Response::new(KeyGenPreprocResult {
            preprocessing_id: Some(request_id.into()),
            external_signature: preproc_data.external_signature,
        }))
    }

    async fn get_all_preprocessing_ids(&self) -> Result<Vec<String>, MetricedError> {
        let guarded_meta_store = self.preproc_buckets.read().await;
        let request_ids = guarded_meta_store.get_all_request_ids();
        Ok(request_ids.into_iter().map(|id| id.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
    use crate::engine::{base::BaseKmsStruct, threshold::service::session::SessionMaker};
    use crate::{cryptography::signatures::gen_sig_keys, dummy_domain};
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::FheParameter,
        rpc_types::{alloy_to_protobuf_domain, KMSType},
    };
    use rand::SeedableRng;
    use threshold_fhe::{
        execution::{
            online::preprocessing::create_memory_factory, small_execution::prss::PRSSSetup,
        },
        malicious_execution::online::preprocessing::orchestration::malicious_producer_traits::{
            DummyProducerFactory, FailingProducerFactory,
        },
    };

    impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>> RealPreprocessor<P> {
        fn init_test(base_kms: BaseKmsStruct, session_maker: ImmutableSessionMaker) -> Self {
            let tracker = Arc::new(TaskTracker::new());
            let rate_limiter = RateLimiter::default();
            let ongoing = Arc::new(Mutex::new(HashMap::new()));
            Self {
                base_kms,
                preproc_buckets: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                preproc_factory: Arc::new(Mutex::new(create_memory_factory())),
                num_sessions_preproc: 2,
                session_maker,
                tracker,
                ongoing,
                rate_limiter,
                _producer_factory: PhantomData,
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

    async fn setup_prep<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>>(
        rng: &mut AesRng,
        use_prss: bool,
    ) -> RealPreprocessor<P> {
        let epoch_id = *DEFAULT_EPOCH_ID;
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk.clone()).unwrap();
        let prss_setup_z128 = if use_prss {
            Some(PRSSSetup::new_testing_prss(vec![], vec![]))
        } else {
            None
        };
        let prss_setup_z64 = if use_prss {
            Some(PRSSSetup::new_testing_prss(vec![], vec![]))
        } else {
            None
        };

        let session_maker = SessionMaker::four_party_dummy_session(
            prss_setup_z128,
            prss_setup_z64,
            &epoch_id,
            base_kms.new_rng().await,
        );
        RealPreprocessor::<P>::init_test(base_kms, session_maker.make_immutable())
    }

    #[tokio::test]
    async fn invalid_argument() {
        // `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        let mut rng = AesRng::seed_from_u64(22);
        let prep = setup_prep::<DummyProducerFactory>(&mut rng, true).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        {
            let request = KeyGenPreprocRequest {
                request_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid_id".to_string(),
                }),
                params: FheParameter::Test as i32,
                keyset_config: None,
                context_id: None,
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            assert_eq!(
                prep.key_gen_preproc(tonic::Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
            assert_eq!(
                prep.get_result(tonic::Request::new(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid_id".to_string(),
                }))
                .await
                .unwrap_err()
                .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // Invalid argument because request ID is empty
            let request = KeyGenPreprocRequest {
                request_id: None,
                params: FheParameter::Test as i32,
                keyset_config: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            assert_eq!(
                prep.key_gen_preproc(tonic::Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // Invalid argument because params is invalid
            let mut rng = AesRng::seed_from_u64(22);
            let req_id = RequestId::new_random(&mut rng);
            let request = KeyGenPreprocRequest {
                request_id: Some(req_id.into()),
                params: 10,
                keyset_config: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                domain: Some(domain.clone()),
                epoch_id: None,
            };
            assert_eq!(
                prep.key_gen_preproc(tonic::Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        {
            // Invalid argument because domain is missing
            let mut rng = AesRng::seed_from_u64(22);
            let req_id = RequestId::new_random(&mut rng);
            let request = KeyGenPreprocRequest {
                request_id: Some(req_id.into()),
                params: FheParameter::Test as i32,
                keyset_config: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                domain: None,
                epoch_id: None,
            };
            assert_eq!(
                prep.key_gen_preproc(tonic::Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn resource_exhausted() {
        // `ResourceExhausted` - If the KMS is currently busy with too many requests.
        let mut rng = AesRng::seed_from_u64(22);
        let mut prep = setup_prep::<DummyProducerFactory>(&mut rng, true).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();
        prep.set_bucket_size(0);

        let mut rng = AesRng::seed_from_u64(22);
        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            domain: Some(domain),
            epoch_id: None,
        };
        assert_eq!(
            prep.key_gen_preproc(tonic::Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn internal() {
        let mut rng = AesRng::seed_from_u64(22);
        // NOTE we're not using the dummy producer factory here
        let prep = setup_prep::<FailingProducerFactory>(&mut rng, true).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        let mut rng = AesRng::seed_from_u64(22);
        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            domain: Some(domain),
            epoch_id: None,
        };

        // even though we use a failing preprocessor, the request should be ok
        prep.key_gen_preproc(tonic::Request::new(request))
            .await
            .unwrap();

        // but the response should come back to be an error
        assert_eq!(
            prep.get_result(tonic::Request::new(req_id.into()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
    }

    #[tokio::test]
    async fn not_found() {
        // `NotFound` - If the preprocessing does not exist for `request`.
        {
            let mut rng = AesRng::seed_from_u64(22);
            let prep = setup_prep::<DummyProducerFactory>(&mut rng, true).await;
            let req_id = RequestId::new_random(&mut rng);

            // no need to wait because [get_result] is semi-blocking
            assert_eq!(
                prep.get_result(tonic::Request::new(req_id.into()))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
        }
        // `NotFound` - If the PRSS/epoch does not exist
        {
            let mut rng = AesRng::seed_from_u64(23);
            let prep = setup_prep::<DummyProducerFactory>(&mut rng, false).await;
            let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

            let req_id = RequestId::new_random(&mut rng);
            let request = KeyGenPreprocRequest {
                request_id: Some(req_id.into()),
                params: FheParameter::Test as i32,
                keyset_config: None,
                context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                domain: Some(domain),
                epoch_id: None,
            };
            assert_eq!(
                prep.key_gen_preproc(tonic::Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
        }
    }

    #[tokio::test]
    async fn already_exists() {
        let mut rng = AesRng::seed_from_u64(22);
        let prep = setup_prep::<DummyProducerFactory>(&mut rng, true).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            domain: Some(domain),
            epoch_id: None,
        };
        prep.key_gen_preproc(tonic::Request::new(request.clone()))
            .await
            .unwrap();

        // try again with the same request and we should get AlreadyExists error
        assert_eq!(
            prep.key_gen_preproc(tonic::Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn sunshine() {
        let mut rng = AesRng::seed_from_u64(22);
        let prep = setup_prep::<DummyProducerFactory>(&mut rng, true).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        let mut rng = AesRng::seed_from_u64(22);
        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            domain: Some(domain.clone()),
            epoch_id: None,
        };
        prep.key_gen_preproc(tonic::Request::new(request))
            .await
            .unwrap();

        // no need to wait because [get_result] is semi-blocking
        prep.get_result(tonic::Request::new(req_id.into()))
            .await
            .unwrap();
    }
}
