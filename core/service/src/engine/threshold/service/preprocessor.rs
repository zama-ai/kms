// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

// === External Crates ===
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult},
    rpc_types::optional_protobuf_to_alloy_domain,
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{
        ERR_CANCELLED, ERR_USER_PREPROC_FAILED, OP_KEYGEN_PREPROC_REQUEST, TAG_PARTY_ID,
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
        runtime::{
            party::Identity,
            session::{BaseSession, ParameterHandles, SmallSession},
        },
        small_execution::prss::{DerivePRSSState, PRSSSetup},
        tfhe_internals::parameters::DKGParams,
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
        base::{compute_external_signature_preprocessing, retrieve_parameters},
        keyset_configuration::preproc_proto_to_keyset_config,
        threshold::{service::session::SessionPreparerGetter, traits::KeyGenPreprocessor},
        validation::{
            parse_optional_proto_request_id, parse_proto_request_id, RequestIdParsingErr,
        },
    },
    ok_or_tonic_abort, some_or_tonic_abort,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
};

// === Current Module Imports ===
use super::BucketMetaStore;

pub struct RealPreprocessor<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>>
{
    // TODO eventually add mode to allow for nlarge as well.
    pub(crate) sig_key: Arc<PrivateSigKey>,
    pub prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    pub preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    pub preproc_factory:
        Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
    pub num_sessions_preproc: u16,
    pub session_preparer_getter: SessionPreparerGetter,
    pub tracker: Arc<TaskTracker>,
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
    pub(crate) _producer_factory: PhantomData<P>,
}

impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>> RealPreprocessor<P> {
    async fn launch_dkg_preproc(
        &self,
        dkg_params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        request_id: RequestId,
        context_id: Option<RequestId>,
        domain: &alloy_sol_types::Eip712Domain,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        let session_preparer = self
            .session_preparer_getter
            .get(&context_id.unwrap_or(*DEFAULT_MPC_CONTEXT))
            .await?;

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(OP_KEYGEN_PREPROC_REQUEST)
            .tag(TAG_PARTY_ID, session_preparer.my_role()?.to_string());
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }
        // Derive a sequence of sessionId from request_id
        let own_identity = session_preparer.own_identity().await?;

        let sids = (0..self.num_sessions_preproc)
            .map(|ctr| request_id.derive_session_id_with_counter(ctr as u64))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let base_sessions = {
            let mut res = Vec::with_capacity(sids.len());
            for sid in sids {
                let base_session = session_preparer
                    .make_base_session(sid, NetworkMode::Sync)
                    .await?;
                res.push(base_session)
            }
            res
        };

        let factory = Arc::clone(&self.preproc_factory);
        let bucket_store = Arc::clone(&self.preproc_buckets);
        let bucket_store_cancellation = Arc::clone(&self.preproc_buckets);

        let prss_setup = some_or_tonic_abort(
            (*self.prss_setup.read().await).clone(),
            "No PRSS setup exists".to_string(),
        )?;

        let token = CancellationToken::new();
        {
            self.ongoing.lock().await.insert(request_id, token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);

        let sk = Arc::clone(&self.sig_key);
        let domain_clone = domain.clone();
        self.tracker.spawn(
            async move {
                //Start the metric timer, it will end on drop
                let _timer = timer.start();
                 tokio::select! {
                    res = Self::preprocessing_background(sk, &request_id, &domain_clone, base_sessions, bucket_store, prss_setup, own_identity, dkg_params, keyset_config, factory, permit) => {
                        if res.is_err() {
                            metrics::METRICS.increment_error_counter(OP_KEYGEN_PREPROC_REQUEST, ERR_USER_PREPROC_FAILED);
                        }
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&request_id);
                        tracing::info!("Preprocessing of request {} exiting normally.", &request_id);
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
        base_sessions: Vec<BaseSession>,
        bucket_store: Arc<RwLock<MetaStore<BucketMetaStore>>>,
        prss_setup: PRSSSetup<ResiduePolyF4Z128>,
        own_identity: Identity,
        params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        factory: Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), ()> {
        let _permit = permit; // dropped at the end of the function
        fn create_sessions(
            base_sessions: Vec<BaseSession>,
            prss_setup: PRSSSetup<ResiduePolyF4Z128>,
        ) -> Vec<SmallSession<ResiduePolyF4Z128>> {
            base_sessions
                .into_iter()
                .filter_map(|base_session| {
                    let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
                    match SmallSession::new_from_prss_state(base_session, prss_state) {
                        Ok(session) => Some(session),
                        Err(err) => {
                            tracing::error!("Failed to create small session: {}", err);
                            None
                        }
                    }
                })
                .collect_vec()
        }
        let sessions = create_sessions(base_sessions, prss_setup);
        // Create the orchestrator
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
                    Ok((_, preproc_handle)) => Ok(Arc::new(Mutex::new(preproc_handle))),
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

        let external_signature = match compute_external_signature_preprocessing(&sk, req_id, domain)
        {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("Failed to compute external signature: {}", e);
                return Err(());
            }
        };

        let mut guarded_meta_store = bucket_store.write().await;

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
}

#[tonic::async_trait]
impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>> + Send + Sync>
    KeyGenPreprocessor for RealPreprocessor<P>
{
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        let permit = self.rate_limiter.start_preproc().await?;

        let inner = request.into_inner();
        let domain = optional_protobuf_to_alloy_domain(inner.domain.as_ref())?;
        let request_id = parse_optional_proto_request_id(
            &inner.request_id,
            RequestIdParsingErr::PreprocRequest,
        )?;

        //Retrieve the DKG parameters
        let dkg_params = retrieve_parameters(Some(inner.params))?;

        //Ensure there's no entry in preproc buckets for that request_id
        let entry_exists = {
            let map = self.preproc_buckets.read().await;
            map.exists(&request_id)
        };

        let keyset_config = preproc_proto_to_keyset_config(&inner.keyset_config)?;

        // If the entry did not exist before, start the preproc
        // NOTE: We currently consider an existing entry is NOT an error
        if !entry_exists {
            tracing::info!("Starting preproc generation for Request ID {}", request_id);
            // We don't increment the error counter here but rather in launch_dkg_preproc
            let ctx = inner.context_id.map(|x| x.try_into()).transpose().map_err(
                |e: kms_grpc::IdentifierError| {
                    tonic::Status::new(tonic::Code::Internal, e.to_string())
                },
            )?;
            ok_or_tonic_abort(self.launch_dkg_preproc(dkg_params, keyset_config, request_id,  ctx, &domain, permit).await, format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {dkg_params:?}"))?;
            Ok(Response::new(Empty {}))
        } else {
            Err(tonic::Status::already_exists(format!(
                "Preprocessing for request ID {request_id} already exists"
            )))
        }
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        let request_id =
            parse_proto_request_id(&request.into_inner(), RequestIdParsingErr::PreprocResponse)?;

        let status = {
            let guarded_meta_store = self.preproc_buckets.read().await;
            guarded_meta_store.retrieve(&request_id)
        };

        // if we got the result it means the preprocessing is done
        let preproc_data = handle_res_mapping(status, &request_id, "Preprocessing").await?;

        if preproc_data.preprocessing_id != request_id {
            return Err(Status::internal(format!(
                "Internal error: preprocessing ID mismatch for request ID, expecting {}, got {}",
                request_id, preproc_data.preprocessing_id
            )));
        }

        Ok(Response::new(KeyGenPreprocResult {
            preprocessing_id: Some(request_id.into()),
            external_signature: preproc_data.external_signature,
        }))
    }

    async fn get_all_preprocessing_ids(&self) -> Result<Vec<String>, Status> {
        let guarded_meta_store = self.preproc_buckets.read().await;
        let request_ids = guarded_meta_store.get_all_request_ids();
        Ok(request_ids.into_iter().map(|id| id.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::{
        kms::v1::FheParameter,
        rpc_types::{alloy_to_protobuf_domain, KMSType},
    };
    use rand::SeedableRng;
    use threshold_fhe::{
        execution::online::preprocessing::create_memory_factory,
        malicious_execution::online::preprocessing::orchestration::malicious_producer_traits::{
            DummyProducerFactory, FailingProducerFactory,
        },
    };

    use crate::{cryptography::internal_crypto_types::gen_sig_keys, dummy_domain};

    use super::*;
    use crate::engine::{
        base::BaseKmsStruct,
        threshold::service::session::{SessionPreparer, SessionPreparerManager},
    };

    impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>> RealPreprocessor<P> {
        fn init_test(
            sk: Arc<PrivateSigKey>,
            prss_setup_z128: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
            session_preparer_getter: SessionPreparerGetter,
        ) -> Self {
            let tracker = Arc::new(TaskTracker::new());
            let rate_limiter = RateLimiter::default();
            let ongoing = Arc::new(Mutex::new(HashMap::new()));
            Self {
                sig_key: sk,
                prss_setup: prss_setup_z128,
                preproc_buckets: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                preproc_factory: Arc::new(Mutex::new(create_memory_factory())),
                num_sessions_preproc: 2,
                session_preparer_getter,
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
        let (_pk, sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk.clone()).unwrap();
        let prss_setup_z128 = Arc::new(RwLock::new(if use_prss {
            Some(PRSSSetup::new_testing_prss(vec![], vec![]))
        } else {
            None
        }));
        let prss_setup_z64 = Arc::new(RwLock::new(if use_prss {
            Some(PRSSSetup::new_testing_prss(vec![], vec![]))
        } else {
            None
        }));
        let session_preparer_manager = SessionPreparerManager::new_test_session();
        let session_preparer =
            SessionPreparer::new_test_session(base_kms, prss_setup_z128.clone(), prss_setup_z64);
        session_preparer_manager
            .insert(*DEFAULT_MPC_CONTEXT, session_preparer)
            .await;
        RealPreprocessor::<P>::init_test(
            Arc::new(sk),
            prss_setup_z128,
            session_preparer_manager.make_getter(),
        )
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
    async fn aborted() {
        // Starting a preprocessing request that will be aborted if there's no PRSS
        let mut rng = AesRng::seed_from_u64(22);
        let prep = setup_prep::<DummyProducerFactory>(&mut rng, false).await;
        let domain = alloy_to_protobuf_domain(&dummy_domain()).unwrap();

        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
            context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
            domain: Some(domain),
        };
        assert_eq!(
            prep.key_gen_preproc(tonic::Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
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
