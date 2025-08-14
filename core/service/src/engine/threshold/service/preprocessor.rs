// === Standard Library ===
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

// === External Crates ===
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult},
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
    engine::{
        base::retrieve_parameters, keyset_configuration::preproc_proto_to_keyset_config,
        threshold::traits::KeyGenPreprocessor, validation::validate_request_id,
    },
    tonic_handle_potential_err, tonic_some_or_err,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
};

// === Current Module Imports ===
use super::{session::SessionPreparer, BucketMetaStore};

pub struct RealPreprocessor<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>>
{
    // TODO eventually add mode to allow for nlarge as well.
    pub prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    pub preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    pub preproc_factory:
        Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
    pub num_sessions_preproc: u16,
    pub session_preparer: SessionPreparer,
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
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(OP_KEYGEN_PREPROC_REQUEST)
            .tag(TAG_PARTY_ID, self.session_preparer.my_id.to_string());
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }
        // Derive a sequence of sessionId from request_id
        let own_identity = self.session_preparer.own_identity()?;

        let sids = (0..self.num_sessions_preproc)
            .map(|ctr| request_id.derive_session_id_with_counter(ctr as u64))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let base_sessions = {
            let mut res = Vec::with_capacity(sids.len());
            for sid in sids {
                let base_session = self
                    .session_preparer
                    .make_base_session(sid, NetworkMode::Sync)
                    .await?;
                res.push(base_session)
            }
            res
        };

        let factory = Arc::clone(&self.preproc_factory);
        let bucket_store = Arc::clone(&self.preproc_buckets);
        let bucket_store_cancellation = Arc::clone(&self.preproc_buckets);

        let prss_setup = tonic_some_or_err(
            (*self.prss_setup.read().await).clone(),
            "No PRSS setup exists".to_string(),
        )?;

        let token = CancellationToken::new();
        {
            self.ongoing.lock().await.insert(request_id, token.clone());
        }
        let ongoing = Arc::clone(&self.ongoing);
        self.tracker.spawn(
            async move {
                //Start the metric timer, it will end on drop
                let _timer = timer.start();
                 tokio::select! {
                    res = Self::preprocessing_background(&request_id, base_sessions, bucket_store, prss_setup, own_identity, dkg_params, keyset_config, factory, permit) => {
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
        req_id: &RequestId,
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

        let mut guarded_meta_store = bucket_store.write().await;

        // We cannot do much if updating the storage fails at this point...
        let meta_store_write = guarded_meta_store.update(req_id, handle_update.clone());

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
        let request_id: RequestId = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (key_gen_preproc)".to_string(),
        )?
        .into();
        validate_request_id(&request_id)?;

        //Retrieve the DKG parameters
        let dkg_params = retrieve_parameters(inner.params)?;

        //Ensure there's no entry in preproc buckets for that request_id
        let entry_exists = {
            let map = self.preproc_buckets.read().await;
            map.exists(&request_id)
        };

        let keyset_config = tonic_handle_potential_err(
            preproc_proto_to_keyset_config(&inner.keyset_config),
            "Failed to process keyset config".to_string(),
        )?;

        // If the entry did not exist before, start the preproc
        // NOTE: We currently consider an existing entry is NOT an error
        if !entry_exists {
            tracing::info!("Starting preproc generation for Request ID {}", request_id);
            // We don't increment the error counter here but rather in launch_dkg_preproc
            tonic_handle_potential_err(self.launch_dkg_preproc(dkg_params, keyset_config, request_id, permit).await, format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {dkg_params:?}"))?;
        } else {
            tracing::warn!(
                "Tried to generate preproc multiple times for the same Request ID {} -- skipped it!",
                request_id
            );
        }
        Ok(Response::new(Empty {}))
    }

    async fn get_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        let request_id = request.into_inner().into();
        validate_request_id(&request_id)?;

        let status = {
            let guarded_meta_store = self.preproc_buckets.read().await;
            guarded_meta_store.retrieve(&request_id)
        };

        // if we got the result it means the preprocessing is done
        let _preproc_data = handle_res_mapping(status, &request_id, "Preprocessing").await?;

        Ok(Response::new(KeyGenPreprocResult {}))
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::FheParameter;
    use rand::SeedableRng;
    use threshold_fhe::{
        execution::online::preprocessing::create_memory_factory,
        malicious_execution::online::preprocessing::orchestration::malicious_producer_traits::{
            DummyProducerFactory, FailingProducerFactory,
        },
    };

    use super::*;

    impl<P: ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>> RealPreprocessor<P> {
        fn init_test(session_preparer: SessionPreparer) -> Self {
            let tracker = Arc::new(TaskTracker::new());
            let rate_limiter = RateLimiter::default();
            let ongoing = Arc::new(Mutex::new(HashMap::new()));
            let prss_setup = session_preparer.prss_setup_z128.clone();
            Self {
                prss_setup,
                preproc_buckets: Arc::new(RwLock::new(MetaStore::new_unlimited())),
                preproc_factory: Arc::new(Mutex::new(create_memory_factory())),
                num_sessions_preproc: 2,
                session_preparer,
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

    #[tokio::test]
    async fn invalid_argument() {
        // `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        let session_preparer = SessionPreparer::new_test_session(true);
        let prep = RealPreprocessor::<DummyProducerFactory>::init_test(session_preparer);

        {
            let request = KeyGenPreprocRequest {
                request_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "invalid_id".to_string(),
                }),
                params: FheParameter::Test as i32,
                keyset_config: None,
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
            // Invalid argument because params is invalid
            let mut rng = AesRng::seed_from_u64(22);
            let req_id = RequestId::new_random(&mut rng);
            let request = KeyGenPreprocRequest {
                request_id: Some(req_id.into()),
                params: 10,
                keyset_config: None,
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
        let session_preparer = SessionPreparer::new_test_session(true);
        let mut prep = RealPreprocessor::<DummyProducerFactory>::init_test(session_preparer);
        prep.set_bucket_size(0);

        let mut rng = AesRng::seed_from_u64(22);
        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
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
        let session_preparer = SessionPreparer::new_test_session(true);
        let prep = RealPreprocessor::<FailingProducerFactory>::init_test(session_preparer);

        let mut rng = AesRng::seed_from_u64(22);
        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
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
    async fn aborted() {
        // `Aborted` - If the request ID is not given, the values in the request are not valid, or an internal problem occured.
        let session_preparer = SessionPreparer::new_test_session(true);
        let prep = RealPreprocessor::<DummyProducerFactory>::init_test(session_preparer);

        // Aborted because request_id is None
        let request = KeyGenPreprocRequest {
            request_id: None,
            params: FheParameter::Test as i32,
            keyset_config: None,
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
    async fn not_found() {
        // `NotFound` - If the preprocessing does not exist for `request`.
        let session_preparer = SessionPreparer::new_test_session(true);
        let prep = RealPreprocessor::<DummyProducerFactory>::init_test(session_preparer);

        let mut rng = AesRng::seed_from_u64(22);
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
    async fn sunshine() {
        let session_preparer = SessionPreparer::new_test_session(true);
        let prep = RealPreprocessor::<DummyProducerFactory>::init_test(session_preparer);

        let mut rng = AesRng::seed_from_u64(22);
        let req_id = RequestId::new_random(&mut rng);
        let request = KeyGenPreprocRequest {
            request_id: Some(req_id.into()),
            params: FheParameter::Test as i32,
            keyset_config: None,
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
