// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{self, Empty, KeyGenPreprocRequest, KeyGenPreprocResult},
    RequestId,
};
use observability::{
    metrics,
    metrics_names::{OP_KEYGEN_PREPROC, TAG_PARTY_ID},
};
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z128, structure_traits::Ring},
    execution::{
        keyset_config as ddec_keyset_config,
        online::preprocessing::{
            orchestration::dkg_orchestrator::PreprocessingOrchestrator, PreprocessorFactory,
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
        base::{preproc_proto_to_keyset_config, retrieve_parameters},
        threshold::{
            service::session::{SessionPreparerGetter, DEFAULT_CONTEXT_ID_ARR},
            traits::KeyGenPreprocessor,
        },
        validation::validate_request_id,
    },
    tonic_handle_potential_err, tonic_some_or_err,
    util::{
        meta_store::{handle_res_mapping, MetaStore},
        rate_limiter::RateLimiter,
    },
};

// === Current Module Imports ===
use super::BucketMetaStore;

pub struct RealPreprocessor {
    // TODO eventually add mode to allow for nlarge as well.
    pub prss_setup: Arc<RwLock<Option<PRSSSetup<ResiduePolyF4Z128>>>>,
    pub preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    pub preproc_factory:
        Arc<Mutex<Box<dyn PreprocessorFactory<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>>>>,
    pub num_sessions_preproc: u16,
    pub session_preparer_getter: SessionPreparerGetter,
    pub tracker: Arc<TaskTracker>,
    pub ongoing: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    pub rate_limiter: RateLimiter,
}

impl RealPreprocessor {
    async fn launch_dkg_preproc(
        &self,
        dkg_params: DKGParams,
        keyset_config: ddec_keyset_config::KeySetConfig,
        request_id: RequestId,
        context_id: Option<RequestId>,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        let session_preparer = self
            .session_preparer_getter
            .get(&context_id.unwrap_or(RequestId::from_bytes(DEFAULT_CONTEXT_ID_ARR)))
            .await?;

        let _request_counter = metrics::METRICS
            .increment_request_counter(OP_KEYGEN_PREPROC)
            .map_err(|e| tracing::warn!("Failed to increment request counter: {}", e));

        // Prepare the timer before giving it to the tokio task
        // that runs the computation
        let timer = metrics::METRICS
            .time_operation(OP_KEYGEN_PREPROC)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tag(TAG_PARTY_ID, session_preparer.my_id_string_unchecked())
                    .map_err(|e| tracing::warn!("Failed to add party tag id: {}", e))
            });
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }
        // Derive a sequence of sessionId from request_id
        let own_identity = session_preparer.own_identity()?;

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
                let _timer = timer.map(|b| b.start());
                 tokio::select! {
                    () = Self::preprocessing_background(&request_id, base_sessions, bucket_store, prss_setup, own_identity, dkg_params, keyset_config, factory, permit) => {
                        // Remove cancellation token since generation is now done.
                        ongoing.lock().await.remove(&request_id);
                        tracing::info!("Preprocessing of request {} exiting normally.", &request_id);
                    },
                    () = token.cancelled() => {
                        tracing::error!("Preprocessing of request {} exiting before completion because of a cancellation event.", &request_id);
                        // Delete any stored data. Since we only cancel during shutdown we can ignore cleaning up the meta store since it is only in RAM
                        let mut guarded_bucket_store = bucket_store_cancellation.write().await;
                        let _ = guarded_bucket_store.delete(&request_id);
                        tracing::info!("Trying to clean up any already written material.")
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
    ) {
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
                    .orchestrate_dkg_processing_secure_small_session(sessions)
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

        // Update the bucket store with the result (success or error)
        let mut guarded_meta_store = bucket_store.write().await;
        // We cannot do much if updating the storage fails at this point...
        let _ = guarded_meta_store.update(req_id, handle_update.clone());

        // Log completion status
        if handle_update.is_ok() {
            tracing::info!("Preproc Finished Successfully P[{:?}]", own_identity);
        } else {
            tracing::info!("Preproc Failed P[{:?}]", own_identity);
        }
    }
}

#[tonic::async_trait]
impl KeyGenPreprocessor for RealPreprocessor {
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        let permit = self
            .rate_limiter
            .start_preproc()
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::ResourceExhausted, e.to_string()))?;

        let inner = request.into_inner();
        let request_id: RequestId = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set (key_gen_preproc)".to_string(),
        )?
        .into();

        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {request_id} is not valid!"),
            ));
        }

        //Retrieve the DKG parameters
        let dkg_params = tonic_handle_potential_err(
            retrieve_parameters(inner.params),
            "Parameter choice is not recognized".to_string(),
        )?;

        //Ensure there's no entry in preproc buckets for that request_id
        let entry_exists = {
            let map = self.preproc_buckets.read().await;
            map.exists(&request_id)
        };

        let keyset_config = tonic_handle_potential_err(
            preproc_proto_to_keyset_config(&inner.keyset_config),
            "Failed to process keyset config".to_string(),
        )?;

        //If the entry did not exist before, start the preproc
        if !entry_exists {
            tracing::info!("Starting preproc generation for Request ID {}", request_id);
            tonic_handle_potential_err(
                self.launch_dkg_preproc(dkg_params, keyset_config, request_id, inner.context_id.map(|x| x.into()), permit).await,
                format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {:?}",dkg_params)
            )?;
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
