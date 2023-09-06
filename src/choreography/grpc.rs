//! gRPC-based choreography.

pub mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_choreography");
}

use self::gen::choreography_server::{Choreography, ChoreographyServer};
use self::gen::{
    DecryptionResponse, KeygenRequest, KeygenResponse, LaunchComputationRequest,
    LaunchComputationResponse, PubkeyRequest, PubkeyResponse, RetrieveResultsRequest,
    RetrieveResultsResponse,
};
use crate::choreography::grpc::gen::DecryptionRequest;
use crate::choreography::NetworkingStrategy;
use crate::computation::SessionId;
use crate::execution::distributed::{
    initialize_key_material, run_circuit_operations_debug, SetupMode,
};
use crate::execution::distributed::{run_decryption, DistributedSession};
use crate::execution::party::Identity;
use crate::execution::party::Role;
use crate::execution::prss::PRSSSetup;
use crate::lwe::{Ciphertext, PublicKey, SecretKeyShare};
use crate::value::Value;
use aes_prng::AesRng;
use async_cell::sync::AsyncCell;
use async_trait::async_trait;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ComputationOutputs {
    pub outputs: HashMap<String, Vec<Value>>,
    pub elapsed_time: Option<Duration>,
}

#[derive(Clone)]
pub struct SetupInfo {
    pub secret_key_share: SecretKeyShare,
    pub prss_setup: Option<PRSSSetup>,
    pub seed: u64,
}

type ResultStores = DashMap<SessionId, Arc<AsyncCell<ComputationOutputs>>>;
type SetupStore = DashMap<SessionId, Arc<AsyncCell<SetupInfo>>>;

pub struct GrpcChoreography {
    own_identity: Identity,
    result_stores: Arc<ResultStores>,
    networking_strategy: NetworkingStrategy,
    setup_store: Arc<SetupStore>,
    pubkey_store: Arc<Mutex<PublicKey>>,
    setup_epoch_id: AsyncCell<SessionId>,
}

impl GrpcChoreography {
    pub fn new(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
    ) -> GrpcChoreography {
        GrpcChoreography {
            own_identity,
            result_stores: Arc::new(ResultStores::default()),
            networking_strategy,
            setup_store: Arc::new(SetupStore::default()),
            setup_epoch_id: AsyncCell::default(),
            pubkey_store: Arc::new(Mutex::new(PublicKey::default())),
        }
    }

    pub fn into_server(self) -> ChoreographyServer<impl Choreography> {
        ChoreographyServer::new(self)
    }
}

#[async_trait]
impl Choreography for GrpcChoreography {
    async fn launch_computation_debug(
        &self,
        request: tonic::Request<LaunchComputationRequest>,
    ) -> Result<tonic::Response<LaunchComputationResponse>, tonic::Status> {
        tracing::info!("Launching computation");
        let request = request.into_inner();
        let ct: Ciphertext =
            bincode::deserialize::<Ciphertext>(&request.ciphertext).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse ciphertext".to_string(),
                )
            })?;
        let computation = bincode::deserialize(&request.computation).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse computation".to_string(),
            )
        })?;

        let threshold: u8 = bincode::deserialize(&request.threshold).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse threshold".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        let session_id = SessionId::new(&ct);
        let setup_epoch_id = &self.setup_epoch_id.try_get();

        match (self.result_stores.entry(session_id), setup_epoch_id) {
            (Entry::Occupied(_), _) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "session id exists already or inconsistent metric and result map".to_string(),
            )),
            (Entry::Vacant(_), None) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "No key share ID set!".to_string(),
            )),
            (Entry::Vacant(result_stores_entry), Some(se_id)) => {
                tracing::debug!("I've launched a new computation");
                let ksarc = self.setup_store.get(se_id).unwrap();
                let setup_info = ksarc.value().get().await;

                let result_cell = AsyncCell::shared();
                result_stores_entry.insert(result_cell);

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(session_id, role_assignments.clone());

                tracing::debug!("own identity: {:?}", own_identity);

                let mut session = DistributedSession::new(
                    session_id,
                    role_assignments,
                    Arc::clone(&networking),
                    threshold,
                    setup_info.prss_setup,
                    own_identity.clone(),
                );

                let execution_start_timer = Instant::now();
                let result_stores = Arc::clone(&self.result_stores);

                tokio::spawn(async move {
                    let mut rng = AesRng::from_random_seed();
                    // maximum one output per party
                    let mut results = HashMap::with_capacity(1);
                    let outputs = run_circuit_operations_debug(
                        &mut session,
                        &own_identity,
                        &computation,
                        Some(setup_info.secret_key_share),
                        Some(ct),
                        &mut rng,
                    )
                    .await
                    .unwrap();

                    tracing::info!("Results in session {:?} ready: {:?}", session_id, outputs);
                    results.insert(format!("{session_id}"), outputs);

                    let result_cell = result_stores
                        .get(&session_id)
                        .expect("session disappeared unexpectedly");

                    let execution_stop_timer = Instant::now();
                    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
                    result_cell.set(ComputationOutputs {
                        outputs: results,
                        elapsed_time: Some(elapsed_time),
                    });
                    tracing::info!(
                        "Online time was {:?} microseconds",
                        (elapsed_time).as_micros()
                    );
                });
                let serialized_session_id = bincode::serialize(&se_id).map_err(|_e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        "Could not serialize session id".to_string(),
                    )
                })?;
                Ok(tonic::Response::new(LaunchComputationResponse {
                    session_id: serialized_session_id,
                }))
            }
        }
    }

    async fn threshold_decrypt(
        &self,
        request: tonic::Request<DecryptionRequest>,
    ) -> Result<tonic::Response<DecryptionResponse>, tonic::Status> {
        tracing::info!("Launching Decryption");
        let request = request.into_inner();

        let ct = bincode::deserialize::<Ciphertext>(&request.ciphertext).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse ciphertext".to_string(),
            )
        })?;

        let mode = bincode::deserialize(&request.mode).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse decryption mode".to_string(),
            )
        })?;

        let threshold: u8 = bincode::deserialize(&request.threshold).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse threshold".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        let session_id = SessionId::new(&ct);
        let setup_epoch_id = &self.setup_epoch_id.try_get();

        match (self.result_stores.entry(session_id), setup_epoch_id) {
            (Entry::Occupied(_), _) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "session id exists already or inconsistent metric and result map".to_string(),
            )),
            (Entry::Vacant(_), None) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "No key share ID set!".to_string(),
            )),
            (Entry::Vacant(result_stores_entry), Some(se_id)) => {
                tracing::debug!("I've launched a new decryption");

                let ksarc = self.setup_store.get(se_id).unwrap();
                let setup_info = ksarc.value().get().await;

                let result_cell = AsyncCell::shared();
                result_stores_entry.insert(result_cell);

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(session_id, role_assignments.clone());

                tracing::debug!("own identity: {:?}", own_identity);

                let mut session = DistributedSession::new(
                    session_id,
                    role_assignments,
                    Arc::clone(&networking),
                    threshold,
                    setup_info.prss_setup,
                    own_identity.clone(),
                );

                let execution_start_timer = Instant::now();
                let result_stores = Arc::clone(&self.result_stores);

                tokio::spawn(async move {
                    let mut results = HashMap::with_capacity(1);
                    let outputs = run_decryption(
                        &mut session,
                        &own_identity,
                        setup_info.secret_key_share,
                        ct,
                        mode,
                        setup_info.seed,
                    )
                    .await
                    .unwrap();

                    tracing::info!("Results in session {:?} ready: {:?}", session_id, outputs);
                    results.insert(format!("{session_id}"), outputs);

                    let result_cell = result_stores
                        .get(&session_id)
                        .expect("session disappeared unexpectedly");

                    let execution_stop_timer = Instant::now();
                    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
                    result_cell.set(ComputationOutputs {
                        outputs: results,
                        elapsed_time: Some(elapsed_time),
                    });
                    tracing::info!(
                        "Online time was {:?} microseconds",
                        (elapsed_time).as_micros()
                    );
                });
                let serialized_session_id = bincode::serialize(&session_id).map_err(|_e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        "Could not serialize session id".to_string(),
                    )
                })?;
                Ok(tonic::Response::new(DecryptionResponse {
                    session_id: serialized_session_id,
                }))
            }
        }
    }

    async fn retrieve_results(
        &self,
        request: tonic::Request<RetrieveResultsRequest>,
    ) -> Result<tonic::Response<RetrieveResultsResponse>, tonic::Status> {
        let request = request.into_inner();

        let session_id = bincode::deserialize::<SessionId>(&request.session_id).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse session id".to_string(),
            )
        })?;

        let session_range = request.session_range;

        let mut results: Vec<ComputationOutputs> = Vec::with_capacity(session_range as usize);

        for i in 0..session_range {
            match self
                .result_stores
                .get(&SessionId::from(session_id.0 + i as u128))
            {
                Some(res) => {
                    let res = res.value().get().await;
                    results.push(res);
                }
                None => {
                    return Err(tonic::Status::new(
                        tonic::Code::NotFound,
                        "unknown session id".to_string(),
                    ))
                }
            }
        }

        let values = bincode::serialize(&results).expect("failed to serialize results");
        Ok(tonic::Response::new(RetrieveResultsResponse { values }))
    }

    async fn keygen(
        &self,
        request: tonic::Request<KeygenRequest>,
    ) -> Result<tonic::Response<KeygenResponse>, tonic::Status> {
        tracing::info!("Launching keygen");
        let request = request.into_inner();

        let epoch_id = bincode::deserialize::<SessionId>(&request.epoch_id).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "failed to parse epoch id".to_string())
        })?;

        let threshold: u8 = bincode::deserialize(&request.threshold).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse threshold".to_string(),
            )
        })?;

        let setup_mode: SetupMode = bincode::deserialize(&request.setup_mode).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse setup mode".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        match self.setup_store.entry(epoch_id) {
            Entry::Occupied(_) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "key epoch exists already or inconsistent metric and result map".to_string(),
            )),
            Entry::Vacant(keyshare_store_entry) => {
                tracing::debug!("I've launched a new keygen");

                // we have a new public key - store the current epoch ID
                self.setup_epoch_id.set(epoch_id);

                let result_cell = AsyncCell::shared();
                keyshare_store_entry.insert(result_cell);

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(epoch_id, role_assignments.clone());

                tracing::debug!("own identity: {:?}", own_identity);

                let session = DistributedSession::new(
                    epoch_id,
                    role_assignments,
                    Arc::clone(&networking),
                    threshold,
                    None,
                    own_identity.clone(),
                );

                let setup_store = Arc::clone(&self.setup_store);
                let pks = Arc::clone(&self.pubkey_store);

                tokio::spawn(async move {
                    let mut rng = AesRng::from_random_seed();

                    let (sk, pk, prss_setup) = initialize_key_material(
                        &session,
                        &own_identity,
                        &mut rng,
                        setup_mode,
                        request.big_ell,
                        request.plaintext_bits as u8,
                        request.seed,
                    )
                    .await
                    .unwrap();

                    let setup_result_cell = setup_store
                        .get(&epoch_id)
                        .expect("Epoch key store disappeared unexpectedly");
                    setup_result_cell.set(SetupInfo {
                        secret_key_share: sk,
                        prss_setup,
                        seed: request.seed,
                    });

                    *pks.lock().unwrap() = pk;
                    tracing::debug!("Key material stored.");
                });

                Ok(tonic::Response::new(KeygenResponse::default()))
            }
        }
    }

    async fn retrieve_pubkey(
        &self,
        request: tonic::Request<PubkeyRequest>,
    ) -> Result<tonic::Response<PubkeyResponse>, tonic::Status> {
        tracing::debug!("Retrieving pubkey...");
        let request = request.into_inner();

        let epoch_id = bincode::deserialize::<SessionId>(&request.epoch_id).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "Failed to parse epoch id".to_string())
        })?;

        match self.setup_store.get(&epoch_id) {
            Some(res) => {
                // make sure that key was generated completely
                let _ = res.value().get().await;

                let pks = Arc::clone(&self.pubkey_store);
                let pkl = pks.lock().unwrap().clone();

                let pk_serialized = bincode::serialize(&pkl).expect("failed to serialize results");
                tracing::debug!("Pubkey successfully retrieved.");

                Ok(tonic::Response::new(PubkeyResponse {
                    pubkey: pk_serialized,
                }))
            }
            None => {
                return Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Pubkey not found for epoch id {}.", epoch_id),
                ))
            }
        }
    }
}
