//! gRPC-based choreography.

pub mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_choreography");
}

use self::gen::choreography_server::{Choreography, ChoreographyServer};
use self::gen::{
    CrsCeremonyRequest, CrsCeremonyResponse, CrsRequest, CrsResponse, DecryptionResponse,
    KeygenRequest, KeygenResponse, PreprocRequest, PreprocResponse, PubkeyRequest, PubkeyResponse,
    RetrieveResultsRequest, RetrieveResultsResponse,
};
use crate::algebra::base_ring::Z64;
use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, RingEmbed};
use crate::choreography::NetworkingStrategy;
use crate::execution::endpoints::decryption::decrypt_using_noiseflooding;
use crate::execution::endpoints::decryption::{Large, Small};
use crate::execution::endpoints::keygen::FhePubKeySet;
use crate::execution::endpoints::keygen::{
    distributed_keygen_z128, distributed_keygen_z64, PrivateKeySet,
};
use crate::execution::large_execution::vss::RealVss;
use crate::execution::online::preprocessing::orchestrator::PreprocessingOrchestrator;
use crate::execution::online::preprocessing::PreprocessorFactory;
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::BaseSession;
use crate::execution::runtime::session::{BaseSessionStruct, ParameterHandles};
use crate::execution::runtime::session::{DecryptionMode, LargeSession, SessionParameters};
use crate::execution::tfhe_internals::parameters::DKGParams;
use crate::execution::tfhe_internals::parameters::{Ciphertext64, NoiseFloodParameters};
use crate::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use crate::execution::zk::ceremony::{Ceremony, PublicParameter, RealCeremony};
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::{
    choreography::grpc::gen::DecryptionRequest, execution::runtime::session::SmallSession,
};
use crate::{execution::small_execution::prss::PRSSSetup, session_id::SessionId};
use aes_prng::AesRng;
use async_cell::sync::AsyncCell;
use async_trait::async_trait;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use itertools::Itertools;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tfhe::CompactPublicKey;
use tracing::{instrument, Instrument};

///Used to store results of decryption
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ComputationOutputs {
    pub outputs: HashMap<String, Z64>,
    pub elapsed_time: Option<Duration>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum SupportedRing {
    //NOTE: For now we never deal with ResiduePoly64 option
    #[allow(dead_code)]
    ResiduePoly64,
    ResiduePoly128,
}

#[derive(Clone)]
enum SupportedPRSSSetup {
    //NOTE: For now we never deal with ResiduePoly64 option
    #[allow(dead_code)]
    ResiduePoly64(Option<PRSSSetup<ResiduePoly64>>),
    ResiduePoly128(Option<PRSSSetup<ResiduePoly128>>),
}

/// Structure that holds data from the one-time (per-epoch) init phase
#[derive(Clone)]
struct InitInfo {
    pub secret_key_share: PrivateKeySet,
    pub prss_setup: HashMap<SupportedRing, SupportedPRSSSetup>,
}
type ResultStores = DashMap<SessionId, Arc<AsyncCell<ComputationOutputs>>>;
type InitStore = DashMap<SessionId, Arc<AsyncCell<InitInfo>>>;
type CrsStore = DashMap<SessionId, Arc<AsyncCell<(PublicParameter, Duration)>>>;

#[derive(Default)]

struct GrpcDataStores {
    init_store: Arc<InitStore>,
    sns_key_store: Arc<Mutex<Option<SwitchAndSquashKey>>>,
    pubkey_store: Arc<Mutex<Option<CompactPublicKey>>>,
    crs_store: Arc<CrsStore>,
    init_epoch_id: AsyncCell<SessionId>,
    crs_epoch_id: AsyncCell<SessionId>,
    result_stores: Arc<ResultStores>,
}

pub struct GrpcChoreography {
    own_identity: Identity,
    networking_strategy: NetworkingStrategy,
    factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
    num_sessions_created: Arc<Mutex<usize>>,
    data: GrpcDataStores,
}

impl GrpcChoreography {
    pub fn new(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
        factory: Box<dyn PreprocessorFactory>,
    ) -> Self {
        GrpcChoreography {
            own_identity,
            networking_strategy,
            factory: Arc::new(Mutex::new(factory)),
            num_sessions_created: Arc::new(Mutex::new(0)),
            data: GrpcDataStores::default(),
        }
    }

    pub fn into_server(self) -> ChoreographyServer<impl Choreography> {
        ChoreographyServer::new(self)
            .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
            .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
    }
}

#[async_trait]
impl Choreography for GrpcChoreography {
    #[instrument(name = "DKG-ENDPOINT", skip(self, request))]
    async fn preproc(
        &self,
        request: tonic::Request<PreprocRequest>,
    ) -> Result<tonic::Response<PreprocResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        let params: DKGParams = bincode::deserialize(&request.params).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse dkg params".to_string(),
            )
        })?;

        let num_sessions: u8 = request.num_sessions.try_into().map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "nb_sessions must be at most 255")
        })?;

        async fn create_sessions<Z: ErrorCorrect + Invert + RingEmbed>(
            mut base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
        ) -> Vec<SmallSession<Z>> {
            let prss_setup =
                PRSSSetup::<Z>::robust_init(&mut base_sessions[0], &RealVss::default())
                    .await
                    .unwrap();
            base_sessions
                .into_iter()
                .map(|base_session| {
                    let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap()
                })
                .collect_vec()
        }

        let own_identity = self.own_identity.clone();
        let factory = self.factory.clone();
        let start_session = {
            let mut start_session_lock = self.num_sessions_created.try_lock().unwrap();
            let start_session = *start_session_lock;
            *start_session_lock += num_sessions as usize;
            start_session
        };
        let base_sessions = (start_session..start_session + num_sessions as usize)
            .map(|session_id| {
                let session_id = SessionId(session_id as u128);
                let params = SessionParameters::new(
                    threshold,
                    session_id,
                    own_identity.clone(),
                    role_assignments.clone(),
                )
                .unwrap();
                let networking = (self.networking_strategy)(session_id, role_assignments.clone());
                BaseSessionStruct::new(params.clone(), networking, AesRng::from_entropy()).unwrap()
            })
            .collect_vec();

        match params {
            DKGParams::WithoutSnS(_) => {
                let my_future = || async move {
                    let sessions = create_sessions(base_sessions).await;

                    let orchestrator = {
                        let mut factory_guard = factory.try_lock().unwrap();
                        let factory = factory_guard.as_mut();
                        PreprocessingOrchestrator::<ResiduePoly64>::new(factory, params).unwrap()
                    };
                    let (mut sessions, mut preproc) = {
                        //let _enter = tracing::info_span!("orchestrate").entered();
                        orchestrator
                            .orchestrate_small_session_dkg_processing(sessions)
                            .instrument(tracing::info_span!("orchestrate"))
                            .await
                            .unwrap()
                    };

                    //TODO: We dont do anything with the keys,
                    //At some point this should replace the keygen endpoint,
                    //but probably best to sync with kms ppl

                    distributed_keygen_z64(&mut sessions[0], preproc.as_mut(), params)
                        .await
                        .unwrap()
                };
                tokio::spawn(my_future().instrument(tracing::Span::current()));
            }
            DKGParams::WithSnS(_) => {
                let my_future = || async move {
                    let sessions = create_sessions(base_sessions).await;
                    let orchestrator = {
                        let mut factory_guard = factory.try_lock().unwrap();
                        let factory = factory_guard.as_mut();
                        PreprocessingOrchestrator::<ResiduePoly128>::new(factory, params).unwrap()
                    };
                    let (mut sessions, mut preproc) = {
                        orchestrator
                            .orchestrate_small_session_dkg_processing(sessions)
                            .await
                            .unwrap()
                    };
                    //TODO: We dont do anything with the keys,
                    //At some point this should replace the keygen endpoint,
                    //but probably best to sync with kms ppl
                    distributed_keygen_z128(&mut sessions[0], preproc.as_mut(), params)
                        .await
                        .unwrap()
                };
                tokio::spawn(my_future().instrument(tracing::Span::current()));
            }
        }
        Ok(tonic::Response::new(PreprocResponse {}))
    }

    ///NOTE: For now we only do threshold decrypt with Ctxt lifting, but we may want to propose both options
    /// (that's why we have setup_store contain a map for both options)
    #[instrument(name = "DDEC ENDPOINT", skip(self, request))]
    async fn threshold_decrypt(
        &self,
        request: tonic::Request<DecryptionRequest>,
    ) -> Result<tonic::Response<DecryptionResponse>, tonic::Status> {
        let request = request.into_inner();

        let ct = bincode::deserialize::<Ciphertext64>(&request.ciphertext).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse ciphertext".to_string(),
            )
        })?;

        //Useless for now, need to integrate large threshold decrypt to grpc
        let mode = bincode::deserialize(&request.mode).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse decryption mode".to_string(),
            )
        })?;

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        let session_id = SessionId::new(&ct).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to construct session ID".to_string(),
            )
        })?;
        let init_epoch_id = &self.data.init_epoch_id.try_get();

        match (self.data.result_stores.entry(session_id), init_epoch_id) {
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

                let setup_info = self
                    .data
                    .init_store
                    .get(se_id)
                    .map(|ksarc| ksarc.value().clone())
                    .ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Internal,
                            "failed to retrieve setup info".to_string(),
                        )
                    })?;
                let setup_info = setup_info.get().await;

                let result_cell = AsyncCell::shared();
                result_stores_entry.insert(result_cell);

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(session_id, role_assignments.clone());
                tracing::debug!(
                    "Register session_id {:?} in this party: {:?}",
                    session_id,
                    own_identity
                );

                let result_stores = Arc::clone(&self.data.result_stores);
                let pks = Arc::clone(&self.data.sns_key_store);
                let ck = match pks.lock().unwrap().clone() {
                    Some(pks) => pks,
                    None => {
                        return Err(tonic::Status::new(
                            tonic::Code::Aborted,
                            "No public key available for decryption".to_string(),
                        ))
                    }
                };
                let params = SessionParameters::new(
                    threshold,
                    session_id,
                    own_identity.clone(),
                    role_assignments,
                )
                .unwrap();
                let base_session =
                    BaseSessionStruct::new(params, Arc::clone(&networking), AesRng::from_entropy())
                        .unwrap();
                let current_span = tracing::Span::current();
                match mode {
                    DecryptionMode::PRSSDecrypt => {
                        let prss_setup =
                            match setup_info.prss_setup.get(&SupportedRing::ResiduePoly128) {
                                Some(SupportedPRSSSetup::ResiduePoly128(v)) => v.clone(),
                                _ => None,
                            };
                        let mut session = SmallSession::new_from_prss_state(
                            base_session,
                            prss_setup.unwrap().new_prss_session_state(session_id)
                        )
                        .map_err(|e| {
                            tonic::Status::new(
                                tonic::Code::Aborted,
                                format!("could not make a valid session with current parameters. Failed with error \"{:?}\"", e).to_string(),
                            )
                        })?;

                        tokio::spawn(
                            async move {
                                let mut protocol = Small::new(session.clone());
                                let (results, elapsed_time) = decrypt_using_noiseflooding(
                                    &mut session,
                                    &mut protocol,
                                    &ck,
                                    ct,
                                    &setup_info.secret_key_share,
                                    mode,
                                    own_identity,
                                )
                                .await
                                .unwrap();
                                result_stores
                                    .get(&session_id)
                                    .map(|res| {
                                        res.set(ComputationOutputs {
                                            outputs: results,
                                            elapsed_time: Some(elapsed_time),
                                        });
                                    })
                                    .expect("session disappeared unexpectedly");
                            }
                            .instrument(current_span),
                        );
                    }
                    DecryptionMode::LargeDecrypt => {
                        let mut session = LargeSession::new(base_session);
                        tokio::spawn(
                            async move {
                                let mut protocol = Large::new(session.clone());
                                let (results, elapsed_time) = decrypt_using_noiseflooding(
                                    &mut session,
                                    &mut protocol,
                                    &ck,
                                    ct,
                                    &setup_info.secret_key_share,
                                    mode,
                                    own_identity,
                                )
                                .await
                                .unwrap();
                                result_stores
                                    .get(&session_id)
                                    .map(|res| {
                                        res.set(ComputationOutputs {
                                            outputs: results,
                                            elapsed_time: Some(elapsed_time),
                                        });
                                    })
                                    .expect("session disappeared unexpectedly");
                            }
                            .instrument(current_span),
                        );
                    }
                    DecryptionMode::BitDecSmallDecrypt => todo!(),
                    DecryptionMode::BitDecLargeDecrypt => todo!(),
                }

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

    #[instrument(skip(self, request))]
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

        tracing::info!("Retrieving results for session {:?}", session_id);

        let session_range = request.session_range;

        let mut results: Vec<ComputationOutputs> = Vec::with_capacity(session_range as usize);

        for i in 0..session_range {
            match self
                .data
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
                        format!("unknown session id {:?} for choreographer", session_id.0),
                    ))
                }
            }
        }

        tracing::debug!("Results retrieved for session {:?}", session_id);
        let values = bincode::serialize(&results).expect("failed to serialize results");
        Ok(tonic::Response::new(RetrieveResultsResponse { values }))
    }

    ///Note: For now assumes keygen works with PRSS128, but we don't really have a protocol yet so...
    #[instrument(skip(self, request))]
    async fn keygen(
        &self,
        request: tonic::Request<KeygenRequest>,
    ) -> Result<tonic::Response<KeygenResponse>, tonic::Status> {
        let request = request.into_inner();

        let epoch_id = bincode::deserialize::<SessionId>(&request.epoch_id).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "failed to parse epoch id".to_string())
        })?;

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "threshold must be at most 255".to_string(),
            )
        })?;

        let dkg_params: NoiseFloodParameters =
            bincode::deserialize(&request.params).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse parameters".to_string(),
                )
            })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        match self.data.init_store.entry(epoch_id) {
            Entry::Occupied(_) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "key epoch exists already or inconsistent metric and result map".to_string(),
            )),
            Entry::Vacant(keyshare_store_entry) => {
                tracing::debug!("I've launched a new keygen");

                // we have a new public key - store the current epoch ID
                self.data.init_epoch_id.set(epoch_id);

                let result_cell = AsyncCell::shared();
                keyshare_store_entry.insert(result_cell);

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(epoch_id, role_assignments.clone());

                tracing::debug!("own identity: {:?}", own_identity);
                let session_params =
                    SessionParameters::new(threshold, epoch_id, own_identity, role_assignments)
                    .map_err(|e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("could not make a valid session parameters with current parameters. Failed with error \"{:?}\"", e).to_string(),
                        )
                    })?;
                let mut base_session =
                    BaseSessionStruct::new(session_params, Arc::clone(&networking), AesRng::from_entropy())
                    .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("could not make a valid base session with current parameters. Failed with error \"{:?}\"", e).to_string(),
                    )
                })?;

                let init_store = Arc::clone(&self.data.init_store);
                let sns_keys = Arc::clone(&self.data.sns_key_store);
                let pks = Arc::clone(&self.data.pubkey_store);

                tokio::spawn(async move {
                    let prss_setup = PRSSSetup::<ResiduePoly128>::robust_init(
                        &mut base_session,
                        &RealVss::default(),
                    )
                    .await
                    .unwrap();
                    let (pub_keys, priv_keys) =
                        local_initialize_key_material(&mut base_session, dkg_params)
                            .await
                            .unwrap();

                    let mut map_setup = HashMap::new();
                    map_setup.insert(
                        SupportedRing::ResiduePoly128,
                        SupportedPRSSSetup::ResiduePoly128(Some(prss_setup)),
                    );

                    init_store
                        .get(&epoch_id)
                        .map(|setup_result_cell| {
                            setup_result_cell.set(InitInfo {
                                secret_key_share: priv_keys,
                                prss_setup: map_setup,
                            });
                        })
                        .expect("Epoch key store disappeared unexpectedly");

                    // store the public key
                    *pks.lock().unwrap() = Some(pub_keys.public_key);
                    *sns_keys.lock().unwrap() = pub_keys.sns_key;
                    tracing::debug!("Key material stored.");
                });

                Ok(tonic::Response::new(KeygenResponse {}))
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn retrieve_pubkey(
        &self,
        request: tonic::Request<PubkeyRequest>,
    ) -> Result<tonic::Response<PubkeyResponse>, tonic::Status> {
        tracing::debug!("Retrieving pubkey...");
        let request = request.into_inner();

        let epoch_id = bincode::deserialize::<SessionId>(&request.epoch_id).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "Failed to parse epoch id".to_string())
        })?;

        let comp = self
            .data
            .init_store
            .get(&epoch_id)
            .map(|res| res.value().clone())
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Pubkey not found for epoch id {}.", epoch_id),
                )
            })?;
        // make sure that key was generated completely
        comp.get().await;

        let pks = Arc::clone(&self.data.pubkey_store);
        let pkl = pks.lock().unwrap().clone().ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "No public key available for decryption".to_string(),
            )
        })?;

        let pk_serialized = bincode::serialize(&pkl).expect("failed to serialize pubkey");
        tracing::debug!("Pubkey successfully retrieved.");

        Ok(tonic::Response::new(PubkeyResponse {
            pubkey: pk_serialized,
        }))
    }

    #[instrument(name = "CRS ENDPONT", skip(self, request))]
    async fn crs_ceremony(
        &self,
        request: tonic::Request<CrsCeremonyRequest>,
    ) -> Result<tonic::Response<CrsCeremonyResponse>, tonic::Status> {
        let request = request.into_inner();

        let epoch_id = bincode::deserialize::<SessionId>(&request.epoch_id).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "failed to parse epoch id".to_string())
        })?;

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse role assignment".to_string(),
                )
            })?;

        match self.data.crs_store.entry(epoch_id) {
            Entry::Occupied(_) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "crs epoch exists already or inconsistent metric and result map".to_string(),
            )),
            Entry::Vacant(keyshare_store_entry) => {
                tracing::debug!("I've launched a new CRS ceremony");

                // we have a new epoch - store the current epoch ID
                self.data.crs_epoch_id.set(epoch_id);

                let result_cell = AsyncCell::shared();
                keyshare_store_entry.insert(result_cell);

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(epoch_id, role_assignments.clone());

                let session_params =
                    SessionParameters::new(threshold, epoch_id, own_identity, role_assignments)
                    .map_err(|e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("could not make a valid session parameters with current parameters. Failed with error \"{:?}\"", e).to_string(),
                        )
                    })?;
                let mut base_session =
                    BaseSessionStruct::new(session_params, Arc::clone(&networking), AesRng::from_entropy())
                    .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("could not make a valid base session with current parameters. Failed with error \"{:?}\"", e).to_string(),
                    )
                })?;

                let crs_store = Arc::clone(&self.data.crs_store);
                let current_span = tracing::Span::current();
                tokio::spawn(
                    async move {
                        let crs_start_timer = Instant::now();

                        let real_ceremony = RealCeremony::default();
                        let pp = real_ceremony
                            .execute::<Z64, _, _>(&mut base_session, request.witness_dim as usize)
                            .await
                            .unwrap();

                        let crs_stop_timer = Instant::now();
                        let elapsed_time = crs_stop_timer.duration_since(crs_start_timer);
                        tracing::info!(
                            "CRS stored. CRS ceremony time was {:?} ms",
                            (elapsed_time).as_millis()
                        );

                        // store the CRS
                        crs_store
                            .get(&epoch_id)
                            .map(|result_cell| {
                                result_cell.set((pp, elapsed_time));
                            })
                            .expect("session disappeared unexpectedly");
                    }
                    .instrument(current_span),
                );

                Ok(tonic::Response::new(CrsCeremonyResponse {}))
            }
        }
    }

    async fn retrieve_crs(
        &self,
        request: tonic::Request<CrsRequest>,
    ) -> Result<tonic::Response<CrsResponse>, tonic::Status> {
        tracing::debug!("Retrieving CRS...");
        let request = request.into_inner();

        let epoch_id = bincode::deserialize::<SessionId>(&request.epoch_id).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "Failed to parse epoch id".to_string())
        })?;

        let crs = self
            .data
            .crs_store
            .get(&epoch_id)
            .map(|res| res.value().clone())
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("CRS not found for epoch id {epoch_id}."),
                )
            })?;

        // wait a bit for the crs to be generated
        // but timeout after a second since this process may take a long time
        let (pp, dur) = tokio::time::timeout(Duration::from_secs(1), crs.get())
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("CRS not ready yet for epoch id {epoch_id} ({e})"),
                )
            })?;

        let crs_ser = bincode::serialize(&pp).expect("failed to serialize CRS");
        tracing::debug!("CRS successfully retrieved.");

        Ok(tonic::Response::new(CrsResponse {
            crs: crs_ser,
            duration_secs: dur.as_secs_f32(),
        }))
    }
}

#[cfg(feature = "testing")]
async fn local_initialize_key_material(
    session: &mut BaseSession,
    params: NoiseFloodParameters,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet)> {
    crate::execution::tfhe_internals::test_feature::initialize_key_material(session, params).await
}

#[cfg(not(feature = "testing"))]
async fn local_initialize_key_material(
    _session: &mut BaseSession,
    _params: NoiseFloodParameters,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet)> {
    todo!()
}
