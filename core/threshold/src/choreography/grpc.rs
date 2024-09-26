//! gRPC-based choreography.

pub mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_choreography");
}

use self::gen::choreography_server::{Choreography, ChoreographyServer};
use self::gen::{
    CrsGenResultRequest, CrsGenResultResponse, PreprocDecryptRequest, PreprocDecryptResponse,
    PreprocKeyGenRequest, PreprocKeyGenResponse, PrssInitRequest, PrssInitResponse,
    StatusCheckRequest, StatusCheckResponse, ThresholdDecryptRequest, ThresholdDecryptResponse,
    ThresholdDecryptResultRequest, ThresholdDecryptResultResponse, ThresholdKeyGenRequest,
    ThresholdKeyGenResponse, ThresholdKeyGenResultRequest, ThresholdKeyGenResultResponse,
};

use crate::algebra::base_ring::Z64;
use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, RingEmbed};
use crate::choreography::requests::{
    CrsGenParams, PreprocDecryptParams, PreprocKeyGenParams, PrssInitParams, SessionType, Status,
    ThresholdDecryptParams, ThresholdKeyGenParams, ThresholdKeyGenResultParams,
};
use crate::execution::endpoints::decryption::{
    init_prep_bitdec_large, init_prep_bitdec_small, run_decryption_bitdec_64,
    run_decryption_noiseflood_64, NoiseFloodPreparation,
};
use crate::execution::endpoints::decryption::{Large, Small};
use crate::execution::endpoints::keygen::FhePubKeySet;
use crate::execution::endpoints::keygen::{
    distributed_keygen_z128, distributed_keygen_z64, PrivateKeySet,
};
use crate::execution::large_execution::vss::RealVss;
use crate::execution::online::preprocessing::dummy::DummyPreprocessing;
use crate::execution::online::preprocessing::orchestrator::PreprocessingOrchestrator;
use crate::execution::online::preprocessing::{
    BitDecPreprocessing, DKGPreprocessing, NoiseFloodPreprocessing, PreprocessorFactory,
};
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::BaseSession;
use crate::execution::runtime::session::SmallSession;
use crate::execution::runtime::session::{BaseSessionStruct, ParameterHandles};
use crate::execution::runtime::session::{DecryptionMode, LargeSession, SessionParameters};
use crate::execution::tfhe_internals::parameters::DKGParams;
use crate::execution::zk::ceremony::{Ceremony, PublicParameter, RealCeremony};
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::networking::{NetworkMode, NetworkingStrategy};
use crate::{execution::small_execution::prss::PRSSSetup, session_id::SessionId};
use aes_prng::AesRng;
use async_trait::async_trait;
use clap::ValueEnum;
use dashmap::DashMap;
use gen::{CrsGenRequest, CrsGenResponse};
use itertools::Itertools;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tracing::{instrument, Instrument};

#[derive(Clone, PartialEq, Eq, Hash, Debug, ValueEnum, Serialize, Deserialize)]
pub enum SupportedRing {
    ResiduePoly64,
    ResiduePoly128,
}

#[derive(Clone)]
enum SupportedPRSSSetup {
    //NOTE: For now we never deal with ResiduePoly64 option
    ResiduePoly64(PRSSSetup<ResiduePoly64>),
    ResiduePoly128(PRSSSetup<ResiduePoly128>),
}

impl SupportedPRSSSetup {
    fn get_poly64(&self) -> Result<PRSSSetup<ResiduePoly64>, tonic::Status> {
        match self {
            SupportedPRSSSetup::ResiduePoly64(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for poly64, make sure you init it first",
            )),
        }
    }

    fn get_poly128(&self) -> Result<PRSSSetup<ResiduePoly128>, tonic::Status> {
        match self {
            SupportedPRSSSetup::ResiduePoly128(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for poly128, make sure you init it first",
            )),
        }
    }
}

type DKGPreprocRegularStore =
    DashMap<SessionId, (DKGParams, Box<dyn DKGPreprocessing<ResiduePoly64>>)>;
type DKGPreprocSnsStore =
    DashMap<SessionId, (DKGParams, Box<dyn DKGPreprocessing<ResiduePoly128>>)>;
type KeyStore = DashMap<SessionId, Arc<(FhePubKeySet, PrivateKeySet)>>;
type DDecPreprocNFStore = DashMap<SessionId, Box<dyn NoiseFloodPreprocessing>>;
type DDecPreprocBitDecStore = DashMap<SessionId, Box<dyn BitDecPreprocessing>>;
type DDecResultStore = DashMap<SessionId, Vec<Z64>>;
type CrsStore = DashMap<SessionId, PublicParameter>;
type StatusStore = DashMap<SessionId, JoinHandle<()>>;

#[derive(Default)]
struct GrpcDataStores {
    prss_setup: Arc<DashMap<SupportedRing, SupportedPRSSSetup>>,
    dkg_preproc_store_regular: Arc<DKGPreprocRegularStore>,
    dkg_preproc_store_sns: Arc<DKGPreprocSnsStore>,
    key_store: Arc<KeyStore>,
    ddec_preproc_store_nf: Arc<DDecPreprocNFStore>,
    ddec_preproc_store_bd: Arc<DDecPreprocBitDecStore>,
    ddec_result_store: Arc<DDecResultStore>,
    crs_store: Arc<CrsStore>,
    status_store: Arc<StatusStore>,
}

pub struct GrpcChoreography {
    own_identity: Identity,
    networking_strategy: NetworkingStrategy,
    factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
    data: GrpcDataStores,
}

impl GrpcChoreography {
    pub fn new(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
        factory: Box<dyn PreprocessorFactory>,
    ) -> Self {
        tracing::debug!("Starting Party with identity: {own_identity}");
        GrpcChoreography {
            own_identity,
            networking_strategy,
            factory: Arc::new(Mutex::new(factory)),
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
    #[instrument(name = "PRSS-INIT", skip_all)]
    async fn prss_init(
        &self,
        request: tonic::Request<PrssInitRequest>,
    ) -> Result<tonic::Response<PrssInitResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let prss_params: PrssInitParams = bincode::deserialize(&request.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse prss params: {:?}", e),
            )
        })?;

        let session_id = prss_params.session_id;
        let ring = prss_params.ring;

        let params = SessionParameters::new(
            threshold,
            session_id,
            self.own_identity.clone(),
            role_assignments.clone(),
        )
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create a base session parameters: {:?}", e),
            )
        })?;

        //Requires Sync network because PRSS robust init relies on bcast
        let networking =
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Sync);

        //NOTE: Do we want to let the user specify a Rng seed for reproducibility ?
        let mut base_session = BaseSessionStruct::new(params, networking, AesRng::from_entropy())
            .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create Base Session: {:?}", e),
            )
        })?;

        let store = self.data.prss_setup.clone();
        match ring {
            SupportedRing::ResiduePoly128 => {
                let my_future = || async move {
                    let prss_setup = PRSSSetup::<ResiduePoly128>::robust_init(
                        &mut base_session,
                        &RealVss::default(),
                    )
                    .await
                    .unwrap();
                    store.insert(
                        SupportedRing::ResiduePoly128,
                        SupportedPRSSSetup::ResiduePoly128(prss_setup),
                    );
                    tracing::info!("PRSS Setup for ResiduePoly128 Done.");
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            SupportedRing::ResiduePoly64 => {
                let my_future = || async move {
                    let prss_setup = PRSSSetup::<ResiduePoly64>::robust_init(
                        &mut base_session,
                        &RealVss::default(),
                    )
                    .await
                    .unwrap();
                    store.insert(
                        SupportedRing::ResiduePoly64,
                        SupportedPRSSSetup::ResiduePoly64(prss_setup),
                    );
                    tracing::info!("PRSS Setup for ResiduePoly64 Done.");
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
        }

        Ok(tonic::Response::new(PrssInitResponse {}))
    }

    #[instrument(name = "DKG-PREPROC", skip_all)]
    async fn preproc_key_gen(
        &self,
        request: tonic::Request<PreprocKeyGenRequest>,
    ) -> Result<tonic::Response<PreprocKeyGenResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let preproc_params: PreprocKeyGenParams =
            bincode::deserialize(&request.params).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Preproc KeyGen params: {:?}", e),
                )
            })?;

        let start_sid = preproc_params.session_id;
        let num_sessions = preproc_params.num_sessions;
        let dkg_params = preproc_params.dkg_params;
        let session_type = preproc_params.session_type;

        fn create_small_sessions<Z: ErrorCorrect + Invert + RingEmbed>(
            base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
            prss_setup: &PRSSSetup<Z>,
        ) -> Vec<SmallSession<Z>> {
            base_sessions
                .into_iter()
                .map(|base_session| {
                    let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap()
                })
                .collect_vec()
        }

        fn create_large_sessions(
            base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
        ) -> Vec<LargeSession> {
            base_sessions
                .into_iter()
                .map(LargeSession::new)
                .collect_vec()
        }

        let own_identity = self.own_identity.clone();
        let factory = self.factory.clone();
        let base_sessions = (start_sid.0..start_sid.0 + num_sessions as u128)
            .map(|session_id| {
                //Set the 126th bit to 1 to avoid collision with future session id
                //this way a "normal user" sending request with id 1,2,3,...
                //won't end up with a dirty sid because of preproc dkg spawning multiple sessions.
                //An alternative would be to derive the other session IDs by using hash of given sid as seed to a PRG
                let session_id = SessionId(session_id | (1u128 << 125));
                let params = SessionParameters::new(
                    threshold,
                    session_id,
                    own_identity.clone(),
                    role_assignments.clone(),
                )
                .unwrap();
                //We are executing offline phase, so requires Sync network
                let networking = (self.networking_strategy)(
                    session_id,
                    role_assignments.clone(),
                    NetworkMode::Sync,
                );
                BaseSessionStruct::new(params.clone(), networking, AesRng::from_entropy()).unwrap()
            })
            .collect_vec();

        match (dkg_params, session_type) {
            (DKGParams::WithoutSnS(_), SessionType::Small) => {
                let prss_setup = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePoly64)
                    .ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            "Failed to retrieve prss_setup, try init it first".to_string(),
                        )
                    })?
                    .get_poly64()?;
                let result_store = self.data.dkg_preproc_store_regular.clone();
                let my_future = || async move {
                    let sessions = create_small_sessions(base_sessions, &prss_setup);

                    let orchestrator = {
                        let mut factory_guard = factory.try_lock().unwrap();
                        let factory = factory_guard.as_mut();
                        PreprocessingOrchestrator::<ResiduePoly64>::new(factory, dkg_params)
                            .unwrap()
                    };
                    let (_sessions, preproc) = {
                        //let _enter = tracing::info_span!("orchestrate").entered();
                        orchestrator
                            .orchestrate_small_session_dkg_processing(sessions)
                            .instrument(tracing::info_span!("orchestrate"))
                            .await
                            .unwrap()
                    };
                    result_store.insert(start_sid, (dkg_params, preproc));
                };
                self.data.status_store.insert(
                    start_sid,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            (DKGParams::WithoutSnS(_), SessionType::Large) => {
                let result_store = self.data.dkg_preproc_store_regular.clone();
                let my_future = || async move {
                    let sessions = create_large_sessions(base_sessions);

                    let orchestrator = {
                        let mut factory_guard = factory.try_lock().unwrap();
                        let factory = factory_guard.as_mut();
                        PreprocessingOrchestrator::<ResiduePoly64>::new(factory, dkg_params)
                            .unwrap()
                    };
                    let (_sessions, preproc) = {
                        //let _enter = tracing::info_span!("orchestrate").entered();
                        orchestrator
                            .orchestrate_large_session_dkg_processing(sessions)
                            .instrument(tracing::info_span!("orchestrate"))
                            .await
                            .unwrap()
                    };
                    result_store.insert(start_sid, (dkg_params, preproc));
                };
                self.data.status_store.insert(
                    start_sid,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            (DKGParams::WithSnS(_), SessionType::Small) => {
                let prss_setup = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePoly128)
                    .ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            "Failed to retrieve prss_setup, try init it first".to_string(),
                        )
                    })?
                    .get_poly128()?;
                let result_store = self.data.dkg_preproc_store_sns.clone();
                let my_future = || async move {
                    let sessions = create_small_sessions(base_sessions, &prss_setup);
                    let orchestrator = {
                        let mut factory_guard = factory.try_lock().unwrap();
                        let factory = factory_guard.as_mut();
                        PreprocessingOrchestrator::<ResiduePoly128>::new(factory, dkg_params)
                            .unwrap()
                    };
                    let (_sessions, preproc) = {
                        orchestrator
                            .orchestrate_small_session_dkg_processing(sessions)
                            .await
                            .unwrap()
                    };
                    result_store.insert(start_sid, (dkg_params, preproc));
                };
                self.data.status_store.insert(
                    start_sid,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            (DKGParams::WithSnS(_), SessionType::Large) => {
                let result_store = self.data.dkg_preproc_store_sns.clone();
                let my_future = || async move {
                    let sessions = create_large_sessions(base_sessions);
                    let orchestrator = {
                        let mut factory_guard = factory.try_lock().unwrap();
                        let factory = factory_guard.as_mut();
                        PreprocessingOrchestrator::<ResiduePoly128>::new(factory, dkg_params)
                            .unwrap()
                    };
                    let (_sessions, preproc) = {
                        orchestrator
                            .orchestrate_large_session_dkg_processing(sessions)
                            .await
                            .unwrap()
                    };
                    result_store.insert(start_sid, (dkg_params, preproc));
                };
                self.data.status_store.insert(
                    start_sid,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
        }
        let sid_serialized = bincode::serialize(&start_sid).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(PreprocKeyGenResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "DKG", skip_all)]
    async fn threshold_key_gen(
        &self,
        request: tonic::Request<ThresholdKeyGenRequest>,
    ) -> Result<tonic::Response<ThresholdKeyGenResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let kg_params: ThresholdKeyGenParams =
            bincode::deserialize(&request.params).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Threshold KeyGen params: {:?}", e),
                )
            })?;

        let session_id = kg_params.session_id;
        let dkg_params = kg_params.dkg_params;
        let preproc_sid = kg_params.session_id_preproc;

        let params = SessionParameters::new(
            threshold,
            session_id,
            self.own_identity.clone(),
            role_assignments.clone(),
        )
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create a base session parameters: {:?}", e),
            )
        })?;

        //This is online phase of DKG, so can work in Async network
        let networking =
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Async);

        //NOTE: Do we want to let the user specify a Rng seed for reproducibility ?
        let mut base_session = BaseSessionStruct::new(params, networking, AesRng::from_entropy())
            .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create Base Session: {:?}", e),
            )
        })?;

        let key_store = self.data.key_store.clone();
        match (dkg_params, preproc_sid) {
            (DKGParams::WithoutSnS(_), Some(id)) => {
                let (_, (params, mut preproc)) =
                    self.data.dkg_preproc_store_regular.remove(&id).ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to retrieve preprocessing for id {id}, make sure to call preprocessing first"),
                        )
                    })?;
                if params != dkg_params {
                    self.data
                        .dkg_preproc_store_regular
                        .insert(id, (params, preproc));
                    return Err(tonic::Status::new(tonic::Code::Aborted,format!("The preprocessing stored under id {id} does not match the parameters request for key gen.")));
                }

                let my_future = || async move {
                    let keys =
                        distributed_keygen_z64(&mut base_session, preproc.as_mut(), dkg_params)
                            .await
                            .unwrap();
                    key_store.insert(session_id, Arc::new(keys));
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            (DKGParams::WithoutSnS(_), None) => {
                let mut preproc =
                    DummyPreprocessing::new(session_id.0 as u64, base_session.clone());
                let my_future = || async move {
                    let keys = distributed_keygen_z64(&mut base_session, &mut preproc, dkg_params)
                        .await
                        .unwrap();
                    key_store.insert(session_id, Arc::new(keys));
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            (DKGParams::WithSnS(_), Some(id)) => {
                let (_, (params, mut preproc)) =
                    self.data.dkg_preproc_store_sns.remove(&id).ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to retrieve preprocessing for id {id}, make sure to call preprocessing first"),
                        )
                    })?;
                if params != dkg_params {
                    self.data
                        .dkg_preproc_store_sns
                        .insert(id, (params, preproc));
                    return Err(tonic::Status::new(tonic::Code::Aborted,format!("The preprocessing stored under id {id} does not match the parameters request for key gen.")));
                }

                let my_future = || async move {
                    let keys =
                        distributed_keygen_z128(&mut base_session, preproc.as_mut(), dkg_params)
                            .await
                            .unwrap();
                    key_store.insert(session_id, Arc::new(keys));
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            (DKGParams::WithSnS(_), None) => {
                let mut preproc =
                    DummyPreprocessing::new(session_id.0 as u64, base_session.clone());
                let my_future = || async move {
                    let keys = distributed_keygen_z128(&mut base_session, &mut preproc, dkg_params)
                        .await
                        .unwrap();
                    key_store.insert(session_id, Arc::new(keys));
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
        }
        let sid_serialized = bincode::serialize(&session_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(ThresholdKeyGenResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "DKG-RESULT", skip_all)]
    async fn threshold_key_gen_result(
        &self,
        request: tonic::Request<ThresholdKeyGenResultRequest>,
    ) -> Result<tonic::Response<ThresholdKeyGenResultResponse>, tonic::Status> {
        let request = request.into_inner();

        let kg_result_params: ThresholdKeyGenResultParams = bincode::deserialize(&request.params)
            .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse Threshold KeyGen Result params: {:?}", e),
            )
        })?;

        let session_id = kg_result_params.session_id;
        let dkg_params = kg_result_params.dkg_params;

        if let Some(dkg_params) = dkg_params {
            let role_assignments: HashMap<Role, Identity> =
                bincode::deserialize(&request.role_assignment).map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to parse role assignment: {:?}", e),
                    )
                })?;
            let params = SessionParameters::new(
                0,
                session_id,
                self.own_identity.clone(),
                role_assignments.clone(),
            )
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to create a base session parameters: {:?}", e),
                )
            })?;

            //We are running a fake dkg, network mode doesn't matter here
            let networking =
                (self.networking_strategy)(session_id, role_assignments, NetworkMode::Async);

            //NOTE: Do we want to let the user specify a Rng seed for reproducibility ?
            let mut base_session =
                BaseSessionStruct::new(params, networking, AesRng::from_entropy()).map_err(
                    |e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to create Base Session: {:?}", e),
                        )
                    },
                )?;
            let keys = local_initialize_key_material(&mut base_session, dkg_params)
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to do centralised key generation {:?}", e),
                    )
                })?;
            self.data
                .key_store
                .insert(session_id, Arc::new(keys.clone()));
            return Ok(tonic::Response::new(ThresholdKeyGenResultResponse {
                pub_keyset: bincode::serialize(&keys.0).map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to serialize pubkey: {:?}", e),
                    )
                })?,
            }));
        } else {
            let keys = self.data.key_store.get(&session_id);
            if let Some(keys) = keys {
                return Ok(tonic::Response::new(ThresholdKeyGenResultResponse {
                    pub_keyset: bincode::serialize(&keys.0).map_err(|e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to serialize pubkey: {:?}", e),
                        )
                    })?,
                }));
            } else {
                return Err(tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("No key stored for session id {session_id}."),
                ));
            }
        }
    }

    #[instrument(name = "DDEC-PREPROC", skip_all)]
    async fn preproc_decrypt(
        &self,
        request: tonic::Request<PreprocDecryptRequest>,
    ) -> Result<tonic::Response<PreprocDecryptResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let preproc_params: PreprocDecryptParams =
            bincode::deserialize(&request.params).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Preproc Decrypt params: {:?}", e),
                )
            })?;

        let session_id = preproc_params.session_id;
        let num_blocks = preproc_params.num_blocks as usize;
        let decryption_mode = preproc_params.decryption_mode;

        let params = SessionParameters::new(
            threshold,
            session_id,
            self.own_identity.clone(),
            role_assignments.clone(),
        )
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create a base session parameters: {:?}", e),
            )
        })?;

        //This is running offline phase for ddec, so requires Sync network
        let networking =
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Sync);

        //NOTE: Do we want to let the user specify a Rng seed for reproducibility ?
        let base_session = BaseSessionStruct::new(params, networking, AesRng::from_entropy())
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to create Base Session: {:?}", e),
                )
            })?;

        match decryption_mode {
            DecryptionMode::BitDecLargeDecrypt => {
                let mut large_session = LargeSession::new(base_session);
                let store = self.data.ddec_preproc_store_bd.clone();
                let my_future = || async move {
                    match init_prep_bitdec_large(&mut large_session, num_blocks).await {
                        Ok(preproc) => {
                            store.insert(session_id, preproc);
                        }
                        Err(_e) => {
                            tracing::error!(
                                "Failed to init preprocessing of noise flooding material"
                            );
                        }
                    };
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::BitDecSmallDecrypt => {
                let prss_state = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePoly64)
                    .ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            "Failed to retrieve prss_setup, try init it first".to_string(),
                        )
                    })?
                    .get_poly64()?
                    .new_prss_session_state(session_id);
                let mut small_session =
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap();
                let store = self.data.ddec_preproc_store_bd.clone();
                let my_future = || async move {
                    match init_prep_bitdec_small(&mut small_session, num_blocks).await {
                        Ok(preproc) => {
                            store.insert(session_id, preproc);
                        }
                        Err(_e) => {
                            tracing::error!(
                                "Failed to init preprocessing of noise flooding material"
                            );
                        }
                    };
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::PRSSDecrypt => {
                let prss_state = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePoly128)
                    .ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            "Failed to retrieve prss_setup, try init it first".to_string(),
                        )
                    })?
                    .get_poly128()?
                    .new_prss_session_state(session_id);
                let mut small_session = Small::new(
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap(),
                );
                let store = self.data.ddec_preproc_store_nf.clone();
                let my_future = || async move {
                    let preproc = match small_session.init_prep_noiseflooding(num_blocks).await {
                        Ok(preproc) => preproc,
                        Err(_e) => {
                            tracing::error!(
                                "Failed to init preprocessing of noise flooding material"
                            );
                            return;
                        }
                    };
                    store.insert(session_id, preproc);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::LargeDecrypt => {
                let mut large_session = Large::new(LargeSession::new(base_session));
                let store = self.data.ddec_preproc_store_nf.clone();
                let my_future = || async move {
                    match large_session.init_prep_noiseflooding(num_blocks).await {
                        Ok(preproc) => {
                            store.insert(session_id, preproc);
                        }
                        Err(_e) => {
                            tracing::error!(
                                "Failed to init preprocessing of noise flooding material"
                            );
                        }
                    };
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
        }

        let sid_serialized = bincode::serialize(&session_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(PreprocDecryptResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "DDEC", skip_all)]
    async fn threshold_decrypt(
        &self,
        request: tonic::Request<ThresholdDecryptRequest>,
    ) -> Result<tonic::Response<ThresholdDecryptResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let decrypt_params: ThresholdDecryptParams = bincode::deserialize(&request.params)
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Preproc Decrypt params: {:?}", e),
                )
            })?;

        let session_id = decrypt_params.session_id;
        let decryption_mode = decrypt_params.decryption_mode;
        let key_sid = decrypt_params.key_sid;
        let preproc_sid = decrypt_params.preproc_sid;
        let ctxts = decrypt_params.ctxts;

        let key_ref = self
            .data
            .key_store
            .get(&key_sid)
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Can not find key that correspond to session ID {key_sid}"),
                )
            })?
            .clone();

        let params = SessionParameters::new(
            threshold,
            session_id,
            self.own_identity.clone(),
            role_assignments.clone(),
        )
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create a base session parameters: {:?}", e),
            )
        })?;

        //This is running the online phase of ddec, so can work in Async network
        let networking =
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Async);

        //NOTE: Do we want to let the user specify a Rng seed for reproducibility ?
        let mut base_session = BaseSessionStruct::new(params, networking, AesRng::from_entropy())
            .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create Base Session: {:?}", e),
            )
        })?;

        let res_store = self.data.ddec_result_store.clone();
        match decryption_mode {
            DecryptionMode::BitDecLargeDecrypt | DecryptionMode::BitDecSmallDecrypt => {
                let mut preprocessing = if let Some(preproc_sid) = preproc_sid {
                    self.data.ddec_preproc_store_bd.remove(&preproc_sid).ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Can not find BitDec preproc that corresponds to session ID {preproc_sid}"),
                        )
                    })?.1
                } else {
                    Box::new(DummyPreprocessing::new(
                        session_id.0 as u64,
                        base_session.clone(),
                    ))
                };
                let mut res = Vec::new();

                let my_future = || async move {
                    let ks = &key_ref.0.server_key.as_ref().as_ref().key_switching_key;
                    for ctxt in ctxts.into_iter() {
                        res.push(
                            run_decryption_bitdec_64(
                                &mut base_session,
                                preprocessing.as_mut(),
                                &key_ref.1,
                                ks,
                                ctxt,
                            )
                            .await
                            .map_err(|e| {
                                tonic::Status::new(
                                    tonic::Code::Aborted,
                                    format!("Error while running bitdec ddec {e}"),
                                )
                            })
                            .unwrap(),
                        )
                    }
                    res_store.insert(session_id, res);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::PRSSDecrypt | DecryptionMode::LargeDecrypt => {
                if key_ref.0.sns_key.is_none() {
                    return Err(tonic::Status::new(tonic::Code::Aborted,format!("Asked for NoiseFlood decrypt but there is no Switch and Squash key for key at session ID {key_sid}")));
                }
                let mut preprocessing = if let Some(preproc_sid) = preproc_sid {
                    self.data.ddec_preproc_store_nf.remove(&preproc_sid).ok_or_else(|| {
                        tonic::Status::new(tonic::Code::Aborted,format!("Can not find NoiseFlood preproc that corresponds to session ID {preproc_sid}"))
                    })?.1
                } else {
                    Box::new(DummyPreprocessing::new(
                        session_id.0 as u64,
                        base_session.clone(),
                    ))
                };
                let my_future = || async move {
                    let mut res = Vec::new();
                    for ctxt in ctxts.into_iter() {
                        let ct_large = if let Some(sns_key) = &key_ref.0.sns_key {
                            sns_key.to_large_ciphertext(&ctxt).unwrap()
                        } else {
                            panic!("Missing key (it was there just before)")
                        };
                        res.push(
                            run_decryption_noiseflood_64(
                                &mut base_session,
                                preprocessing.as_mut(),
                                &key_ref.1,
                                ct_large,
                            )
                            .await
                            .map_err(|e| {
                                tonic::Status::new(
                                    tonic::Code::Aborted,
                                    format!("Error while running noiseflood ddec {e}"),
                                )
                            })
                            .unwrap(),
                        )
                    }
                    res_store.insert(session_id, res);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
        }

        let sid_serialized = bincode::serialize(&session_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(ThresholdDecryptResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "DDEC-RESULT", skip_all)]
    async fn threshold_decrypt_result(
        &self,
        request: tonic::Request<ThresholdDecryptResultRequest>,
    ) -> Result<tonic::Response<ThresholdDecryptResultResponse>, tonic::Status> {
        let request = request.into_inner();
        let session_id = bincode::deserialize(&request.request_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error deserializing session_id: {e}"),
            )
        })?;

        let res = self
            .data
            .ddec_result_store
            .get(&session_id)
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("No result found for session ID {session_id}"),
                )
            })?
            .clone();

        let res_serialized = bincode::serialize(&res).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing answer {e}"),
            )
        })?;

        Ok(tonic::Response::new(ThresholdDecryptResultResponse {
            plaintext: res_serialized,
        }))
    }

    #[instrument(name = "CRS-GEN", skip_all)]
    async fn crs_gen(
        &self,
        request: tonic::Request<CrsGenRequest>,
    ) -> Result<tonic::Response<CrsGenResponse>, tonic::Status> {
        let request = request.into_inner();

        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bincode::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let crs_params: CrsGenParams = bincode::deserialize(&request.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse Preproc Decrypt params: {:?}", e),
            )
        })?;

        let session_id = crs_params.session_id;
        let witness_dim = crs_params.witness_dim;

        let params = SessionParameters::new(
            threshold,
            session_id,
            self.own_identity.clone(),
            role_assignments.clone(),
        )
        .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create a base session parameters: {:?}", e),
            )
        })?;

        //CRS gen is a round robin, so requires a Sync network
        let networking =
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Sync);

        let mut base_session = BaseSessionStruct::new(params, networking, AesRng::from_entropy())
            .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to create Base Session: {:?}", e),
            )
        })?;

        let crs_store = self.data.crs_store.clone();
        let my_future = || async move {
            let real_ceremony = RealCeremony::default();
            let pp = real_ceremony
                .execute::<Z64, _, _>(
                    &mut base_session,
                    witness_dim as usize,
                    request.max_num_bits,
                )
                .await
                .unwrap();
            crs_store.insert(session_id, pp);
        };

        self.data.status_store.insert(
            session_id,
            tokio::spawn(my_future().instrument(tracing::Span::current())),
        );

        let sid_serialized = bincode::serialize(&session_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(CrsGenResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "CRS-RESULT", skip_all)]
    async fn crs_gen_result(
        &self,
        request: tonic::Request<CrsGenResultRequest>,
    ) -> Result<tonic::Response<CrsGenResultResponse>, tonic::Status> {
        let request = request.into_inner();

        let session_id: SessionId = bincode::deserialize(&request.request_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error deserializing session_id: {e}"),
            )
        })?;

        let res = self
            .data
            .crs_store
            .get(&session_id)
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("No result found for session ID {session_id}"),
                )
            })?
            .clone();

        let res_serialized = bincode::serialize(&res).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing answer {e}"),
            )
        })?;

        Ok(tonic::Response::new(CrsGenResultResponse {
            crs: res_serialized,
        }))
    }

    async fn status_check(
        &self,
        request: tonic::Request<StatusCheckRequest>,
    ) -> Result<tonic::Response<StatusCheckResponse>, tonic::Status> {
        let request = request.into_inner();
        let sid: SessionId = bincode::deserialize(&request.request_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error deserializing session_id: {e}"),
            )
        })?;

        let status = if let Some(handle) = self.data.status_store.get(&sid) {
            if handle.is_finished() {
                Status::Finished
            } else {
                Status::Ongoing
            }
        } else {
            Status::Missing
        };

        let status_serialized = bincode::serialize(&status).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing answer {e}"),
            )
        })?;

        Ok(tonic::Response::new(StatusCheckResponse {
            status: status_serialized,
        }))
    }
}

#[cfg(feature = "testing")]
async fn local_initialize_key_material(
    session: &mut BaseSession,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet)> {
    let _tracing_subscribe =
        tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::new());
    crate::execution::tfhe_internals::test_feature::initialize_key_material(session, params).await
}

#[cfg(not(feature = "testing"))]
async fn local_initialize_key_material(
    _session: &mut BaseSession,
    _params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet)> {
    panic!("Require the testing feature on the moby cluster to perform a local intialization of the keys")
}
