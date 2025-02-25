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

use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{Derive, ErrorCorrect, FromU128, Invert, RingEmbed, Solve};
#[cfg(feature = "measure_memory")]
use crate::allocator::MEM_ALLOCATOR;
use crate::choreography::requests::{
    CrsGenParams, PreprocDecryptParams, PreprocKeyGenParams, PrssInitParams, SessionType, Status,
    ThresholdDecryptParams, ThresholdKeyGenParams, ThresholdKeyGenResultParams,
};
use crate::execution::communication::broadcast::broadcast_from_all;
use crate::execution::endpoints::decryption::{
    init_prep_bitdec_large, init_prep_bitdec_small, run_decryption_bitdec_64,
    run_decryption_noiseflood_64, NoiseFloodPreparation,
};
use crate::execution::endpoints::decryption::{Large, Small};
use crate::execution::endpoints::keygen::FhePubKeySet;
use crate::execution::endpoints::keygen::{
    distributed_keygen_z128, distributed_keygen_z64, PrivateKeySet,
};
use crate::execution::keyset_config::KeySetConfig;
use crate::execution::large_execution::vss::RealVss;
use crate::execution::online::preprocessing::dummy::DummyPreprocessing;
use crate::execution::online::preprocessing::orchestrator::PreprocessingOrchestrator;
use crate::execution::online::preprocessing::{
    BitDecPreprocessing, DKGPreprocessing, NoiseFloodPreprocessing, PreprocessorFactory,
};
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::SmallSession;
use crate::execution::runtime::session::{BaseSession, BaseSessionHandles};
use crate::execution::runtime::session::{BaseSessionStruct, ParameterHandles};
use crate::execution::runtime::session::{LargeSession, SessionParameters};
use crate::execution::tfhe_internals::parameters::{AugmentedCiphertextParameters, DKGParams};
use crate::execution::zk::ceremony::{Ceremony, InternalPublicParameter, RealCeremony};
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::networking::value::BroadcastValue;
use crate::networking::{NetworkMode, NetworkingStrategy};
use crate::{execution::small_execution::prss::PRSSSetup, session_id::SessionId};
use aes_prng::AesRng;
use async_trait::async_trait;
use clap::ValueEnum;
use dashmap::DashMap;
use gen::{CrsGenRequest, CrsGenResponse};
use itertools::Itertools;
use kms_common::DecryptionMode;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tfhe::integer::IntegerRadixCiphertext;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{instrument, Instrument};

#[derive(Clone, PartialEq, Eq, Hash, Debug, ValueEnum, Serialize, Deserialize)]
pub enum SupportedRing {
    ResiduePolyZ64,
    ResiduePolyZ128,
}

#[derive(Clone)]
enum SupportedPRSSSetup<const EXTENSION_DEGREE: usize> {
    //NOTE: For now we never deal with ResiduePolyF8Z64 option
    ResiduePolyZ64(PRSSSetup<ResiduePoly<Z64, EXTENSION_DEGREE>>),
    ResiduePolyZ128(PRSSSetup<ResiduePoly<Z128, EXTENSION_DEGREE>>),
}

impl<const EXTENSION_DEGREE: usize> SupportedPRSSSetup<EXTENSION_DEGREE> {
    fn get_poly64(&self) -> Result<PRSSSetup<ResiduePoly<Z64, EXTENSION_DEGREE>>, tonic::Status> {
        match self {
            SupportedPRSSSetup::ResiduePolyZ64(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for poly64, make sure you init it first",
            )),
        }
    }

    fn get_poly128(&self) -> Result<PRSSSetup<ResiduePoly<Z128, EXTENSION_DEGREE>>, tonic::Status> {
        match self {
            SupportedPRSSSetup::ResiduePolyZ128(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for poly128, make sure you init it first",
            )),
        }
    }
}

type DKGPreprocRegularStore<const EXTENSION_DEGREE: usize> = DashMap<
    SessionId,
    (
        DKGParams,
        Box<dyn DKGPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    ),
>;
type DKGPreprocSnsStore<const EXTENSION_DEGREE: usize> = DashMap<
    SessionId,
    (
        DKGParams,
        Box<dyn DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>,
    ),
>;
type KeyStore<const EXTENSION_DEGREE: usize> =
    DashMap<SessionId, Arc<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>>;
type DDecPreprocNFStore<const EXTENSION_DEGREE: usize> =
    DashMap<SessionId, Vec<Box<dyn NoiseFloodPreprocessing<EXTENSION_DEGREE>>>>;
type DDecPreprocBitDecStore<const EXTENSION_DEGREE: usize> =
    DashMap<SessionId, Vec<Box<dyn BitDecPreprocessing<EXTENSION_DEGREE>>>>;
type DDecResultStore = DashMap<SessionId, Vec<Z64>>;
type CrsStore = DashMap<SessionId, InternalPublicParameter>;
type StatusStore = DashMap<SessionId, JoinHandle<()>>;

#[derive(Default)]
struct GrpcDataStores<const EXTENSION_DEGREE: usize> {
    prss_setup: Arc<DashMap<SupportedRing, SupportedPRSSSetup<EXTENSION_DEGREE>>>,
    dkg_preproc_store_regular: Arc<DKGPreprocRegularStore<EXTENSION_DEGREE>>,
    dkg_preproc_store_sns: Arc<DKGPreprocSnsStore<EXTENSION_DEGREE>>,
    key_store: Arc<KeyStore<EXTENSION_DEGREE>>,
    ddec_preproc_store_nf: Arc<DDecPreprocNFStore<EXTENSION_DEGREE>>,
    ddec_preproc_store_bd: Arc<DDecPreprocBitDecStore<EXTENSION_DEGREE>>,
    ddec_result_store: Arc<DDecResultStore>,
    crs_store: Arc<CrsStore>,
    status_store: Arc<StatusStore>,
}

pub struct GrpcChoreography<const EXTENSION_DEGREE: usize> {
    own_identity: Identity,
    networking_strategy: Arc<NetworkingStrategy>,
    factory: Arc<Mutex<Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>>>,
    data: GrpcDataStores<EXTENSION_DEGREE>,
}

impl<const EXTENSION_DEGREE: usize> GrpcChoreography<EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    pub fn new(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
        factory: Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>,
    ) -> Self {
        tracing::debug!("Starting Party with identity: {own_identity}");
        GrpcChoreography {
            own_identity,
            networking_strategy: Arc::new(networking_strategy),
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
impl<const EXTENSION_DEGREE: usize> Choreography for GrpcChoreography<EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    #[instrument(
        name = "PRSS-INIT",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn prss_init(
        &self,
        request: tonic::Request<PrssInitRequest>,
    ) -> Result<tonic::Response<PrssInitResponse>, tonic::Status> {
        #[cfg(feature = "measure_memory")]
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();

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
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Sync)
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create networking: {:?}", e),
                    )
                })?;

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
            SupportedRing::ResiduePolyZ128 => {
                let my_future = || async move {
                    let prss_setup = PRSSSetup::<ResiduePoly<Z128, EXTENSION_DEGREE>>::robust_init(
                        &mut base_session,
                        &RealVss::default(),
                    )
                    .await
                    .unwrap();
                    store.insert(
                        SupportedRing::ResiduePolyZ128,
                        SupportedPRSSSetup::ResiduePolyZ128(prss_setup),
                    );
                    tracing::info!("PRSS Setup for ResiduePoly128 Done.");
                    fill_network_memory_info_single_session(base_session);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            SupportedRing::ResiduePolyZ64 => {
                let my_future = || async move {
                    let prss_setup = PRSSSetup::<ResiduePoly<Z64, EXTENSION_DEGREE>>::robust_init(
                        &mut base_session,
                        &RealVss::default(),
                    )
                    .await
                    .unwrap();
                    store.insert(
                        SupportedRing::ResiduePolyZ64,
                        SupportedPRSSSetup::ResiduePolyZ64(prss_setup),
                    );
                    tracing::info!("PRSS Setup for ResiduePoly64 Done.");
                    fill_network_memory_info_single_session(base_session);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
        }

        Ok(tonic::Response::new(PrssInitResponse {}))
    }

    //TODO: FILL NETWORK INFO FROM ALL THE SESSONS
    #[instrument(
        name = "DKG-PREPROC",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
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
        let percentage_offline = preproc_params.percentage_offline as usize;
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
        let mut base_sessions = Vec::new();
        let mut session_id_generator = AesRng::seed_from_u64(start_sid.0 as u64);
        let sids = (0..num_sessions)
            .map(|_| gen_random_sid(&mut session_id_generator, start_sid.0))
            .collect_vec();
        for session_id in sids {
            let params = SessionParameters::new(
                threshold,
                session_id,
                own_identity.clone(),
                role_assignments.clone(),
            )
            .unwrap();
            //We are executing offline phase, so requires Sync network
            let networking =
                (self.networking_strategy)(session_id, role_assignments.clone(), NetworkMode::Sync)
                    .await
                    .map_err(|e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to create networking: {:?}", e),
                        )
                    })?;
            base_sessions.push(
                BaseSessionStruct::new(params.clone(), networking, AesRng::from_entropy())
                    .expect("Failed to create Base Session"),
            );
        }

        match (dkg_params, session_type) {
            (DKGParams::WithoutSnS(_), SessionType::Small) => {
                let prss_setup = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePolyZ64)
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
                        PreprocessingOrchestrator::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new_partial(
                            factory,
                            dkg_params,
                            KeySetConfig::default(),
                            percentage_offline,
                        )
                        .unwrap()
                    };
                    let (sessions, preproc) = {
                        //let _enter = tracing::info_span!("orchestrate").entered();
                        orchestrator
                            .orchestrate_small_session_dkg_processing(sessions)
                            .instrument(tracing::info_span!("orchestrate"))
                            .await
                            .unwrap()
                    };
                    fill_network_memory_info_multiple_sessions(sessions);
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
                        PreprocessingOrchestrator::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new_partial(
                            factory,
                            dkg_params,
                            KeySetConfig::default(),
                            percentage_offline,
                        )
                        .unwrap()
                    };
                    let (sessions, preproc) = {
                        //let _enter = tracing::info_span!("orchestrate").entered();
                        orchestrator
                            .orchestrate_large_session_dkg_processing(sessions)
                            .instrument(tracing::info_span!("orchestrate"))
                            .await
                            .unwrap()
                    };
                    fill_network_memory_info_multiple_sessions(sessions);
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
                    .get(&SupportedRing::ResiduePolyZ128)
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
                        PreprocessingOrchestrator::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new_partial(
                            factory,
                            dkg_params,
                            KeySetConfig::default(),
                            percentage_offline,
                        )
                        .unwrap()
                    };
                    let (sessions, preproc) = {
                        orchestrator
                            .orchestrate_small_session_dkg_processing(sessions)
                            .await
                            .unwrap()
                    };
                    fill_network_memory_info_multiple_sessions(sessions);
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
                        PreprocessingOrchestrator::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new_partial(
                            factory,
                            dkg_params,
                            KeySetConfig::default(),
                            percentage_offline,
                        )
                        .unwrap()
                    };
                    let (sessions, preproc) = {
                        orchestrator
                            .orchestrate_large_session_dkg_processing(sessions)
                            .await
                            .unwrap()
                    };
                    fill_network_memory_info_multiple_sessions(sessions);
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

    #[instrument(
        name = "DKG",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn threshold_key_gen(
        &self,
        request: tonic::Request<ThresholdKeyGenRequest>,
    ) -> Result<tonic::Response<ThresholdKeyGenResponse>, tonic::Status> {
        #[cfg(feature = "measure_memory")]
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();

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
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Async)
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create networking: {:?}", e),
                    )
                })?;

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
                    fill_network_memory_info_single_session(base_session);
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
                    fill_network_memory_info_single_session(base_session);
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
                    fill_network_memory_info_single_session(base_session);
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
                    fill_network_memory_info_single_session(base_session);
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
                (self.networking_strategy)(session_id, role_assignments, NetworkMode::Async)
                    .await
                    .map_err(|e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to create networking: {:?}", e),
                        )
                    })?;

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

    #[instrument(
        name = "DDEC-PREPROC",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn preproc_decrypt(
        &self,
        request: tonic::Request<PreprocDecryptRequest>,
    ) -> Result<tonic::Response<PreprocDecryptResponse>, tonic::Status> {
        #[cfg(feature = "measure_memory")]
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();

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
        let key_sid = preproc_params.key_sid;
        let num_ctxt = preproc_params.num_ctxts;
        let ctxt_type = preproc_params.ctxt_type;
        let log_message_modulus = self
            .data
            .key_store
            .get(&key_sid)
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Can not find key that corresponds to session ID {key_sid}"),
                )
            })?
            .1
            .parameters
            .message_modulus_log();
        let num_bits_message = ctxt_type.get_num_bits_rep();
        let num_blocks_per_ctxt = num_bits_message.div_ceil(log_message_modulus as usize);
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
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Sync)
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create networking: {:?}", e),
                    )
                })?;

        //NOTE: Do we want to let the user specify a Rng seed for reproducibility ?
        let base_session = BaseSessionStruct::new(params, networking, AesRng::from_entropy())
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to create Base Session: {:?}", e),
                )
            })?;

        match decryption_mode {
            DecryptionMode::BitDecLarge => {
                let mut large_session = LargeSession::new(base_session);
                let store = self.data.ddec_preproc_store_bd.clone();
                let my_future = || async move {
                    for _ in 0..num_ctxt {
                        match init_prep_bitdec_large(&mut large_session, num_blocks_per_ctxt).await
                        {
                            Ok(preproc) => {
                                if let Some(mut entry) = store.get_mut(&session_id) {
                                    (*entry).push(preproc);
                                } else {
                                    store.insert(session_id, vec![preproc]);
                                }
                            }
                            Err(_e) => {
                                tracing::error!(
                                    "Failed to init preprocessing of noise flooding material"
                                );
                            }
                        };
                    }

                    fill_network_memory_info_single_session(large_session);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::BitDecSmall => {
                let prss_state = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePolyZ64)
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
                    for _ in 0..num_ctxt {
                        match init_prep_bitdec_small(&mut small_session, num_blocks_per_ctxt).await
                        {
                            Ok(preproc) => {
                                if let Some(mut entry) = store.get_mut(&session_id) {
                                    (*entry).push(preproc);
                                } else {
                                    store.insert(session_id, vec![preproc]);
                                }
                            }
                            Err(_e) => {
                                tracing::error!(
                                    "Failed to init preprocessing of noise flooding material"
                                );
                            }
                        };
                    }
                    fill_network_memory_info_single_session(small_session);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::NoiseFloodSmall => {
                let prss_state = self
                    .data
                    .prss_setup
                    .get(&SupportedRing::ResiduePolyZ128)
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
                    for _ in 0..num_ctxt {
                        let preproc = match small_session
                            .init_prep_noiseflooding(num_blocks_per_ctxt)
                            .await
                        {
                            Ok(preproc) => preproc,
                            Err(_e) => {
                                tracing::error!(
                                    "Failed to init preprocessing of noise flooding material"
                                );
                                return;
                            }
                        };
                        if let Some(mut entry) = store.get_mut(&session_id) {
                            (*entry).push(preproc);
                        } else {
                            store.insert(session_id, vec![preproc]);
                        }
                    }
                    fill_network_memory_info_single_session(small_session.session.into_inner());
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            DecryptionMode::NoiseFloodLarge => {
                let mut large_session = Large::new(LargeSession::new(base_session));
                let store = self.data.ddec_preproc_store_nf.clone();
                let my_future = || async move {
                    for _ in 0..num_ctxt {
                        match large_session
                            .init_prep_noiseflooding(num_blocks_per_ctxt)
                            .await
                        {
                            Ok(preproc) => {
                                if let Some(mut entry) = store.get_mut(&session_id) {
                                    (*entry).push(preproc);
                                } else {
                                    store.insert(session_id, vec![preproc]);
                                }
                            }
                            Err(_e) => {
                                tracing::error!(
                                    "Failed to init preprocessing of noise flooding material"
                                );
                            }
                        };
                    }

                    fill_network_memory_info_single_session(large_session.session.into_inner());
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

    #[instrument(
        name = "DDEC",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn threshold_decrypt(
        &self,
        request: tonic::Request<ThresholdDecryptRequest>,
    ) -> Result<tonic::Response<ThresholdDecryptResponse>, tonic::Status> {
        #[cfg(feature = "measure_memory")]
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();

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
        let num_ctxts = ctxts.len();

        let throughput = decrypt_params.throughput;

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

        let res_store = self.data.ddec_result_store.clone();
        //Good enough for benchmarking purposes
        let mut session_id_generator = AesRng::seed_from_u64(session_id.0 as u64);
        //This is throughput testing
        if let Some(throughput) = throughput {
            let num_sessions = throughput.num_sessions;
            let num_copies = throughput.num_copies;
            let chunk_size = num_copies.div_ceil(num_sessions);
            let own_identity = self.own_identity.clone();
            let role_assignments = role_assignments.clone();
            let prss_setup = self.data.prss_setup.clone();
            let networking_strategy = self.networking_strategy.clone();
            let sns_key = Arc::new(key_ref.0.sns_key.clone().unwrap());
            let ks = Arc::new(
                key_ref
                    .0
                    .server_key
                    .as_ref()
                    .as_ref()
                    .key_switching_key
                    .clone(),
            );
            let num_blocks = ctxts[0].clone().into_blocks().len();

            //Prepare for bcast
            let bcast_sid = gen_random_sid(&mut session_id_generator, session_id.0);
            let params = SessionParameters::new(
                threshold,
                bcast_sid,
                own_identity.clone(),
                role_assignments.clone(),
            )
            .unwrap();
            let networking =
                (networking_strategy)(bcast_sid, role_assignments.clone(), NetworkMode::Async)
                    .await
                    .unwrap();
            let bcast_session =
                BaseSessionStruct::new(params.clone(), networking, AesRng::from_entropy()).unwrap();

            match decryption_mode {
                DecryptionMode::NoiseFloodSmall => {
                    let ctxts_large = ctxts
                        .iter()
                        .map(|ctxt| sns_key.to_large_ciphertext(ctxt).unwrap())
                        .collect_vec();
                    //Do bcast after the Sns to sync parties
                    let _ = broadcast_from_all(
                        &bcast_session,
                        Some(BroadcastValue::from(Z128::from_u128(42))),
                    )
                    .await;
                    let my_future = || async move {
                        let mut vec_res = Vec::new();
                        let mut vec_base_sessions = Vec::new();
                        for ct_large in ctxts_large.into_iter() {
                            let num_blocks = ct_large.len();

                            // Copy the ctxt
                            let ctxt_chunked = vec![vec![ct_large; chunk_size]; num_sessions];

                            let sids = (0..num_sessions)
                                .map(|_| gen_random_sid(&mut session_id_generator, session_id.0))
                                .collect_vec();

                            // Derive all the prss states (1 per session)
                            let prss_states = sids
                                .iter()
                                .map(|sid| {
                                    prss_setup
                                        .get(&SupportedRing::ResiduePolyZ128)
                                        .ok_or_else(|| {
                                            tonic::Status::new(
                                                tonic::Code::Aborted,
                                                "Failed to retrieve prss_setup, try init it first"
                                                    .to_string(),
                                            )
                                        })
                                        .unwrap()
                                        .get_poly128()
                                        .unwrap()
                                        .new_prss_session_state(*sid)
                                })
                                .collect_vec();

                            // Instantiate required number of base sessions
                            let mut base_sessions = Vec::new();
                            for session_id in sids {
                                let params = SessionParameters::new(
                                    threshold,
                                    session_id,
                                    own_identity.clone(),
                                    role_assignments.clone(),
                                )
                                .unwrap();
                                let networking = (networking_strategy)(
                                    session_id,
                                    role_assignments.clone(),
                                    NetworkMode::Async,
                                )
                                .await
                                .unwrap();
                                base_sessions.push(
                                    BaseSessionStruct::new(
                                        params.clone(),
                                        networking,
                                        AesRng::from_entropy(),
                                    )
                                    .unwrap(),
                                );
                            }

                            // Crate required number of small sessions from base sessions and prss_states
                            let small_sessions = base_sessions
                                .into_iter()
                                .zip(prss_states.into_iter())
                                .map(|(base_session, prss_state)| {
                                    Small::new(
                                        SmallSession::new_from_prss_state(base_session, prss_state)
                                            .unwrap(),
                                    )
                                })
                                .collect_vec();

                            // Spawn a tokio task for each session
                            let mut decryption_tasks = JoinSet::new();
                            for (mut small_session, ctxts) in
                                small_sessions.into_iter().zip(ctxt_chunked.into_iter())
                            {
                                let decrypt_span = tracing::info_span!("Online-NoiseFloodSmall");
                                let key_ref = key_ref.clone();
                                tracing::info!(
                                    "Starting session with id {} to decrypt {} ctxts",
                                    small_session.session.borrow().session_id(),
                                    ctxts.len()
                                );
                                decryption_tasks.spawn(
                                    async move {
                                        let mut noiseflood_preprocessing = small_session
                                            .init_prep_noiseflooding(ctxts.len() * num_blocks)
                                            .await
                                            .unwrap();

                                        let mut base_session =
                                            small_session.session.into_inner().base_session;

                                        let mut res = Vec::new();
                                        for ctxt in ctxts.into_iter() {
                                            res.push(
                                                run_decryption_noiseflood_64(
                                                    &mut base_session,
                                                    noiseflood_preprocessing.as_mut(),
                                                    &key_ref.1,
                                                    ctxt,
                                                )
                                                .await
                                                .unwrap(),
                                            );
                                        }
                                        (res, base_session)
                                    }
                                    .instrument(decrypt_span),
                                );
                            }
                            //Retrieve info from this batch
                            let mut all_res = Vec::new();
                            while let Some(Ok((res, base_session))) =
                                decryption_tasks.join_next().await
                            {
                                vec_base_sessions.push(base_session);
                                all_res.push(res[0]);
                            }
                            vec_res.push(all_res[0]);
                        }
                        res_store.insert(session_id, vec_res);
                        fill_network_memory_info_multiple_sessions(vec_base_sessions);
                    };
                    let throughput_span = tracing::info_span!(
                        "Throughput-NoiseFloodSmall",
                        num_copies = num_copies,
                        num_sessions = num_sessions,
                        network_round = tracing::field::Empty,
                        network_sent = tracing::field::Empty,
                        network_received = tracing::field::Empty,
                        peak_mem = tracing::field::Empty
                    );
                    self.data.status_store.insert(
                        session_id,
                        tokio::spawn(my_future().instrument(throughput_span)),
                    );
                }
                DecryptionMode::BitDecSmall => {
                    //Do bcast to sync parties
                    let _ = broadcast_from_all(
                        &bcast_session,
                        Some(BroadcastValue::from(Z128::from_u128(42))),
                    )
                    .await;
                    let my_future = || async move {
                        let mut vec_res = Vec::new();
                        let mut vec_base_sessions = Vec::new();
                        for ctxt in ctxts.into_iter() {
                            // Copy the ctxt
                            let ctxt_chunked = vec![vec![ctxt; chunk_size]; num_sessions];

                            let sids = (0..num_sessions)
                                .map(|_| gen_random_sid(&mut session_id_generator, session_id.0))
                                .collect_vec();

                            // Derive all the prss states (1 per session)
                            let prss_states = sids
                                .iter()
                                .map(|sid| {
                                    prss_setup
                                        .get(&SupportedRing::ResiduePolyZ64)
                                        .ok_or_else(|| {
                                            tonic::Status::new(
                                                tonic::Code::Aborted,
                                                "Failed to retrieve prss_setup, try init it first"
                                                    .to_string(),
                                            )
                                        })
                                        .unwrap()
                                        .get_poly64()
                                        .unwrap()
                                        .new_prss_session_state(*sid)
                                })
                                .collect_vec();

                            // Instantiate required number of base sessions
                            let mut base_sessions = Vec::new();
                            for session_id in sids {
                                let params = SessionParameters::new(
                                    threshold,
                                    session_id,
                                    own_identity.clone(),
                                    role_assignments.clone(),
                                )
                                .unwrap();
                                let networking = (networking_strategy)(
                                    session_id,
                                    role_assignments.clone(),
                                    NetworkMode::Sync,
                                )
                                .await
                                .unwrap();
                                base_sessions.push(
                                    BaseSessionStruct::new(
                                        params.clone(),
                                        networking,
                                        AesRng::from_entropy(),
                                    )
                                    .unwrap(),
                                );
                            }

                            // Create required number of small sessions from base sessions and prss_states
                            let small_sessions = base_sessions
                                .into_iter()
                                .zip(prss_states.into_iter())
                                .map(|(base_session, prss_state)| {
                                    SmallSession::new_from_prss_state(base_session, prss_state)
                                        .unwrap()
                                })
                                .collect_vec();

                            // Spawn a tokio task for each session
                            let mut decryption_tasks = JoinSet::new();
                            for (mut small_session, ctxts) in
                                small_sessions.into_iter().zip(ctxt_chunked.into_iter())
                            {
                                let key_ref = key_ref.clone();
                                tracing::info!(
                                    "Starting session with id {} to decrypt {} ctxts",
                                    small_session.session_id(),
                                    ctxts.len()
                                );
                                let ks = ks.clone();
                                decryption_tasks.spawn(
                                    async move {
                                        let mut bitdec_preprocessing = init_prep_bitdec_small(
                                            &mut small_session,
                                            ctxts.len() * num_blocks,
                                        )
                                        .await
                                        .unwrap();

                                        let mut base_session = small_session.base_session;

                                        let mut res = Vec::new();
                                        for ctxt in ctxts.into_iter() {
                                            res.push(
                                                run_decryption_bitdec_64(
                                                    &mut base_session,
                                                    bitdec_preprocessing.as_mut(),
                                                    &key_ref.1,
                                                    &ks,
                                                    ctxt,
                                                )
                                                .await
                                                .unwrap(),
                                            );
                                        }
                                        (res, base_session)
                                    }
                                    .instrument(tracing::Span::current()),
                                );
                            }
                            //Retrieve info from this batch
                            let mut all_res = Vec::new();
                            while let Some(Ok((res, base_session))) =
                                decryption_tasks.join_next().await
                            {
                                vec_base_sessions.push(base_session);
                                all_res.push(res[0]);
                            }
                            vec_res.push(all_res[0]);
                        }
                        res_store.insert(session_id, vec_res);
                        fill_network_memory_info_multiple_sessions(vec_base_sessions);
                    };
                    let throughput_span = tracing::info_span!(
                        "Throughput-BitDecSmall",
                        num_copies = num_copies,
                        num_sessions = num_sessions,
                        network_round = tracing::field::Empty,
                        network_sent = tracing::field::Empty,
                        network_received = tracing::field::Empty,
                        peak_mem = tracing::field::Empty
                    );
                    self.data.status_store.insert(
                        session_id,
                        tokio::spawn(my_future().instrument(throughput_span)),
                    );
                }
                _ => todo!("No throughput yet"),
            };

            //This is "regular" testing
        } else {
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
            let networking = (self.networking_strategy)(
                session_id,
                role_assignments.clone(),
                NetworkMode::Async,
            )
            .await
            .unwrap();

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
            match decryption_mode {
                DecryptionMode::BitDecLarge | DecryptionMode::BitDecSmall => {
                    let preprocessings = if let Some(preproc_sid) = preproc_sid {
                        self.data.ddec_preproc_store_bd.remove(&preproc_sid).ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Can not find BitDec preproc that corresponds to session ID {preproc_sid}"),
                        )
                    })?.1
                    } else {
                        (0..num_ctxts)
                            .map(|_| {
                                let my_box: Box<dyn BitDecPreprocessing<EXTENSION_DEGREE>> =
                                    Box::new(DummyPreprocessing::new(
                                        session_id.0 as u64,
                                        base_session.clone(),
                                    ));
                                my_box
                            })
                            .collect_vec()
                    };
                    let mut res = Vec::new();

                    let my_future = || async move {
                        let ks = &key_ref.0.server_key.as_ref().as_ref().key_switching_key;
                        for (ctxt, mut preprocessing) in
                            ctxts.into_iter().zip(preprocessings.into_iter())
                        {
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
                        fill_network_memory_info_single_session(base_session);
                    };
                    self.data.status_store.insert(
                        session_id,
                        tokio::spawn(my_future().instrument(tracing::Span::current())),
                    );
                }
                DecryptionMode::NoiseFloodSmall | DecryptionMode::NoiseFloodLarge => {
                    if key_ref.0.sns_key.is_none() {
                        return Err(tonic::Status::new(tonic::Code::Aborted,format!("Asked for NoiseFlood decrypt but there is no Switch and Squash key for key at session ID {key_sid}")));
                    }
                    let preprocessings = if let Some(preproc_sid) = preproc_sid {
                        self.data.ddec_preproc_store_nf.remove(&preproc_sid).ok_or_else(|| {
                        tonic::Status::new(tonic::Code::Aborted,format!("Can not find NoiseFlood preproc that corresponds to session ID {preproc_sid}"))
                    })?.1
                    } else {
                        (0..num_ctxts)
                            .map(|_| {
                                let my_box: Box<dyn NoiseFloodPreprocessing<EXTENSION_DEGREE>> =
                                    Box::new(DummyPreprocessing::new(
                                        session_id.0 as u64,
                                        base_session.clone(),
                                    ));
                                my_box
                            })
                            .collect_vec()
                    };
                    let my_future = || async move {
                        let mut res = Vec::new();
                        for (ctxt, mut preprocessing) in
                            ctxts.into_iter().zip(preprocessings.into_iter())
                        {
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
                        fill_network_memory_info_single_session(base_session);
                    };
                    self.data.status_store.insert(
                        session_id,
                        tokio::spawn(my_future().instrument(tracing::Span::current())),
                    );
                }
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

    #[instrument(
        name = "CRS-GEN",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn crs_gen(
        &self,
        request: tonic::Request<CrsGenRequest>,
    ) -> Result<tonic::Response<CrsGenResponse>, tonic::Status> {
        #[cfg(feature = "measure_memory")]
        MEM_ALLOCATOR.get().unwrap().reset_peak_usage();

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
            (self.networking_strategy)(session_id, role_assignments, NetworkMode::Sync)
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create networking: {:?}", e),
                    )
                })?;

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
            fill_network_memory_info_single_session(base_session);
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

/// Fill the current span with the following information:
/// - total number of sessions
/// - max number of rounds across all sessions
/// - total number of bytes sent across all sessions
/// - total number of bytes received across all sessions
/// - peak memory usage in bytes as given by the custom allocator
fn fill_network_memory_info_multiple_sessions<R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    sessions: Vec<B>,
) {
    let span = tracing::Span::current();
    // Take the max number of rounds across all sessions
    // (as they ran in parallel the sum isn't really a good measure)
    let num_rounds = sessions.iter().fold(0, |cur_max, sess| {
        cur_max.max(sess.network().get_current_round().unwrap())
    });

    span.record("total_num_sessions", sessions.len());
    span.record("network_round", num_rounds);
    let total_num_byte_sent = sessions
        .iter()
        .map(|sess| {
            if sess.network().get_current_round().unwrap() > 0 {
                sess.network().get_num_byte_sent().unwrap()
            } else {
                0
            }
        })
        .sum::<usize>();

    let total_num_byte_received = sessions
        .iter()
        .map(|sess| {
            if sess.network().get_current_round().unwrap() > 0 {
                sess.network().get_num_byte_received().unwrap()
            } else {
                0
            }
        })
        .sum::<usize>();

    span.record("network_sent", total_num_byte_sent);
    span.record("network_received", total_num_byte_received);

    #[cfg(feature = "measure_memory")]
    span.record("peak_mem", MEM_ALLOCATOR.get().unwrap().peak_usage());
}

fn fill_network_memory_info_single_session<R: Rng + CryptoRng, B: BaseSessionHandles<R>>(
    session: B,
) {
    fill_network_memory_info_multiple_sessions(vec![session]);
}

#[cfg(feature = "testing")]
async fn local_initialize_key_material<const EXTENSION_DEGREE: usize>(
    session: &mut BaseSession,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: crate::algebra::structure_traits::Ring,
    ResiduePoly<Z128, EXTENSION_DEGREE>: crate::algebra::structure_traits::Ring,
{
    let _tracing_subscribe =
        tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::new());
    crate::execution::tfhe_internals::test_feature::initialize_key_material(session, params).await
}

#[cfg(not(feature = "testing"))]
async fn local_initialize_key_material<const EXTENSION_DEGREE: usize>(
    _session: &mut BaseSession,
    _params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)> {
    panic!("Require the testing feature on the moby cluster to perform a local intialization of the keys")
}

/// Fills up the 96 MSBs with randomness and fills the 32 LSBs with the given sid
/// (so it's easier to find "real" sid by looking at bin rep)
pub fn gen_random_sid(rng: &mut AesRng, current_sid: u128) -> SessionId {
    SessionId(
        ((rng.next_u64() as u128) << 64)
            | ((rng.next_u32() as u128) << 32)
            | (current_sid & 0xFFFF_FFFF),
    )
}
