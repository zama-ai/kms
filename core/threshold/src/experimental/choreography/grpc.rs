//! gRPC-based choreography for experimental features

use crate::choreography::grpc::gen::choreography_server::{Choreography, ChoreographyServer};

use crate::choreography::grpc::gen::{
    CrsGenRequest, CrsGenResponse, CrsGenResultRequest, CrsGenResultResponse,
    PreprocDecryptRequest, PreprocDecryptResponse, PreprocKeyGenRequest, PreprocKeyGenResponse,
    PrssInitRequest, PrssInitResponse, StatusCheckRequest, StatusCheckResponse,
    ThresholdDecryptRequest, ThresholdDecryptResponse, ThresholdDecryptResultRequest,
    ThresholdDecryptResultResponse, ThresholdKeyGenRequest, ThresholdKeyGenResponse,
    ThresholdKeyGenResultRequest, ThresholdKeyGenResultResponse,
};
use crate::choreography::grpc::r#gen::{ReshareRequest, ReshareResponse};
use crate::choreography::grpc::{
    create_small_sessions, fill_network_memory_info_multiple_sessions,
    fill_network_memory_info_single_session, gen_random_sid,
};
use crate::choreography::requests::Status;
use crate::execution::online::preprocessing::dummy::DummyPreprocessing;
use crate::execution::online::preprocessing::PreprocessorFactory;
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::ParameterHandles;
use crate::execution::runtime::session::SessionParameters;
use crate::execution::runtime::session::SmallSession;
use crate::execution::runtime::session::{BaseSession, BaseSessionStruct};
use crate::execution::small_execution::prss::{
    DerivePRSSState, PRSSInit, PRSSSetup, RobustSecurePrssInit,
};
use crate::experimental::algebra::levels::{LevelEll, LevelKsw, LevelOne};
use crate::experimental::algebra::ntt::{Const, N65536};
use crate::experimental::bgv::basics::{PrivateBgvKeySet, PublicBgvKeySet, PublicKey};
use crate::experimental::bgv::ddec::noise_flood_decryption;
use crate::experimental::bgv::dkg::bgv_distributed_keygen;
use crate::experimental::bgv::dkg_orchestrator::BGVPreprocessingOrchestrator;
use crate::experimental::bgv::dkg_preproc::InMemoryBGVDkgPreprocessing;
use crate::experimental::bgv::utils::transfer_secret_key;
use crate::experimental::bgv::utils::{gen_key_set, transfer_pub_key};
use crate::experimental::choreography::requests::{PreprocKeyGenParams, ThresholdDecryptParams};
use crate::experimental::constants::INPUT_PARTY_ID;
use crate::experimental::constants::PLAINTEXT_MODULUS;
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::networking::NetworkMode;
use crate::networking::NetworkingStrategy;
use crate::session_id::SessionId;
use aes_prng::AesRng;
use async_trait::async_trait;
use dashmap::DashMap;
use itertools::Itertools;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Duration;
use tracing::{instrument, Instrument};

use super::requests::{
    PrssInitParams, SupportedRing, ThresholdKeyGenParams, ThresholdKeyGenResultParams,
};

#[derive(Clone)]
enum SupportedPRSSSetup {
    LevelOne(PRSSSetup<LevelOne>),
    LevelKsw(PRSSSetup<LevelKsw>),
}

impl SupportedPRSSSetup {
    // This method returns Result<T, tonic::Status> directly rather than using our BoxedStatus wrapper.
    // This is a deliberate design choice for the following reasons:
    // 1. This is a gRPC service method that directly propagates errors to the transport layer
    // 2. Performance optimization - avoiding unnecessary boxing/unboxing of errors
    // 3. Simplicity - maintaining direct compatibility with the tonic gRPC interface
    // The clippy::result_large_err warning is suppressed because this is an API boundary
    // where the error type is dictated by the external interface requirements.
    #[allow(clippy::result_large_err)]
    fn get_levelone(&self) -> Result<PRSSSetup<LevelOne>, tonic::Status> {
        match self {
            SupportedPRSSSetup::LevelOne(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for LevelOne, make sure you init it first",
            )),
        }
    }
    // This method returns Result<T, tonic::Status> directly rather than using our BoxedStatus wrapper.
    // This is a deliberate design choice for the following reasons:
    // 1. This is a gRPC service method that directly propagates errors to the transport layer
    // 2. Performance optimization - avoiding unnecessary boxing/unboxing of errors
    // 3. Simplicity - maintaining direct compatibility with the tonic gRPC interface
    // The clippy::result_large_err warning is suppressed because this is an API boundary
    // where the error type is dictated by the external interface requirements.
    #[allow(clippy::result_large_err)]
    fn get_levelksw(&self) -> Result<PRSSSetup<LevelKsw>, tonic::Status> {
        match self {
            SupportedPRSSSetup::LevelKsw(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for LevelKsw, make sure you init it first",
            )),
        }
    }
}

///Used to store results of decryption
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ComputationOutputs {
    pub outputs: HashMap<String, Vec<u32>>,
    pub elapsed_time: Option<Duration>,
}

type StatusStore = DashMap<SessionId, JoinHandle<()>>;
type DKGPreprocStore = DashMap<SessionId, InMemoryBGVDkgPreprocessing>;
type KeyStore = DashMap<SessionId, Arc<(PublicKey<LevelEll, LevelKsw, N65536>, PrivateBgvKeySet)>>;
type DDecResultStore = DashMap<SessionId, Vec<Vec<u32>>>;

#[derive(Default)]
struct GrpcDataStores {
    prss_setup: Arc<DashMap<SupportedRing, SupportedPRSSSetup>>,
    dkg_preproc_store: Arc<DKGPreprocStore>,
    key_store: Arc<KeyStore>,
    ddec_result_store: Arc<DDecResultStore>,
    status_store: Arc<StatusStore>,
}

pub struct ExperimentalGrpcChoreography {
    own_identity: Identity,
    networking_strategy: NetworkingStrategy,
    data: GrpcDataStores,
}

impl ExperimentalGrpcChoreography {
    pub fn new<const EXTENSION_DEGREE: usize>(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
        //NOTE: Might need the factory when/if we implemented orchestrator with redis for
        //dkg preproc (but we may also decide to always use InMemory preprocessing?)
        //Also, have to put a dummy degree here that's implemented for trait bounds reasons
        //even though it's not used in BGV/BFV implem
        _factory: Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>,
    ) -> Self {
        tracing::debug!("Starting Party with identity: {own_identity}");
        ExperimentalGrpcChoreography {
            own_identity,
            networking_strategy,
            data: GrpcDataStores::default(),
        }
    }

    pub fn into_server(self) -> ChoreographyServer<impl Choreography> {
        ChoreographyServer::new(self)
            .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
            .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
    }

    async fn create_base_session(
        &self,
        request_sid: SessionId,
        threshold: u8,
        role_assignments: HashMap<Role, Identity>,
        network_mode: NetworkMode,
        seed: Option<u64>,
    ) -> anyhow::Result<BaseSessionStruct<AesRng, SessionParameters>> {
        Ok(self
            .create_base_sessions(
                request_sid,
                1,
                threshold,
                role_assignments,
                network_mode,
                seed,
            )
            .await?
            .pop()
            .map_or_else(
                || {
                    Err(tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create session for {:?}", request_sid),
                    ))
                },
                Ok,
            )?)
    }

    async fn create_base_sessions(
        &self,
        request_sid: SessionId,
        num_sessions: usize,
        threshold: u8,
        role_assignments: HashMap<Role, Identity>,
        network_mode: NetworkMode,
        seed: Option<u64>,
    ) -> anyhow::Result<Vec<BaseSessionStruct<AesRng, SessionParameters>>> {
        let sid_u128 = request_sid.into();
        let mut session_id_generator = AesRng::from_seed(request_sid.to_le_bytes());
        let sids = (0..num_sessions)
            .map(|_| gen_random_sid(&mut session_id_generator, sid_u128))
            .collect_vec();

        //Fetch my Role for the role_assignment
        let mut my_role_idx = 0;
        for (role, identity) in role_assignments.iter() {
            if *identity == self.own_identity {
                my_role_idx = role.one_based() as u64;
            }
        }
        let mut base_sessions = Vec::new();
        for (idx, session_id) in sids.into_iter().enumerate() {
            let params = SessionParameters::new(
                threshold,
                session_id,
                self.own_identity.clone(),
                role_assignments.clone(),
            )
            .unwrap();
            //We are executing offline phase, so requires Sync network
            let networking =
                (self.networking_strategy)(session_id, role_assignments.clone(), network_mode)
                    .await
                    .map_err(|e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Failed to create networking: {:?}", e),
                        )
                    })?;
            let aes_rng = if let Some(seed) = seed {
                AesRng::seed_from_u64(seed + my_role_idx + (idx as u64))
            } else {
                AesRng::from_entropy()
            };
            base_sessions.push(
                BaseSessionStruct::new(params.clone(), networking, aes_rng)
                    .expect("Failed to create Base Session"),
            );
        }
        Ok(base_sessions)
    }
}

#[async_trait]
impl Choreography for ExperimentalGrpcChoreography {
    #[instrument(
        name = "PRSS-INIT (BGV)",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn prss_init(
        &self,
        request: tonic::Request<PrssInitRequest>,
    ) -> Result<tonic::Response<PrssInitResponse>, tonic::Status> {
        let request = request.into_inner();

        //Useless for now, need to integrate large threshold decrypt to grpc
        let threshold: u8 = request.threshold.try_into().map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "Threshold must be at most 255".to_string(),
            )
        })?;

        let role_assignments: HashMap<Role, Identity> =
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let prss_params: PrssInitParams = bc2wrap::deserialize(&request.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse prss params: {:?}", e),
            )
        })?;

        let session_id = prss_params.session_id;
        let ring = prss_params.ring;

        let mut base_session = self
            .create_base_session(
                session_id,
                threshold,
                role_assignments.clone(),
                NetworkMode::Sync,
                request.seed,
            )
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to create Base Session: {:?}", e),
                )
            })?;

        let store = self.data.prss_setup.clone();
        match ring {
            SupportedRing::LevelOne => {
                let my_future = || async move {
                    let prss_setup = RobustSecurePrssInit::default()
                        .init(&mut base_session)
                        .await
                        .unwrap();
                    store.insert(
                        SupportedRing::LevelOne,
                        SupportedPRSSSetup::LevelOne(prss_setup),
                    );
                    tracing::info!("PRSS Setup for LevelOne Done.");
                    fill_network_memory_info_single_session(base_session);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            SupportedRing::LevelKsw => {
                let my_future = || async move {
                    let prss_setup = RobustSecurePrssInit::default()
                        .init(&mut base_session)
                        .await
                        .unwrap();
                    store.insert(
                        SupportedRing::LevelKsw,
                        SupportedPRSSSetup::LevelKsw(prss_setup),
                    );
                    tracing::info!("PRSS Setup for LevelKsw Done.");
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

    #[instrument(
        name = "DKG-PREPROC (BGV)",
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let preproc_params: PreprocKeyGenParams =
            bc2wrap::deserialize(&request.params).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Preproc KeyGen params: {:?}", e),
                )
            })?;

        let session_id = preproc_params.session_id;
        let start_sid = preproc_params.session_id;
        let num_sessions = preproc_params.num_sessions;

        let base_sessions = self
            .create_base_sessions(
                start_sid,
                num_sessions as usize,
                threshold,
                role_assignments.clone(),
                NetworkMode::Sync,
                request.seed,
            )
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to create Base Session: {:?}", e),
                )
            })?;

        let prss_setup = self
            .data
            .prss_setup
            .get(&SupportedRing::LevelKsw)
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "Failed to retrieve prss_setup, try init it first".to_string(),
                )
            })?
            .get_levelksw()?;

        let store = self.data.dkg_preproc_store.clone();
        let my_future = || async move {
            let small_sessions = create_small_sessions(base_sessions, &prss_setup);

            let small_sessions = small_sessions
                .into_iter()
                .map(|s| s.to_secure_small_session())
                .collect();

            let orchestrator = BGVPreprocessingOrchestrator::new(N65536::VALUE);

            let (sessions, preproc) = orchestrator
                .orchestrate_small_session_bgv_dkg_preprocessing(small_sessions)
                .instrument(tracing::info_span!("orchestrate"))
                .await
                .unwrap();
            fill_network_memory_info_multiple_sessions(sessions);
            store.insert(start_sid, preproc);
        };
        self.data.status_store.insert(
            session_id,
            tokio::spawn(my_future().instrument(tracing::Span::current())),
        );

        let sid_serialized = bc2wrap::serialize(&session_id).map_err(|e| {
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
        name = "DKG (BGV)",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let kg_params: ThresholdKeyGenParams =
            bc2wrap::deserialize(&request.params).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Threshold KeyGen params: {:?}", e),
                )
            })?;

        let session_id = kg_params.session_id;
        let preproc_sid = kg_params.session_id_preproc;

        let mut base_session = self
            .create_base_session(
                session_id,
                threshold,
                role_assignments.clone(),
                NetworkMode::Async,
                request.seed,
            )
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to create Base Session: {:?}", e),
                )
            })?;

        let key_store = self.data.key_store.clone();
        if let Some(preproc_sid) = preproc_sid {
            let (_,mut preproc) = self.data.dkg_preproc_store.remove(&preproc_sid).ok_or_else(||{
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to retrieve preprocessing for id {preproc_sid}, make sure to call preprocessing first"),
                )
            })?;
            let my_future = || async move {
                let keys = bgv_distributed_keygen::<N65536, _, _, _>(
                    &mut base_session,
                    &mut preproc,
                    PLAINTEXT_MODULUS.get().0,
                )
                .await
                .unwrap();
                key_store.insert(session_id, Arc::new(keys));
                fill_network_memory_info_single_session(base_session);
            };
            self.data.status_store.insert(
                session_id,
                tokio::spawn(my_future().instrument(tracing::Span::current())),
            );
        } else {
            let prss_state = self
                .data
                .prss_setup
                .get(&SupportedRing::LevelKsw)
                .ok_or_else(|| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        "Failed to retrieve prss_setup, try init it first".to_string(),
                    )
                })?
                .get_levelksw()?
                .new_prss_session_state(session_id);

            let mut small_session =
                SmallSession::new_from_prss_state(base_session, prss_state).unwrap();
            let sid_u128: u128 = session_id.into();
            let mut preproc =
                DummyPreprocessing::<LevelKsw, _, _>::new(sid_u128 as u64, small_session.clone());
            let my_future = || async move {
                let keys = bgv_distributed_keygen::<N65536, _, _, _>(
                    &mut small_session,
                    &mut preproc,
                    PLAINTEXT_MODULUS.get().0,
                )
                .await
                .unwrap();
                key_store.insert(session_id, Arc::new(keys));
                fill_network_memory_info_single_session(small_session);
            };
            self.data.status_store.insert(
                session_id,
                tokio::spawn(my_future().instrument(tracing::Span::current())),
            );
        }

        let sid_serialized = bc2wrap::serialize(&session_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(ThresholdKeyGenResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "DKG-RESULT (BGV)", skip_all)]
    async fn threshold_key_gen_result(
        &self,
        request: tonic::Request<ThresholdKeyGenResultRequest>,
    ) -> Result<tonic::Response<ThresholdKeyGenResultResponse>, tonic::Status> {
        let request = request.into_inner();

        let kg_result_params: ThresholdKeyGenResultParams = bc2wrap::deserialize(&request.params)
            .map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse Threshold KeyGen Result params: {:?}", e),
            )
        })?;

        let session_id = kg_result_params.session_id;
        let gen_params = kg_result_params.gen_params;

        if gen_params {
            let role_assignments: HashMap<Role, Identity> =
                bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
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
            let keys = local_initialize_key_material(&mut base_session)
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
                pub_keyset: bc2wrap::serialize(&keys.0).map_err(|e| {
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
                    pub_keyset: bc2wrap::serialize(&keys.0).map_err(|e| {
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

    async fn preproc_decrypt(
        &self,
        _request: tonic::Request<PreprocDecryptRequest>,
    ) -> Result<tonic::Response<PreprocDecryptResponse>, tonic::Status> {
        unimplemented!("No DDec preproc required for BGV Ddec");
    }

    #[instrument(
        name = "DDEC (BGV)",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let preproc_params: ThresholdDecryptParams = bc2wrap::deserialize(&request.params)
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse preproc params: {:?}", e),
                )
            })?;

        let session_id = preproc_params.session_id;
        let key_sid = preproc_params.key_sid;
        //We receive a Vec<Ctxt>, each ctxt is attributed to a session a copied
        //num_ctxt_per_session time
        //(trick to do throughput bench without having to deal with http max size)
        let vec_ctxts = preproc_params
            .ctxts
            .into_iter()
            .map(|ctxt| vec![ctxt; preproc_params.num_ctxt_per_session])
            .collect_vec();
        let num_parallel = vec_ctxts.len();

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

        let prss_setup = self
            .data
            .prss_setup
            .get(&SupportedRing::LevelOne)
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "Failed to retrieve prss_setup, try init it first".to_string(),
                )
            })?
            .get_levelone()?;

        let base_sessions = self
            .create_base_sessions(
                session_id,
                num_parallel,
                threshold,
                role_assignments.clone(),
                NetworkMode::Async,
                request.seed,
            )
            .await
            .unwrap();
        let mut small_sessions = create_small_sessions(base_sessions, &prss_setup);

        //Sort here, because we sort the result by sid to make sure all parties output same thing
        small_sessions.sort_by_key(|s| s.session_id());
        tracing::info!(
            "Run decryption on {} sessions in parallel",
            small_sessions.len()
        );
        let res_store = self.data.ddec_result_store.clone();
        let my_future = || async move {
            let mut join_set = JoinSet::new();
            for (ctxts, mut session) in vec_ctxts.into_iter().zip(small_sessions.into_iter()) {
                let key_ref = key_ref.clone();
                join_set.spawn(
                    async move {
                        tracing::info!("Inside session, decrypt {} ctxts in sequence", ctxts.len());
                        let mut vec_inner_res = Vec::new();
                        for ctxt in ctxts.into_iter() {
                            vec_inner_res.push(
                                noise_flood_decryption(&mut session, &key_ref.1, &ctxt).await,
                            );
                        }
                        (session, vec_inner_res)
                    }
                    .instrument(tracing::Span::current()),
                );
            }

            let mut small_sessions = Vec::new();
            let mut res = Vec::new();

            while let Some(Ok((session, vec_inner_res))) = join_set.join_next().await {
                let sid = session.session_id();
                small_sessions.push(session);
                for inner_res in vec_inner_res.into_iter() {
                    let inner_res = inner_res
                        .map_err(|e| {
                            tonic::Status::new(
                                tonic::Code::Aborted,
                                format!("Error while running noiseflood ddec {e}"),
                            )
                        })
                        .unwrap();
                    res.push((sid, inner_res));
                }
            }

            res.sort_by_key(|(sid, _)| *sid);
            let res = res.into_iter().map(|(_, r)| r).collect();

            res_store.insert(session_id, res);
            fill_network_memory_info_multiple_sessions(small_sessions);
        };
        self.data.status_store.insert(
            session_id,
            tokio::spawn(my_future().instrument(tracing::Span::current())),
        );

        let sid_serialized = bc2wrap::serialize(&session_id).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(ThresholdDecryptResponse {
            request_id: sid_serialized,
        }))
    }

    #[instrument(name = "DDEC-RESULT (BGV)", skip_all)]
    async fn threshold_decrypt_result(
        &self,
        request: tonic::Request<ThresholdDecryptResultRequest>,
    ) -> Result<tonic::Response<ThresholdDecryptResultResponse>, tonic::Status> {
        let request = request.into_inner();
        let session_id = bc2wrap::deserialize(&request.request_id).map_err(|e| {
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

        let res_serialized = bc2wrap::serialize(&res).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing answer {e}"),
            )
        })?;

        Ok(tonic::Response::new(ThresholdDecryptResultResponse {
            plaintext: res_serialized,
        }))
    }

    async fn status_check(
        &self,
        request: tonic::Request<StatusCheckRequest>,
    ) -> Result<tonic::Response<StatusCheckResponse>, tonic::Status> {
        let request = request.into_inner();
        let sid: SessionId = bc2wrap::deserialize(&request.request_id).map_err(|e| {
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

        let status_serialized = bc2wrap::serialize(&status).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing answer {e}"),
            )
        })?;

        Ok(tonic::Response::new(StatusCheckResponse {
            status: status_serialized,
        }))
    }

    async fn crs_gen(
        &self,
        _request: tonic::Request<CrsGenRequest>,
    ) -> Result<tonic::Response<CrsGenResponse>, tonic::Status> {
        unimplemented!("BGV Does not have a CRS generation")
    }

    async fn crs_gen_result(
        &self,
        _request: tonic::Request<CrsGenResultRequest>,
    ) -> Result<tonic::Response<CrsGenResultResponse>, tonic::Status> {
        unimplemented!("BGV Does not have a CRS generation")
    }

    #[instrument(
        name = "Reshare (BGV)",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn reshare(
        &self,
        _request: tonic::Request<ReshareRequest>,
    ) -> Result<tonic::Response<ReshareResponse>, tonic::Status> {
        todo!("BGV reshare not implemented yet, need syndrome decode first")
    }
}

async fn local_initialize_key_material(
    session: &mut BaseSession,
) -> anyhow::Result<(PublicBgvKeySet, PrivateBgvKeySet)> {
    let own_role = session.my_role()?;
    let keyset = if own_role.one_based() == INPUT_PARTY_ID {
        tracing::info!("Keyset generated by input party {}", own_role);
        Some(gen_key_set())
    } else {
        None
    };
    let passed_pk = transfer_pub_key(
        session,
        keyset.clone().map(|ks| ks.0),
        &own_role,
        INPUT_PARTY_ID,
    )
    .await?;

    let sk = transfer_secret_key(session, keyset.map(|ks| ks.1), &own_role, INPUT_PARTY_ID).await?;
    Ok((passed_pk, sk))
}
