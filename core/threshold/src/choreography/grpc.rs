//! gRPC-based choreography.

pub mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_choreography");
}

use self::gen::choreography_server::{Choreography, ChoreographyServer};
use self::gen::{
    CrsGenResultRequest, CrsGenResultResponse, PreprocDecryptRequest, PreprocDecryptResponse,
    PreprocKeyGenRequest, PreprocKeyGenResponse, PrssInitRequest, PrssInitResponse, ReshareRequest,
    ReshareResponse, StatusCheckRequest, StatusCheckResponse, ThresholdDecryptRequest,
    ThresholdDecryptResponse, ThresholdDecryptResultRequest, ThresholdDecryptResultResponse,
    ThresholdKeyGenRequest, ThresholdKeyGenResponse, ThresholdKeyGenResultRequest,
    ThresholdKeyGenResultResponse,
};

use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{Derive, ErrorCorrect, FromU128, Invert, Solve, Syndrome};
#[cfg(feature = "measure_memory")]
use crate::allocator::MEM_ALLOCATOR;
use crate::choreography::requests::{
    CrsGenParams, PreprocDecryptParams, PreprocKeyGenParams, PrssInitParams, ReshareParams,
    SessionType, Status, ThresholdDecryptParams, ThresholdKeyGenParams,
    ThresholdKeyGenResultParams,
};
use crate::execution::communication::broadcast::{Broadcast, SyncReliableBroadcast};
use crate::execution::endpoints::decryption::{
    combine_plaintext_blocks, init_prep_bitdec, run_decryption_noiseflood_64,
    task_decryption_bitdec_par, BlocksPartialDecrypt, DecryptionMode, NoiseFloodPreparation,
    RadixOrBoolCiphertext, SnsRadixOrBoolCiphertext,
};
use crate::execution::endpoints::decryption::{NoiseFloodLargeSession, NoiseFloodSmallSession};
use crate::execution::endpoints::keygen::FhePubKeySet;
use crate::execution::endpoints::keygen::{
    distributed_keygen_z128, distributed_keygen_z64, PrivateKeySet,
};
use crate::execution::keyset_config::KeySetConfig;
use crate::execution::large_execution::offline::SecureLargePreprocessing;
use crate::execution::online::preprocessing::dummy::DummyPreprocessing;
use crate::execution::online::preprocessing::memory::noiseflood::InMemoryNoiseFloodPreprocessing;
use crate::execution::online::preprocessing::orchestration::dkg_orchestrator::PreprocessingOrchestrator;
use crate::execution::online::preprocessing::orchestration::producers::bits_producer::GenericBitProducer;
use crate::execution::online::preprocessing::orchestration::producers::randoms_producer::GenericRandomProducer;
use crate::execution::online::preprocessing::orchestration::producers::triples_producer::GenericTripleProducer;
use crate::execution::online::preprocessing::{
    BitDecPreprocessing, DKGPreprocessing, InMemoryBitDecPreprocessing, NoiseFloodPreprocessing,
    PreprocessorFactory,
};
use crate::execution::online::reshare::{reshare_sk_same_sets, ResharePreprocRequired};
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::ParameterHandles;
use crate::execution::runtime::session::ToBaseSession;
use crate::execution::runtime::session::{BaseSession, BaseSessionHandles};
use crate::execution::runtime::session::{LargeSession, SessionParameters};
use crate::execution::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
use crate::execution::small_execution::prf::PRSSConversions;
use crate::execution::small_execution::prss::{DerivePRSSState, PRSSPrimitives};
use crate::execution::tfhe_internals::parameters::{AugmentedCiphertextParameters, DKGParams};
use crate::execution::zk::ceremony::{Ceremony, InternalPublicParameter, SecureCeremony};
use crate::malicious_execution::runtime::malicious_session::GenericSmallSessionStruct;
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::networking::value::BroadcastValue;
use crate::networking::{NetworkMode, NetworkingStrategy};
use crate::{execution::small_execution::prss::PRSSInit, session_id::SessionId};
use aes_prng::AesRng;
use async_trait::async_trait;
use clap::ValueEnum;
use dashmap::DashMap;
use gen::{CrsGenRequest, CrsGenResponse};
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::Wrapping;
use std::sync::{Arc, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{instrument, Instrument};

#[derive(Clone, PartialEq, Eq, Hash, Debug, ValueEnum, Serialize, Deserialize)]
pub enum SupportedRing {
    ResiduePolyZ64,
    ResiduePolyZ128,
}

#[derive(Clone)]
enum SupportedPRSSSetup<PRSSSetupTypeZ64: Clone, PRSSSetupTypeZ128: Clone> {
    //NOTE: For now we never deal with ResiduePolyF8Z64 option
    ResiduePolyZ64(PRSSSetupTypeZ64),
    ResiduePolyZ128(PRSSSetupTypeZ128),
}

impl<PRSSSetupTypeZ64: Clone, PRSSSetupTypeZ128: Clone>
    SupportedPRSSSetup<PRSSSetupTypeZ64, PRSSSetupTypeZ128>
{
    // This method returns Result<T, tonic::Status> directly rather than using our BoxedStatus wrapper.
    // This is a deliberate design choice for the following reasons:
    // 1. This is a gRPC service method that directly propagates errors to the transport layer
    // 2. Performance optimization - avoiding unnecessary boxing/unboxing of errors
    // 3. Simplicity - maintaining direct compatibility with the tonic gRPC interface
    // The clippy::result_large_err warning is suppressed because this is an API boundary
    // where the error type is dictated by the external interface requirements.
    #[allow(clippy::result_large_err)]
    fn get_poly64(&self) -> Result<PRSSSetupTypeZ64, tonic::Status> {
        match self {
            SupportedPRSSSetup::ResiduePolyZ64(res) => Ok(res.clone()),
            _ => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "Can not retrieve PRSS init for poly64, make sure you init it first",
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
    fn get_poly128(&self) -> Result<PRSSSetupTypeZ128, tonic::Status> {
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
    DashMap<SessionId, Vec<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>>>;
type DDecPreprocBitDecStore<const EXTENSION_DEGREE: usize> =
    DashMap<SessionId, Vec<Vec<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>>>>;
type DDecResultStore = DashMap<SessionId, Vec<Z64>>;
type CrsStore = DashMap<SessionId, InternalPublicParameter>;
type StatusStore = DashMap<SessionId, JoinHandle<()>>;
type PRSSStore<PRSSSetupTypeZ64, PRSSSetupTypeZ128> =
    DashMap<SupportedRing, SupportedPRSSSetup<PRSSSetupTypeZ64, PRSSSetupTypeZ128>>;

struct GrpcDataStores<
    const EXTENSION_DEGREE: usize,
    PRSSSetupTypeZ64: Clone,
    PRSSSetupTypeZ128: Clone,
> {
    prss_setup: Arc<PRSSStore<PRSSSetupTypeZ64, PRSSSetupTypeZ128>>,
    dkg_preproc_store_regular: Arc<DKGPreprocRegularStore<EXTENSION_DEGREE>>,
    dkg_preproc_store_sns: Arc<DKGPreprocSnsStore<EXTENSION_DEGREE>>,
    key_store: Arc<KeyStore<EXTENSION_DEGREE>>,
    ddec_preproc_store_nf: Arc<DDecPreprocNFStore<EXTENSION_DEGREE>>,
    ddec_preproc_store_bd: Arc<DDecPreprocBitDecStore<EXTENSION_DEGREE>>,
    ddec_result_store: Arc<DDecResultStore>,
    crs_store: Arc<CrsStore>,
    status_store: Arc<StatusStore>,
}

impl<const EXTENSION_DEGREE: usize, PRSSSetupTypeZ64: Clone, PRSSSetupTypeZ128: Clone> Default
    for GrpcDataStores<EXTENSION_DEGREE, PRSSSetupTypeZ64, PRSSSetupTypeZ128>
{
    fn default() -> Self {
        Self {
            prss_setup: Arc::new(DashMap::new()),
            dkg_preproc_store_regular: Arc::new(DashMap::new()),
            dkg_preproc_store_sns: Arc::new(DashMap::new()),
            key_store: Arc::new(DashMap::new()),
            ddec_preproc_store_nf: Arc::new(DashMap::new()),
            ddec_preproc_store_bd: Arc::new(DashMap::new()),
            ddec_result_store: Arc::new(DashMap::new()),
            crs_store: Arc::new(DashMap::new()),
            status_store: Arc::new(DashMap::new()),
        }
    }
}

// Type aliases for complex associated types
type PRSSInitOutput64<P, const EXTENSION_DEGREE: usize> =
    <P as PRSSInit<ResiduePoly<Z64, EXTENSION_DEGREE>>>::OutputType;

type PRSSInitOutput128<P, const EXTENSION_DEGREE: usize> =
    <P as PRSSInit<ResiduePoly<Z128, EXTENSION_DEGREE>>>::OutputType;

type PRSSState64<P, const EXTENSION_DEGREE: usize> =
    <PRSSInitOutput64<P, EXTENSION_DEGREE> as DerivePRSSState<
        ResiduePoly<Z64, EXTENSION_DEGREE>,
    >>::OutputType;

type PRSSState128<P, const EXTENSION_DEGREE: usize> =
    <PRSSInitOutput128<P, EXTENSION_DEGREE> as DerivePRSSState<
        ResiduePoly<Z128, EXTENSION_DEGREE>,
    >>::OutputType;

type GenericSmallSessionZ64<P, const EXTENSION_DEGREE: usize> =
    GenericSmallSessionStruct<ResiduePoly<Z64, EXTENSION_DEGREE>, P>;

type GenericSmallSessionZ128<P, const EXTENSION_DEGREE: usize> =
    GenericSmallSessionStruct<ResiduePoly<Z128, EXTENSION_DEGREE>, P>;

pub struct GrpcChoreography<
    const EXTENSION_DEGREE: usize,
    PRSSInitStrategy: Default,
    SmallOfflineStrategy: Default,
    LargeOfflineStrategyZ64: Default,
    LargeOfflineStrategyZ128: Default,
> where
    PRSSInitStrategy: PRSSInit<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    PRSSInitStrategy: PRSSInit<ResiduePoly<Z128, EXTENSION_DEGREE>>,
{
    own_identity: Identity,
    networking_strategy: Arc<NetworkingStrategy>,
    factory: Arc<Mutex<Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>>>,
    data: GrpcDataStores<
        EXTENSION_DEGREE,
        <PRSSInitStrategy as PRSSInit<ResiduePoly<Z64, EXTENSION_DEGREE>>>::OutputType,
        <PRSSInitStrategy as PRSSInit<ResiduePoly<Z128, EXTENSION_DEGREE>>>::OutputType,
    >,
    _marker_prss_strat: std::marker::PhantomData<PRSSInitStrategy>,
    _marker_small_offline_strat: std::marker::PhantomData<SmallOfflineStrategy>,
    _marker_large_offline_z64_strat: std::marker::PhantomData<LargeOfflineStrategyZ64>,
    _marker_large_offline_z128_strat: std::marker::PhantomData<LargeOfflineStrategyZ128>,
}

impl<
        const EXTENSION_DEGREE: usize,
        PRSSInitStrategy: Default + 'static,
        SmallOfflineStrategy: Default + 'static,
        LargeOfflineStrategyZ64: Default + 'static,
        LargeOfflineStrategyZ128: Default + 'static,
    >
    GrpcChoreography<
        EXTENSION_DEGREE,
        PRSSInitStrategy,
        SmallOfflineStrategy,
        LargeOfflineStrategyZ64,
        LargeOfflineStrategyZ128,
    >
where
    // Ring requirements for both Z64 and Z128 polynomials
    ResiduePoly<Z64, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,

    // PRSS initialization and state derivation
    PRSSInitStrategy: PRSSInit<ResiduePoly<Z64, EXTENSION_DEGREE>>
        + PRSSInit<ResiduePoly<Z128, EXTENSION_DEGREE>>,

    PRSSState64<PRSSInitStrategy, EXTENSION_DEGREE>:
        PRSSPrimitives<ResiduePoly<Z64, EXTENSION_DEGREE>> + Clone,

    PRSSState128<PRSSInitStrategy, EXTENSION_DEGREE>:
        PRSSPrimitives<ResiduePoly<Z128, EXTENSION_DEGREE>> + Clone,

    // Preprocessing strategies
    SmallOfflineStrategy: Preprocessing<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            GenericSmallSessionZ64<
                PRSSState64<PRSSInitStrategy, EXTENSION_DEGREE>,
                EXTENSION_DEGREE,
            >,
        > + Preprocessing<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            GenericSmallSessionZ128<
                PRSSState128<PRSSInitStrategy, EXTENSION_DEGREE>,
                EXTENSION_DEGREE,
            >,
        >,
    LargeOfflineStrategyZ64: Preprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>, LargeSession>,
    LargeOfflineStrategyZ128: Preprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>, LargeSession>,
{
    pub fn new(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
        factory: Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>,
    ) -> Self {
        tracing::debug!("Starting Party with identity: {own_identity}");
        println!("{}", Self::describe_self());
        GrpcChoreography {
            own_identity,
            networking_strategy: Arc::new(networking_strategy),
            factory: Arc::new(Mutex::new(factory)),
            data: GrpcDataStores::default(),
            _marker_prss_strat: std::marker::PhantomData,
            _marker_small_offline_strat: std::marker::PhantomData,
            _marker_large_offline_z64_strat: std::marker::PhantomData,
            _marker_large_offline_z128_strat: std::marker::PhantomData,
        }
    }

    pub fn describe_self() -> String {
        // Get all protocol descriptions
        let prss_desc = PRSSInitStrategy::protocol_desc(1);
        let small_desc = SmallOfflineStrategy::protocol_desc(1);
        let large_z64_desc = LargeOfflineStrategyZ64::protocol_desc(1);
        let large_z128_desc = LargeOfflineStrategyZ128::protocol_desc(1);

        // Calculate the maximum width needed
        let header = "GRPC CHOREOGRAPHY PROTOCOL DESCRIPTIONS";
        let section_headers = [
            "PRSSInit:",
            "SmallOffline:",
            "LargeOfflineZ64:",
            "LargeOfflineZ128:",
        ];

        // Find max line width across ALL content (including headers and section titles)
        let max_desc_width = [&prss_desc, &small_desc, &large_z64_desc, &large_z128_desc]
            .iter()
            .flat_map(|desc| desc.lines())
            .map(|line| line.len())
            .max()
            .unwrap_or(0);

        let max_header_width = section_headers.iter().map(|h| h.len()).max().unwrap_or(0);
        let main_header_width = header.len();

        // Calculate the CONTENT width (what goes between the | |)
        let content_width = max_desc_width.max(max_header_width).max(main_header_width);

        // Helper function to format content lines with consistent width
        let format_section = |title: &str, content: &str| {
            let mut result = String::new();
            result.push_str(&format!("│ {:^width$} │\n", title, width = content_width));

            for line in content.lines() {
                result.push_str(&format!("│ {:<width$} │\n", line, width = content_width));
            }
            result
        };

        // Build the table
        let line = '─'.to_string().repeat(content_width + 2).to_string();
        format!(
            "┌{}┐\n│ {:^width$} │\n├{}┤\n{}├{}┤\n{}├{}┤\n{}├{}┤\n{}└{}┘",
            &line,
            header,
            &line,
            format_section("PRSSInit:", &prss_desc),
            &line,
            format_section("SmallOffline:", &small_desc),
            &line,
            format_section("LargeOfflineZ64:", &large_z64_desc),
            &line,
            format_section("LargeOfflineZ128:", &large_z128_desc),
            &line,
            width = content_width
        )
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
    ) -> anyhow::Result<BaseSession> {
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
    ) -> anyhow::Result<Vec<BaseSession>> {
        let mut session_id_generator = AesRng::from_seed(request_sid.to_le_bytes());
        let sids = (0..num_sessions)
            .map(|_| gen_random_sid(&mut session_id_generator, request_sid.into()))
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
                BaseSession::new(params.clone(), networking, aes_rng)
                    .expect("Failed to create Base Session"),
            );
        }
        Ok(base_sessions)
    }
}

#[async_trait]
impl<
        const EXTENSION_DEGREE: usize,
        PRSSInitStrategy: Default + 'static,
        SmallOfflineStrategy: Default + 'static,
        LargeOfflineStrategyZ64: Default + 'static,
        LargeOfflineStrategyZ128: Default + 'static,
    > Choreography
    for GrpcChoreography<
        EXTENSION_DEGREE,
        PRSSInitStrategy,
        SmallOfflineStrategy,
        LargeOfflineStrategyZ64,
        LargeOfflineStrategyZ128,
    >
where
    // Ring requirements for both Z64 and Z128 polynomials
    ResiduePoly<Z64, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,

    // PRSS initialization and state derivation
    PRSSInitStrategy: PRSSInit<ResiduePoly<Z64, EXTENSION_DEGREE>>
        + PRSSInit<ResiduePoly<Z128, EXTENSION_DEGREE>>,

    PRSSState64<PRSSInitStrategy, EXTENSION_DEGREE>:
        PRSSPrimitives<ResiduePoly<Z64, EXTENSION_DEGREE>> + Clone,

    PRSSState128<PRSSInitStrategy, EXTENSION_DEGREE>:
        PRSSPrimitives<ResiduePoly<Z128, EXTENSION_DEGREE>> + Clone,

    // Preprocessing strategies
    SmallOfflineStrategy: Preprocessing<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            GenericSmallSessionZ64<
                PRSSState64<PRSSInitStrategy, EXTENSION_DEGREE>,
                EXTENSION_DEGREE,
            >,
        > + Preprocessing<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            GenericSmallSessionZ128<
                PRSSState128<PRSSInitStrategy, EXTENSION_DEGREE>,
                EXTENSION_DEGREE,
            >,
        >,
    LargeOfflineStrategyZ64: Preprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>, LargeSession>,
    LargeOfflineStrategyZ128: Preprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>, LargeSession>,
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
            SupportedRing::ResiduePolyZ128 => {
                let my_future = || async move {
                    let prss_setup = PRSSInit::<ResiduePoly<Z128, EXTENSION_DEGREE>>::init(
                        &PRSSInitStrategy::default(),
                        &mut base_session,
                    )
                    .await;

                    let prss_setup = match prss_setup {
                        Ok(prss_setup) => prss_setup,
                        Err(prss_setup) => {
                            panic!(
                                "Failed to initialize PRSS for ResiduePolyZ128: {:?}",
                                prss_setup
                            );
                        }
                    };

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
                    let prss_setup = PRSSInit::<ResiduePoly<Z64, EXTENSION_DEGREE>>::init(
                        &PRSSInitStrategy::default(),
                        &mut base_session,
                    )
                    .await;

                    let prss_setup = match prss_setup {
                        Ok(prss_setup) => prss_setup,
                        Err(prss_setup) => {
                            panic!(
                                "Failed to initialize PRSS for ResiduePolyZ64: {:?}",
                                prss_setup
                            );
                        }
                    };

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

        let start_sid = preproc_params.session_id;
        let num_sessions = preproc_params.num_sessions;
        let percentage_offline = preproc_params.percentage_offline as usize;
        let dkg_params = preproc_params.dkg_params;
        let session_type = preproc_params.session_type;

        let factory = self.factory.clone();

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
                        orchestrator
                            .orchestrate_dkg_processing::<_, GenericTripleProducer<
                                _,
                                _,
                                SmallOfflineStrategy,
                            >, GenericRandomProducer<
                                _,
                                _,
                                SmallOfflineStrategy,
                            >, GenericBitProducer<
                                _,
                                _,
                                SmallOfflineStrategy,
                            >>(sessions)
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
                        orchestrator
                            .orchestrate_dkg_processing::<_, GenericTripleProducer<
                                _,
                                _,
                                LargeOfflineStrategyZ64,
                            >, GenericRandomProducer<
                                _,
                                _,
                                LargeOfflineStrategyZ64,
                            >, GenericBitProducer<
                                _,
                                _,
                                LargeOfflineStrategyZ64,
                            >>(sessions)
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
                            .orchestrate_dkg_processing::<_, GenericTripleProducer<
                                _,
                                _,
                                SmallOfflineStrategy,
                            >, GenericRandomProducer<
                                _,
                                _,
                                SmallOfflineStrategy,
                            >, GenericBitProducer<
                                _,
                                _,
                                SmallOfflineStrategy,
                            >>(sessions)
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
                            .orchestrate_dkg_processing::<_, GenericTripleProducer<
                                _,
                                _,
                                LargeOfflineStrategyZ128,
                            >, GenericRandomProducer<
                                _,
                                _,
                                LargeOfflineStrategyZ128,
                            >, GenericBitProducer<
                                _,
                                _,
                                LargeOfflineStrategyZ128,
                            >>(sessions)
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
        let sid_serialized = bc2wrap::serialize(&start_sid).map_err(|e| {
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
        let dkg_params = kg_params.dkg_params;
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
                let sid_u128: u128 = session_id.into();
                let mut preproc = DummyPreprocessing::new(sid_u128 as u64, &base_session);
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
                let sid_u128: u128 = session_id.into();
                let mut preproc = DummyPreprocessing::new(sid_u128 as u64, &base_session);
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

    #[instrument(name = "DKG-RESULT", skip_all)]
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
        let dkg_params = kg_result_params.dkg_params;

        if let Some(dkg_params) = dkg_params {
            let role_assignments: HashMap<Role, Identity> =
                bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to parse role assignment: {:?}", e),
                    )
                })?;

            let mut base_session = self
                .create_base_session(
                    session_id,
                    0,
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let preproc_params: PreprocDecryptParams =
            bc2wrap::deserialize(&request.params).map_err(|e| {
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

        match decryption_mode {
            //For BitDec we do parallelisation by spawning one session per "raw" ctxt
            DecryptionMode::BitDecLarge => {
                let num_sessions = num_blocks_per_ctxt;
                let base_sessions = self
                    .create_base_sessions(
                        session_id,
                        num_sessions,
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
                let large_sessions = create_large_sessions(base_sessions);

                let store = self.data.ddec_preproc_store_bd.clone();
                let my_future = || async move {
                    let mut tasks = JoinSet::new();
                    for (session_num, mut large_session) in large_sessions.into_iter().enumerate() {
                        tasks.spawn(
                            async move {
                                let mut res = Vec::new();
                                for _ in 0..num_ctxt {
                                    //We need to generate preprocessing for one block as we parallelised it
                                    match init_prep_bitdec::<EXTENSION_DEGREE,_,LargeOfflineStrategyZ64>(&mut large_session, 1).await {
                                        Ok(preproc) => res.push(preproc),
                                        Err(_e) => {
                                            tracing::error!(
                                                "Failed to init preprocessing of noise flooding material"
                                            );
                                        }
                                    };
                                }
                                (res, session_num, large_session)
                            }
                            .instrument(tracing::Span::current()),
                        );
                    }

                    //Join on all those tasks
                    let mut preprocessings = Vec::new();
                    let mut sessions = Vec::new();
                    while let Some(Ok((res, session_num, large_session))) = tasks.join_next().await
                    {
                        preprocessings.push((session_num, res));
                        sessions.push(large_session);
                    }

                    // At this points preprocessings is a Vec of Vec of preprocessings
                    // such that preprocessings[i][j] is the preprocessing to decrypt the ith block
                    // of the jth "extended" Ctxt (FheType)
                    //Push the preprocessing to the store sorted by block
                    preprocessings.sort_by_key(|p| p.0);
                    let preprocessings = preprocessings.into_iter().map(|p| p.1).collect_vec();
                    let _ = store.insert(session_id, preprocessings);

                    fill_network_memory_info_multiple_sessions(sessions);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            //For BitDec we do parallelisation by spawning one session per ctxt
            DecryptionMode::BitDecSmall => {
                let num_sessions = num_blocks_per_ctxt;
                let base_sessions = self
                    .create_base_sessions(
                        session_id,
                        num_sessions,
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
                    .get(&SupportedRing::ResiduePolyZ64)
                    .ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            "Failed to retrieve prss_setup, try init it first".to_string(),
                        )
                    })?
                    .get_poly64()?;
                let small_sessions = create_small_sessions(base_sessions, &prss_setup);
                let store = self.data.ddec_preproc_store_bd.clone();
                let my_future = || async move {
                    let mut tasks = JoinSet::new();
                    for (session_num, mut small_session) in small_sessions.into_iter().enumerate() {
                        tasks.spawn(
                            async move {
                                let mut res = Vec::new();
                                for _ in 0..num_ctxt {
                                    match init_prep_bitdec::<EXTENSION_DEGREE,_,SmallOfflineStrategy>(
                                        &mut small_session,
                                        1, //We need to generate preprocessing for one block as we parallelised it
                                    )
                                    .await
                                    {
                                        Ok(preproc) => res.push(preproc),
                                        Err(_e) => {
                                            tracing::error!(
                                                "Failed to init preprocessing of noise flooding material"
                                            );
                                        }
                                    };
                                }
                                (res, session_num, small_session)
                            }
                            .instrument(tracing::Span::current()),
                        );
                    }

                    //Join on all those tasks
                    let mut preprocessings = Vec::new();
                    let mut sessions = Vec::new();
                    while let Some(Ok((res, session_num, small_session))) = tasks.join_next().await
                    {
                        preprocessings.push((session_num, res));
                        sessions.push(small_session);
                    }

                    // At this points preprocessings is a Vec of Vec of preprocessings
                    // such that preprocessings[i][j] is the preprocessing to decrypt the ith block
                    // of the jth "extended" Ctxt (FheType)
                    //Push the preprocessing to the store sorted by block
                    preprocessings.sort_by_key(|p| p.0);
                    let preprocessings = preprocessings.into_iter().map(|p| p.1).collect_vec();
                    let _ = store.insert(session_id, preprocessings);

                    fill_network_memory_info_multiple_sessions(sessions);
                };
                self.data.status_store.insert(
                    session_id,
                    tokio::spawn(my_future().instrument(tracing::Span::current())),
                );
            }
            // NoiseFlood Preproc is so tiny that we just do everything in one go
            DecryptionMode::NoiseFloodSmall => {
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
                let base_session = self
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
                let mut small_session =
                    NoiseFloodSmallSession::new(create_small_session(base_session, &prss_setup));
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
            // NoiseFlood Preproc is so tiny that we just do everything in one go
            DecryptionMode::NoiseFloodLarge => {
                let base_session = self
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
                let mut large_session = NoiseFloodLargeSession::<LargeOfflineStrategyZ128>::new(
                    create_large_session(base_session),
                );
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

        let sid_serialized = bc2wrap::serialize(&session_id).map_err(|e| {
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let decrypt_params: ThresholdDecryptParams = bc2wrap::deserialize(&request.params)
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse Threshold Decrypt params: {:?}", e),
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
                    format!("Can not find key that corresponds to session ID {key_sid}"),
                )
            })?
            .clone();

        let res_store = self.data.ddec_result_store.clone();
        // This is throughput testing we thus will use a single ciphertext and copy
        // it the expected number of times (num_copies).
        // - For Noiseflood technique we first do the SnS before copying the ctxt as we do
        //   not want to benchmark SnS here
        // - For BitDec it is not yet parallelised at the block level
        if let Some(throughput) = throughput {
            let num_sessions = throughput.num_sessions;
            let num_copies = throughput.num_copies;
            let chunk_size = num_copies.div_ceil(num_sessions);
            let role_assignments = role_assignments.clone();
            let prss_setup = self.data.prss_setup.clone();
            let sns_key = Arc::new(key_ref.0.server_key.noise_squashing_key().unwrap());
            let server_key = Arc::new(key_ref.0.server_key.as_ref());
            let ks = Arc::new(
                key_ref
                    .0
                    .server_key
                    .as_ref()
                    .as_ref()
                    .key_switching_key
                    .clone(),
            );
            //Throughput number of ctxts is dictated by num_sessions*num_copies
            //we thus only take the 1st ctxt here
            let num_blocks = ctxts[0].len();
            let ctxt = ctxts[0].clone();

            //Create one session for bcast
            let bcast_session = self
                .create_base_session(
                    session_id,
                    threshold,
                    role_assignments.clone(),
                    NetworkMode::Sync,
                    None,
                )
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create Base Session: {:?}", e),
                    )
                })?;
            let new_session_id = bcast_session.session_id();

            match decryption_mode {
                DecryptionMode::NoiseFloodSmall => {
                    let base_sessions = self
                        .create_base_sessions(
                            new_session_id,
                            num_sessions,
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
                    let ct_large = match ctxt {
                        RadixOrBoolCiphertext::Bool(ct) => {
                            let squashed = sns_key
                                .squash_boolean_block_noise(&server_key, &ct)
                                .expect("squash noise failed for boolean ct");
                            SnsRadixOrBoolCiphertext::Bool(squashed)
                        }
                        RadixOrBoolCiphertext::Radix(ct) => SnsRadixOrBoolCiphertext::Radix(
                            sns_key
                                .squash_radix_ciphertext_noise(&server_key, &ct)
                                .expect("squash noise failed for radix ct"),
                        ),
                    };
                    //Do bcast after the Sns to sync parties
                    let _ = SyncReliableBroadcast::default()
                        .broadcast_from_all(
                            &bcast_session,
                            BroadcastValue::from(Z128::from_u128(42)),
                        )
                        .await;
                    let my_future = || async move {
                        let num_blocks = ct_large.len();

                        // Copy the ctxt
                        let ctxt_chunked = vec![vec![ct_large; chunk_size]; num_sessions];

                        // Derive all the prss states (1 per session)
                        let prss_setup = prss_setup
                            .get(&SupportedRing::ResiduePolyZ128)
                            .ok_or_else(|| {
                                tonic::Status::new(
                                    tonic::Code::Aborted,
                                    "Failed to retrieve prss_setup, try init it first".to_string(),
                                )
                            })
                            .unwrap()
                            .get_poly128()
                            .unwrap();

                        // Instantiate required number of small sessions
                        let small_sessions = create_small_sessions(base_sessions, &prss_setup)
                            .into_iter()
                            .map(NoiseFloodSmallSession::new)
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
                                                &mut noiseflood_preprocessing,
                                                &key_ref.1,
                                                &ctxt,
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
                        let mut vec_res = Vec::new();
                        let mut vec_base_sessions = Vec::new();
                        let mut all_res = Vec::new();
                        while let Some(Ok((res, base_session))) = decryption_tasks.join_next().await
                        {
                            vec_base_sessions.push(base_session);
                            all_res.push(res[0]);
                        }
                        vec_res.push(all_res[0]);

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
                    // Create enough sessions to enable parallelism for TDecTwo
                    let base_sessions = self
                        .create_base_sessions(
                            new_session_id,
                            num_sessions * num_blocks,
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
                    //Do bcast to sync parties
                    let _ = SyncReliableBroadcast::default()
                        .broadcast_from_all(
                            &bcast_session,
                            BroadcastValue::from(Z128::from_u128(42)),
                        )
                        .await;
                    let my_future = || async move {
                        // Copy the ctxt
                        let ctxt_chunked = vec![vec![ctxt.clone(); chunk_size]; num_sessions];

                        // Derive all the prss states (1 per session)
                        let prss_setup = prss_setup
                            .get(&SupportedRing::ResiduePolyZ64)
                            .ok_or_else(|| {
                                tonic::Status::new(
                                    tonic::Code::Aborted,
                                    "Failed to retrieve prss_setup, try init it first".to_string(),
                                )
                            })
                            .unwrap()
                            .get_poly64()
                            .unwrap();

                        // Create required number of small sessions from base sessions and prss_states
                        let small_sessions = create_small_sessions(base_sessions, &prss_setup);
                        let small_sessions = small_sessions.into_iter().chunks(num_blocks);

                        // Spawn a tokio task for each session
                        let mut decryption_tasks = JoinSet::new();
                        for (small_session_chunk, ctxts) in
                            small_sessions.into_iter().zip(ctxt_chunked.into_iter())
                        {
                            let key_ref = key_ref.clone();
                            let ks = ks.clone();
                            let small_session_chunk = small_session_chunk.collect_vec();

                            decryption_tasks.spawn(
                                async move {
                                    //First, rework the ctxt layout to match sessions'
                                    let mut ctxts_w_session_layout = vec![Vec::new(); num_blocks];
                                    ctxts.into_iter().for_each(|ctxt| {
                                        ctxt.owned_blocks()
                                            .into_iter()
                                            .zip(ctxts_w_session_layout.iter_mut())
                                            .for_each(|(block, ctxts)| ctxts.push(block));
                                    });

                                    //Give block i of each ctxt to session i
                                    let mut tasks = JoinSet::new();
                                    for (block_idx, (mut small_session, inner_blocks_ctxt)) in
                                        small_session_chunk
                                            .into_iter()
                                            .zip(ctxts_w_session_layout.into_iter())
                                            .enumerate()
                                    {
                                        let key_ref = Arc::clone(&key_ref);
                                        let ks = Arc::clone(&ks);
                                        tasks.spawn(
                                            async move {
                                                let mut bitdec_preprocessing = init_prep_bitdec::<
                                                    EXTENSION_DEGREE,
                                                    _,
                                                    SmallOfflineStrategy,
                                                >(
                                                    &mut small_session,
                                                    inner_blocks_ctxt.len(),
                                                )
                                                .await
                                                .unwrap();
                                                //Split preprocessing into chunks for each ctxt
                                                let mut inner_preprocessings = (0
                                                    ..inner_blocks_ctxt.len())
                                                    .map(|_| {
                                                        bitdec_preprocessing
                                                            .cast_to_in_memory_impl(1)
                                                            .unwrap()
                                                    })
                                                    .collect_vec();
                                                let mut base_session = small_session.base_session;
                                                let res = task_decryption_bitdec_par::<
                                                    EXTENSION_DEGREE,
                                                    _,
                                                    _,
                                                    u64,
                                                >(
                                                    &mut base_session,
                                                    &mut inner_preprocessings,
                                                    &key_ref.1,
                                                    &ks,
                                                    inner_blocks_ctxt,
                                                )
                                                .await;
                                                (block_idx, res, base_session)
                                            }
                                            .instrument(tracing::Span::current()),
                                        );
                                    }

                                    //Join on task of block-wise decryptions
                                    //Re-assemble the partial resuts coming from all the tasks
                                    let mut indexed_blocks_accumulator = Vec::new();
                                    let mut sessions = Vec::new();
                                    while let Some(partial_decrypts) = tasks.join_next().await {
                                        let (block_idx, partial_decrypts, session) =
                                            partial_decrypts.unwrap();
                                        indexed_blocks_accumulator
                                            .push((block_idx, partial_decrypts.unwrap()));
                                        sessions.push(session);
                                    }

                                    indexed_blocks_accumulator
                                        .sort_by_key(|(index, _blocks)| *index);

                                    let mut blocks_partial_decrypts = Vec::new();
                                    for _ in 0..num_ctxts {
                                        let mut rearranged_blocks = BlocksPartialDecrypt::default();
                                        for (_, blocks) in indexed_blocks_accumulator.iter_mut() {
                                            //If this fails the task did not compute num_ctxts
                                            //which should not happen
                                            let block = blocks.pop().unwrap();
                                            rearranged_blocks.bits_in_block = block.bits_in_block;
                                            rearranged_blocks
                                                .partial_decryptions
                                                .push(block.partial_decryption);
                                        }
                                        blocks_partial_decrypts.push(rearranged_blocks);
                                    }

                                    let res = blocks_partial_decrypts
                                        .into_iter()
                                        .map(|blocks| {
                                            Wrapping(combine_plaintext_blocks(blocks).unwrap())
                                        })
                                        .rev() //Add a rev because with push and pop we reversed ctxt order
                                        .collect_vec();

                                    (res, sessions)
                                }
                                .instrument(tracing::Span::current()),
                            );
                        }
                        //Retrieve info from this batch
                        let mut vec_res = Vec::new();
                        let mut vec_base_sessions = Vec::new();
                        let mut all_res = Vec::new();
                        while let Some(Ok((res, base_session))) = decryption_tasks.join_next().await
                        {
                            vec_base_sessions.extend(base_session);
                            all_res.push(res[0]);
                        }
                        vec_res.push(all_res[0]);

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
            let mut base_session = BaseSession::new(params, networking, AesRng::from_entropy())
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Failed to create Base Session: {:?}", e),
                    )
                })?;
            match decryption_mode {
                // For BitDec we do parallelization by spawning one session per "raw" ctxt
                DecryptionMode::BitDecLarge | DecryptionMode::BitDecSmall => {
                    //We assume all ctxt are same TFHEType
                    let num_sessions = ctxts.first().unwrap().len();
                    //let base_sessions = self.create_base_sessions(session_id,)
                    let preprocessings = if let Some(preproc_sid) = preproc_sid {
                        self.data.ddec_preproc_store_bd.remove(&preproc_sid).ok_or_else(|| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            format!("Can not find BitDec preproc that corresponds to session ID {preproc_sid}"),
                        )
                    })?.1
                    } else {
                        let sid_u128: u128 = session_id.into();
                        let mut dummy_preproc =
                            DummyPreprocessing::new(sid_u128 as u64, &base_session);
                        (0..num_sessions)
                            .map(|_| {
                                (0..num_ctxts)
                                    .map(|_| dummy_preproc.cast_to_in_memory_impl(1).unwrap())
                                    .collect_vec()
                            })
                            .collect_vec()
                    };

                    //Sanity checking
                    if num_sessions != preprocessings.len() {
                        return Err(tonic::Status::new(
                            tonic::Code::Aborted,
                            format!(
                                "Expected {} blocks of preprocessing, found only {}",
                                num_sessions,
                                preprocessings.len()
                            ),
                        ));
                    }

                    let base_sessions = self
                        .create_base_sessions(
                            session_id,
                            num_sessions,
                            threshold,
                            role_assignments.clone(),
                            NetworkMode::Async,
                            request.seed,
                        )
                        .await
                        .unwrap();

                    //NOTE: Inline the decryption process to parallelize it more easily without side effects on
                    //rest of codebase for now

                    //First, rework the ctxt layout to match sessions'
                    let mut ctxts_w_session_layout = vec![Vec::new(); num_sessions];
                    ctxts.into_iter().for_each(|ctxt| {
                        ctxt.owned_blocks()
                            .into_iter()
                            .zip(ctxts_w_session_layout.iter_mut())
                            .for_each(|(block, ctxts)| ctxts.push(block));
                    });

                    let my_future = || async move {
                        let ks = Arc::new(
                            key_ref
                                .0
                                .server_key
                                .as_ref()
                                .as_ref()
                                .key_switching_key
                                .clone(),
                        );
                        let mut tasks = JoinSet::new();
                        for (block_idx, (ctxts_blocks, (mut session, mut inner_preprocessings))) in
                            ctxts_w_session_layout
                                .into_iter()
                                .zip(base_sessions.into_iter().zip(preprocessings.into_iter()))
                                .enumerate()
                        {
                            let ksk = ks.clone();
                            let key_share = key_ref.clone();

                            tasks.spawn(
                                async move {
                                    (
                                        block_idx,
                                        task_decryption_bitdec_par::<EXTENSION_DEGREE, _, _, u64>(
                                            &mut session,
                                            &mut inner_preprocessings,
                                            &key_share.1,
                                            &ksk,
                                            ctxts_blocks,
                                        )
                                        .await,
                                        session,
                                    )
                                }
                                .instrument(tracing::Span::current()),
                            );
                        }

                        //Re-assemble the partial resuts coming from all the tasks
                        let mut indexed_blocks_accumulator = Vec::new();
                        let mut sessions = Vec::new();
                        while let Some(partial_decrypts) = tasks.join_next().await {
                            let (block_idx, partial_decrypts, session) = partial_decrypts.unwrap();
                            indexed_blocks_accumulator.push((block_idx, partial_decrypts.unwrap()));
                            sessions.push(session);
                        }

                        indexed_blocks_accumulator.sort_by_key(|(index, _blocks)| *index);

                        let mut blocks_partial_decrypts = Vec::new();
                        for _ in 0..num_ctxts {
                            let mut rearranged_blocks = BlocksPartialDecrypt::default();
                            for (_, blocks) in indexed_blocks_accumulator.iter_mut() {
                                //If this fails the task did not compute num_ctxts
                                //which should not happen
                                let block = blocks.pop().unwrap();
                                rearranged_blocks.bits_in_block = block.bits_in_block;
                                rearranged_blocks
                                    .partial_decryptions
                                    .push(block.partial_decryption);
                            }
                            blocks_partial_decrypts.push(rearranged_blocks);
                        }

                        let res = blocks_partial_decrypts
                            .into_iter()
                            .map(|blocks| Wrapping(combine_plaintext_blocks(blocks).unwrap()))
                            .rev() //Add a rev because with push and pop we reversed ctxt order
                            .collect_vec();

                        res_store.insert(session_id, res);
                        fill_network_memory_info_multiple_sessions(sessions);
                    };
                    self.data.status_store.insert(
                        session_id,
                        tokio::spawn(my_future().instrument(tracing::Span::current())),
                    );
                }
                DecryptionMode::NoiseFloodSmall | DecryptionMode::NoiseFloodLarge => {
                    if key_ref.0.server_key.noise_squashing_key().is_none() {
                        return Err(tonic::Status::new(tonic::Code::Aborted,format!("Asked for NoiseFlood decrypt but there is no Switch and Squash key for key at session ID {key_sid}")));
                    }
                    let preprocessings = if let Some(preproc_sid) = preproc_sid {
                        self.data.ddec_preproc_store_nf.remove(&preproc_sid).ok_or_else(|| {
                        tonic::Status::new(tonic::Code::Aborted,format!("Can not find NoiseFlood preproc that corresponds to session ID {preproc_sid}"))
                    })?.1
                    } else {
                        //Assume all ctxt have the same number of blocks
                        let num_blocks_per_ctxt = ctxts.first().unwrap().len();
                        let sid_u128: u128 = session_id.into();
                        let mut dummy_preproc =
                            DummyPreprocessing::new(sid_u128 as u64, &base_session);
                        (0..num_ctxts)
                            .map(|_| {
                                let mut inner =
                                    InMemoryNoiseFloodPreprocessing::<EXTENSION_DEGREE>::default();
                                inner
                                    .fill_from_bits_preproc(&mut dummy_preproc, num_blocks_per_ctxt)
                                    .unwrap();
                                inner
                            })
                            .collect_vec()
                    };
                    let my_future = || async move {
                        let server_key = key_ref.0.server_key.as_ref();
                        let mut res = Vec::new();
                        let sns_key = key_ref.0.server_key.noise_squashing_key();
                        for (ctxt, mut preprocessing) in
                            ctxts.into_iter().zip(preprocessings.into_iter())
                        {
                            let ct_large = if let Some(sns_key) = sns_key {
                                match ctxt {
                                    RadixOrBoolCiphertext::Radix(ct) => {
                                        SnsRadixOrBoolCiphertext::Radix(
                                            sns_key
                                                .squash_radix_ciphertext_noise(server_key, &ct)
                                                .expect("squash noise failed for radix ct"),
                                        )
                                    }
                                    RadixOrBoolCiphertext::Bool(ct) => {
                                        let squashed = sns_key
                                            .squash_boolean_block_noise(server_key, &ct)
                                            .expect("squash noise failed for boolean ct");
                                        SnsRadixOrBoolCiphertext::Bool(squashed)
                                    }
                                }
                            } else {
                                panic!("Missing key (it was there just before)")
                            };
                            res.push(
                                run_decryption_noiseflood_64(
                                    &mut base_session,
                                    &mut preprocessing,
                                    &key_ref.1,
                                    &ct_large,
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

    #[instrument(name = "DDEC-RESULT", skip_all)]
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let crs_params: CrsGenParams = bc2wrap::deserialize(&request.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse Crs Gen params: {:?}", e),
            )
        })?;

        let session_id = crs_params.session_id;
        let witness_dim = crs_params.witness_dim;

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

        let crs_store = self.data.crs_store.clone();
        let my_future = || async move {
            let real_ceremony = SecureCeremony::default();
            let pp = real_ceremony
                .execute::<Z64, _>(
                    &mut base_session,
                    witness_dim as usize,
                    request.max_num_bits,
                )
                .await
                .unwrap();
            crs_store.insert(session_id, pp.inner);
            fill_network_memory_info_single_session(base_session);
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

        let session_id: SessionId = bc2wrap::deserialize(&request.request_id).map_err(|e| {
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

        let res_serialized = bc2wrap::serialize(&res).map_err(|e| {
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

    #[instrument(
        name = "RESHARE",
        skip_all,
        fields(network_round, network_sent, network_received, peak_mem)
    )]
    async fn reshare(
        &self,
        request: tonic::Request<ReshareRequest>,
    ) -> Result<tonic::Response<ReshareResponse>, tonic::Status> {
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
            bc2wrap::deserialize(&request.role_assignment).map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("Failed to parse role assignment: {:?}", e),
                )
            })?;

        let reshare_params: ReshareParams = bc2wrap::deserialize(&request.params).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Failed to parse Reshare params: {:?}", e),
            )
        })?;

        let session_type = reshare_params.session_type;
        //We use the new_key_sid as the session_id for the protocol
        let session_id = reshare_params.new_key_sid;
        let num_parties = role_assignments.len();

        //Create 3 sessions, 2 for preproc (z64 and z128), 1 for actual reshare
        let mut base_sessions = self
            .create_base_sessions(
                session_id,
                3,
                threshold,
                role_assignments,
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

        let prss_setup = self.data.prss_setup.clone();

        let key_store = self.data.key_store.clone();

        let my_future = || async move {
            let old_key_sid = reshare_params.old_key_sid;
            let key_ref = key_store
                .get(&old_key_sid)
                .ok_or_else(|| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("Can not find key that corresponds to session ID {old_key_sid}"),
                    )
                })
                .unwrap()
                .clone();
            let preproc_z128_base_session = base_sessions
                .pop()
                .expect("Can not retrieve a session for preproc_z128");
            let preproc_z64_base_session = base_sessions
                .pop()
                .expect("Can not retrieve a session for preproc_z64");
            let mut reshare_base_session = base_sessions
                .pop()
                .expect("Can not retrieve a session for reshare");

            //NOTE: we need a mutable access to the keyset because reshare will zeroize it
            //however since this is a clone it doesn't do much...
            //Wondering whether it really should be reshare's role to zeroize stuff ?
            let public_key_set = key_ref.0.clone();
            let mut old_private_key_set = key_ref.1.clone();

            //Perform preprocessing
            let num_needed_preproc =
                ResharePreprocRequired::new_same_set(num_parties, &old_private_key_set);

            let (mut preprocessing_64, mut preprocessing_128, sessions) = match session_type {
                SessionType::Small => {
                    let prss_setup_z128 = prss_setup
                        .get(&SupportedRing::ResiduePolyZ128)
                        .ok_or_else(|| {
                            tonic::Status::new(
                                tonic::Code::Aborted,
                                "Failed to retrieve prss_setup_z128, try init it first".to_string(),
                            )
                        })
                        .unwrap()
                        .get_poly128()
                        .unwrap();

                    let prss_setup_z64 = prss_setup
                        .get(&SupportedRing::ResiduePolyZ64)
                        .ok_or_else(|| {
                            tonic::Status::new(
                                tonic::Code::Aborted,
                                "Failed to retrieve prss_setup_z64, try init it first".to_string(),
                            )
                        })
                        .unwrap()
                        .get_poly64()
                        .unwrap();

                    let mut small_session_z64 =
                        create_small_session(preproc_z64_base_session, &prss_setup_z64);
                    let mut small_session_z128 =
                        create_small_session(preproc_z128_base_session, &prss_setup_z128);

                    let correlated_randomness_z64 = SecureSmallPreprocessing::default()
                        .execute(&mut small_session_z64, num_needed_preproc.batch_params_64)
                        .await
                        .unwrap();

                    let correlated_randomness_z128 = SecureSmallPreprocessing::default()
                        .execute(&mut small_session_z128, num_needed_preproc.batch_params_128)
                        .await
                        .unwrap();

                    (
                        correlated_randomness_z64,
                        correlated_randomness_z128,
                        [
                            small_session_z64.to_base_session(),
                            small_session_z128.to_base_session(),
                        ],
                    )
                }
                SessionType::Large => {
                    let mut large_session_z64 = create_large_session(preproc_z64_base_session);
                    let mut large_session_z128 = create_large_session(preproc_z128_base_session);

                    let correlated_randomness_z64 = SecureLargePreprocessing::default()
                        .execute(&mut large_session_z64, num_needed_preproc.batch_params_64)
                        .await
                        .unwrap();
                    let correlated_randomness_z128 = SecureLargePreprocessing::default()
                        .execute(&mut large_session_z128, num_needed_preproc.batch_params_128)
                        .await
                        .unwrap();

                    (
                        correlated_randomness_z64,
                        correlated_randomness_z128,
                        [
                            large_session_z64.to_base_session(),
                            large_session_z128.to_base_session(),
                        ],
                    )
                }
            };

            //Perform online
            let new_private_key_set = reshare_sk_same_sets(
                &mut preprocessing_128,
                &mut preprocessing_64,
                &mut reshare_base_session,
                &mut old_private_key_set,
            )
            .await
            .unwrap();

            //Store the new_private_key
            //NOTE: we do not delete the old one as moby is only for testing purposes
            key_store.insert(
                reshare_params.new_key_sid,
                Arc::new((public_key_set, new_private_key_set)),
            );
            let mut sessions = sessions.into_iter().collect_vec();
            sessions.push(reshare_base_session);
            fill_network_memory_info_multiple_sessions(sessions);
        };

        self.data.status_store.insert(
            reshare_params.new_key_sid,
            tokio::spawn(my_future().instrument(tracing::Span::current())),
        );

        let sid_serialized = bc2wrap::serialize(&reshare_params.new_key_sid).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("Error serializing session ID {e}"),
            )
        })?;
        Ok(tonic::Response::new(ReshareResponse {
            request_id: sid_serialized,
        }))
    }
}

/// Fill the current span with the following information:
/// - total number of sessions
/// - max number of rounds across all sessions
/// - total number of bytes sent across all sessions
/// - total number of bytes received across all sessions
/// - peak memory usage in bytes as given by the custom allocator
pub(crate) fn fill_network_memory_info_multiple_sessions<B: BaseSessionHandles>(sessions: Vec<B>) {
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

pub(crate) fn fill_network_memory_info_single_session<B: BaseSessionHandles>(session: B) {
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
    SessionId::from(
        ((rng.next_u64() as u128) << 64)
            | ((rng.next_u32() as u128) << 32)
            | (current_sid & 0xFFFF_FFFF),
    )
}

pub fn create_small_session<
    Z: ErrorCorrect + Invert + PRSSConversions,
    PRSSSetupType: DerivePRSSState<Z>,
>(
    base_session: BaseSession,
    prss_setup: &PRSSSetupType,
) -> GenericSmallSessionStruct<Z, PRSSSetupType::OutputType> {
    create_small_sessions(vec![base_session], prss_setup)
        .pop()
        .unwrap()
}

pub fn create_small_sessions<
    Z: ErrorCorrect + Invert + PRSSConversions,
    PRSSSetupType: DerivePRSSState<Z>,
>(
    base_sessions: Vec<BaseSession>,
    prss_setup: &PRSSSetupType,
) -> Vec<GenericSmallSessionStruct<Z, PRSSSetupType::OutputType>> {
    base_sessions
        .into_iter()
        .map(|base_session| {
            let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
            GenericSmallSessionStruct::new_from_prss_state(base_session, prss_state).unwrap()
        })
        .collect_vec()
}

pub fn create_large_session(base_session: BaseSession) -> LargeSession {
    create_large_sessions(vec![base_session]).pop().unwrap()
}

pub fn create_large_sessions(base_sessions: Vec<BaseSession>) -> Vec<LargeSession> {
    base_sessions
        .into_iter()
        .map(LargeSession::new)
        .collect_vec()
}
