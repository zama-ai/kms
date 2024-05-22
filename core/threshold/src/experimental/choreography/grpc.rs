//! gRPC-based choreography for experimental features

use crate::choreography::grpc::gen::choreography_server::{Choreography, ChoreographyServer};
use crate::choreography::grpc::gen::{
    CrsCeremonyRequest, CrsCeremonyResponse, CrsRequest, CrsResponse, DecryptionRequest,
    DecryptionResponse, KeygenRequest, KeygenResponse, PreprocRequest, PreprocResponse,
    PubkeyRequest, PubkeyResponse, RetrieveResultsRequest, RetrieveResultsResponse,
};
use crate::choreography::NetworkingStrategy;
use crate::execution::constants::INPUT_PARTY_ID;
use crate::execution::online::preprocessing::PreprocessorFactory;
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::ParameterHandles;
use crate::execution::runtime::session::SessionParameters;
use crate::execution::runtime::session::SmallSessionStruct;
use crate::execution::runtime::session::{BaseSession, BaseSessionStruct};
use crate::execution::small_execution::agree_random::RealAgreeRandom;
use crate::execution::small_execution::prss::PRSSSetup;
use crate::experimental::algebra::levels::LevelOne;
use crate::experimental::bgv::basics::{LevelEllBgvCiphertext, PrivateBgvKeySet, PublicBgvKeySet};
use crate::experimental::bgv::ddec::noise_flood_decryption;
use crate::experimental::bgv::utils::transfer_secret_key;
use crate::experimental::bgv::utils::{gen_key_set, transfer_pub_key};
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::session_id::SessionId;
use aes_prng::AesRng;
use async_cell::sync::AsyncCell;
use async_trait::async_trait;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::instrument;

pub const EPOCH: SessionId = SessionId(0_u128);

///Used to store results of decryption
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ComputationOutputs {
    pub outputs: HashMap<String, Vec<u32>>,
    pub elapsed_time: Option<Duration>,
}

/// Structure that holds data from the one-time init phase
#[derive(Clone)]
struct InitInfo {
    pub secret_key_share: PrivateBgvKeySet,
    pub prss_setup_level_one: PRSSSetup<LevelOne>,
}

type ResultStores = DashMap<SessionId, Arc<AsyncCell<ComputationOutputs>>>;
type InitStore = AsyncCell<InitInfo>;

#[derive(Default)]
struct GrpcDataStores {
    init_store: Arc<InitStore>,
    pubkey_store: Arc<Mutex<Option<PublicBgvKeySet>>>,
    result_stores: Arc<ResultStores>,
}

pub struct ExperimentalGrpcChoreography {
    own_identity: Identity,
    networking_strategy: NetworkingStrategy,
    data: GrpcDataStores,
}

impl ExperimentalGrpcChoreography {
    pub fn new(
        own_identity: Identity,
        networking_strategy: NetworkingStrategy,
        _factory: Box<dyn PreprocessorFactory>,
    ) -> Self {
        tracing::debug!("Starting an experimental grpc choreography...");
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
}

#[async_trait]
impl Choreography for ExperimentalGrpcChoreography {
    ///NOTE: For now we only do threshold decrypt with Ctxt lifting, but we may want to propose both options
    /// (that's why we have setup_store contain a map for both options)
    #[instrument(skip(self, request))]
    async fn threshold_decrypt(
        &self,
        request: tonic::Request<DecryptionRequest>,
    ) -> Result<tonic::Response<DecryptionResponse>, tonic::Status> {
        let request = request.into_inner();

        let ct =
            bincode::deserialize::<LevelEllBgvCiphertext>(&request.ciphertext).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse ciphertext".to_string(),
                )
            })?;

        //Useless for now, need to integrate large threshold decrypt to grpc
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

        let session_id = SessionId::from_bgv_ct(&ct).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to construct session ID".to_string(),
            )
        })?;

        match self.data.result_stores.entry(session_id) {
            Entry::Occupied(_) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "session id exists already or inconsistent metric and result map".to_string(),
            )),
            Entry::Vacant(result_stores_entry) => {
                tracing::debug!("I've launched a new BGV decryption");

                let setup_info = self.data.init_store.clone();
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

                let ct_c = Arc::new(ct.clone());
                tokio::spawn(async move {
                    let prss_setup = setup_info.prss_setup_level_one.clone();
                    let mut session = SmallSessionStruct::new_from_prss_state(
                        base_session,
                        prss_setup.new_prss_session_state(session_id),
                    )
                    .unwrap();
                    let (results, elapsed_time) = noise_flood_decryption(
                        &mut session,
                        &setup_info.secret_key_share,
                        ct_c.as_ref(),
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
        let results = match self.data.result_stores.get(&session_id) {
            Some(res) => res.value().get().await,
            None => {
                return Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("unknown session id {:?} for choreographer", session_id.0),
                ))
            }
        };

        let values = bincode::serialize(&results).expect("failed to serialize results");
        Ok(tonic::Response::new(RetrieveResultsResponse { values }))
    }

    #[instrument(skip(self, request))]
    async fn keygen(
        &self,
        request: tonic::Request<KeygenRequest>,
    ) -> Result<tonic::Response<KeygenResponse>, tonic::Status> {
        tracing::debug!("calling keygen endpoint...");
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

        tracing::debug!("I've launched a new BGV keygen");

        let own_identity = self.own_identity.clone();
        let networking = (self.networking_strategy)(EPOCH, role_assignments.clone());

        tracing::debug!("own identity: {:?}", own_identity);
        let session_params =
            SessionParameters::new(threshold, EPOCH, own_identity, role_assignments)
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
        let pk_store = Arc::clone(&self.data.pubkey_store);
        tokio::spawn(async move {
            let prss_setup = PRSSSetup::<LevelOne>::init_with_abort::<RealAgreeRandom, AesRng, _>(
                &mut base_session,
            )
            .await
            .unwrap();
            tracing::info!("finished running the PRSS init");
            // TODO(Dragos) here need to generate pk, sk for BGV.
            let (pub_keys, priv_keys) = local_initialize_key_material(&mut base_session)
                .await
                .unwrap();

            tracing::info!("finished local key gen");
            init_store.set(InitInfo {
                secret_key_share: priv_keys,
                prss_setup_level_one: prss_setup,
            });

            *pk_store.lock().unwrap() = Some(pub_keys);
        });

        Ok(tonic::Response::new(KeygenResponse {}))
    }

    async fn retrieve_pubkey(
        &self,
        _request: tonic::Request<PubkeyRequest>,
    ) -> Result<tonic::Response<PubkeyResponse>, tonic::Status> {
        tracing::debug!("Retrieving pubkey...");
        self.data.init_store.get().await;

        let pk = Arc::clone(&self.data.pubkey_store)
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "No public key available for decryption".to_string(),
                )
            })?;
        tracing::debug!("Pubkey successfully retrieved.");
        Ok(tonic::Response::new(PubkeyResponse {
            pubkey: bincode::serialize(&pk).expect("failed to serialize pubkey"),
        }))
    }

    async fn crs_ceremony(
        &self,
        _request: tonic::Request<CrsCeremonyRequest>,
    ) -> Result<tonic::Response<CrsCeremonyResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn retrieve_crs(
        &self,
        _request: tonic::Request<CrsRequest>,
    ) -> Result<tonic::Response<CrsResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn preproc(
        &self,
        _request: tonic::Request<PreprocRequest>,
    ) -> Result<tonic::Response<PreprocResponse>, tonic::Status> {
        unimplemented!()
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
