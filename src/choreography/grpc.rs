//! gRPC-based choreography.

pub mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_choreography");
}

use self::gen::choreography_server::{Choreography, ChoreographyServer};
use self::gen::{
    DecryptionResponse, KeygenRequest, KeygenResponse, PubkeyRequest, PubkeyResponse,
    RetrieveResultsRequest, RetrieveResultsResponse,
};
use crate::algebra::base_ring::Z64;
use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::execution::endpoints::decryption::{
    init_prep_noiseflood_large, init_prep_noiseflood_small, run_decryption_noiseflood,
};
use crate::execution::endpoints::keygen::initialize_key_material;
use crate::execution::runtime::party::{Identity, Role};
use crate::execution::runtime::session::{
    DecryptionMode, LargeSession, SessionParameters, SmallSessionStruct,
};
use crate::lwe::to_large_ciphertext_block;
use crate::lwe::{Ciphertext64, PubConKeyPair, SecretKeyShare, ThresholdLWEParameters};
use crate::networking::constants::MAX_EN_DECODE_MESSAGE_SIZE;
use crate::{
    choreography::grpc::gen::DecryptionRequest, execution::runtime::session::SmallSession,
};
use crate::{choreography::NetworkingStrategy, execution::runtime::session::SetupMode};
use crate::{computation::SessionId, execution::small_execution::prss::PRSSSetup};
use async_cell::sync::AsyncCell;
use async_trait::async_trait;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

///Used to store results of decryption
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ComputationOutputs {
    pub outputs: HashMap<String, Vec<Z64>>,
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

#[derive(Clone)]
struct SetupInfo {
    pub secret_key_share: SecretKeyShare,
    pub prss_setup: HashMap<SupportedRing, SupportedPRSSSetup>,
}

type ResultStores = DashMap<SessionId, Arc<AsyncCell<ComputationOutputs>>>;
type SetupStore = DashMap<SessionId, Arc<AsyncCell<SetupInfo>>>;

///Store results of decryptions (Z64) and setups for PRSS128 and PRSS64
pub struct GrpcChoreography {
    own_identity: Identity,
    result_stores: Arc<ResultStores>,
    networking_strategy: NetworkingStrategy,
    setup_store: Arc<SetupStore>,
    pubkey_store: Arc<Mutex<Option<PubConKeyPair>>>,
    setup_epoch_id: AsyncCell<SessionId>,
}

impl GrpcChoreography {
    pub fn new(own_identity: Identity, networking_strategy: NetworkingStrategy) -> Self {
        GrpcChoreography {
            own_identity,
            result_stores: Arc::new(ResultStores::default()),
            networking_strategy,
            setup_store: Arc::new(SetupStore::default()),
            setup_epoch_id: AsyncCell::default(),
            pubkey_store: Arc::new(Mutex::new(None)),
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
    ///NOTE: For now we only do threshold decrypt with Ctxt lifting, but we may want to propose both options
    /// (that's why we have setup_store contain a map for both options)
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

        let session_id = SessionId::new(&ct).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to construct session ID".to_string(),
            )
        })?;
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

                let setup_info = self
                    .setup_store
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

                let result_stores = Arc::clone(&self.result_stores);
                let pks = Arc::clone(&self.pubkey_store);
                let pkl = pks.lock().unwrap().clone();
                match mode {
                    DecryptionMode::PRSSDecrypt => {
                        let prss_setup =
                            match setup_info.prss_setup.get(&SupportedRing::ResiduePoly128) {
                                Some(SupportedPRSSSetup::ResiduePoly128(v)) => v.clone(),
                                _ => None,
                            };
                        let mut session = SmallSession::new(
                            session_id,
                            role_assignments,
                            Arc::clone(&networking),
                            threshold,
                            prss_setup,
                            own_identity.clone(),
                            None,
                        )
                        .map_err(|e| {
                            tonic::Status::new(
                                tonic::Code::Aborted,
                                format!("could not make a valid session with current parameters. Failed with error \"{:?}\"", e).to_string(),
                            )
                        })?;

                        tokio::spawn(async move {
                            let execution_start_timer = Instant::now();
                            let ck = &pkl
                                .as_ref()
                                .ok_or_else(|| {
                                    tonic::Status::new(
                                        tonic::Code::Aborted,
                                        "No public key available for decryption".to_string(),
                                    )
                                })
                                .unwrap()
                                .ck;
                            let ct_large = ct
                                .iter()
                                .map(|ct_block| to_large_ciphertext_block(ck, ct_block))
                                .collect_vec();

                            //Set up the preprocessing
                            let mut noiseflood_preprocessing =
                                init_prep_noiseflood_small(&mut session, ct_large.len());

                            let mut results = HashMap::with_capacity(1);
                            let outputs = run_decryption_noiseflood(
                                &mut session,
                                noiseflood_preprocessing.as_mut(),
                                &setup_info.secret_key_share,
                                ct_large,
                            )
                            .await
                            .unwrap();

                            tracing::info!(
                                "Results in session {:?} ready: {:?}",
                                session_id,
                                outputs
                            );
                            results.insert(format!("{session_id}"), outputs);

                            let execution_stop_timer = Instant::now();
                            let elapsed_time =
                                execution_stop_timer.duration_since(execution_start_timer);
                            result_stores
                                .get(&session_id)
                                .map(|res| {
                                    res.set(ComputationOutputs {
                                        outputs: results,
                                        elapsed_time: Some(elapsed_time),
                                    });
                                })
                                .expect("session disappeared unexpectedly");
                            tracing::info!(
                                "Online time was {:?} microseconds",
                                (elapsed_time).as_micros()
                            );
                        });
                    }
                    DecryptionMode::LargeDecrypt => {
                        let session_params = SessionParameters::new(
                            threshold,
                            session_id,
                            own_identity,
                            role_assignments,
                        )
                        .unwrap();
                        let mut session =
                            LargeSession::new(session_params, Arc::clone(&networking)).unwrap();
                        tokio::spawn(async move {
                            let execution_start_timer = Instant::now();
                            let ck = &pkl
                                .as_ref()
                                .ok_or_else(|| {
                                    tonic::Status::new(
                                        tonic::Code::Aborted,
                                        "No public key available for decryption".to_string(),
                                    )
                                })
                                .unwrap()
                                .ck;
                            let ct_large = ct
                                .iter()
                                .map(|ct_block| to_large_ciphertext_block(ck, ct_block))
                                .collect_vec();

                            //Set up the preprocessing
                            let mut noiseflood_preprocessing =
                                init_prep_noiseflood_large(&mut session, ct_large.len()).await;

                            let mut results = HashMap::with_capacity(1);
                            let outputs = run_decryption_noiseflood(
                                &mut session,
                                noiseflood_preprocessing.as_mut(),
                                &setup_info.secret_key_share,
                                ct_large,
                            )
                            .await
                            .unwrap();

                            tracing::info!(
                                "Results in session {:?} ready: {:?}",
                                session_id,
                                outputs
                            );
                            results.insert(format!("{session_id}"), outputs);

                            let execution_stop_timer = Instant::now();
                            let elapsed_time =
                                execution_stop_timer.duration_since(execution_start_timer);

                            result_stores
                                .get(&session_id)
                                .map(|result_cell| {
                                    result_cell.set(ComputationOutputs {
                                        outputs: results,
                                        elapsed_time: Some(elapsed_time),
                                    });
                                })
                                .expect("session disappeared unexpectedly");
                            tracing::info!(
                                "Online time was {:?} microseconds",
                                (elapsed_time).as_micros()
                            );
                        });
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
    async fn keygen(
        &self,
        request: tonic::Request<KeygenRequest>,
    ) -> Result<tonic::Response<KeygenResponse>, tonic::Status> {
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

        let params: ThresholdLWEParameters =
            bincode::deserialize(&request.params).map_err(|_e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    "failed to parse parameters".to_string(),
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

                let mut session: SmallSessionStruct<ResiduePoly128,aes_prng::AesRng, SessionParameters> = SmallSession::new(
                    epoch_id, role_assignments, Arc::clone(&networking), threshold, None, own_identity, None,)
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        format!("could not make a valid session with current parameters. Failed with error \"{:?}\"", e).to_string(),
                    )
                })?;

                let setup_store = Arc::clone(&self.setup_store);
                let pks = Arc::clone(&self.pubkey_store);

                tokio::spawn(async move {
                    let (sk, pk, prss_setup) =
                        initialize_key_material(&mut session, setup_mode, params)
                            .await
                            .unwrap();

                    let mut map_setup = HashMap::new();
                    map_setup.insert(
                        SupportedRing::ResiduePoly128,
                        SupportedPRSSSetup::ResiduePoly128(prss_setup),
                    );

                    setup_store
                        .get(&epoch_id)
                        .map(|setup_result_cell| {
                            setup_result_cell.set(SetupInfo {
                                secret_key_share: sk,
                                prss_setup: map_setup,
                            });
                        })
                        .expect("Epoch key store disappeared unexpectedly");

                    *pks.lock().unwrap() = Some(pk);
                    tracing::debug!("Key material stored.");
                });

                Ok(tonic::Response::new(KeygenResponse {}))
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

        let comp = self
            .setup_store
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

        let pks = Arc::clone(&self.pubkey_store);
        let pkl = pks.lock().unwrap().clone().ok_or_else(|| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "No public key available for decryption".to_string(),
            )
        })?;

        let pk_serialized = bincode::serialize(&pkl).expect("failed to serialize results");
        tracing::debug!("Pubkey successfully retrieved.");

        Ok(tonic::Response::new(PubkeyResponse {
            pubkey: pk_serialized,
        }))
    }
}
