//! gRPC-based choreography.

pub mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_choreography");
}

use self::gen::choreography_client::ChoreographyClient;
use self::gen::choreography_server::{Choreography, ChoreographyServer};
use self::gen::{LaunchComputationRequest, LaunchComputationResponse};
use super::NetworkingStrategy;
use crate::computation::SessionId;
use crate::execution::distributed::execute_small_circuit;
use crate::execution::distributed::DistributedSession;
use crate::execution::player::Identity;
use crate::execution::player::Role;
use crate::parser::Circuit;
use crate::value::Value;
use aes_prng::AesRng;
use async_cell::sync::AsyncCell;
use async_trait::async_trait;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tonic::codegen::http::Uri;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ComputationOutputs {
    pub outputs: Vec<Value>,
    pub elapsed_time: Option<Duration>,
}

type ResultStores = DashMap<SessionId, Arc<AsyncCell<ComputationOutputs>>>;

pub struct GrpcChoreography {
    own_identity: Identity,
    result_stores: Arc<ResultStores>,
    networking_strategy: NetworkingStrategy,
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
        }
    }

    pub fn into_server(self) -> ChoreographyServer<impl Choreography> {
        ChoreographyServer::new(self)
    }
}

#[async_trait]
impl Choreography for GrpcChoreography {
    async fn launch_computation(
        &self,
        request: tonic::Request<LaunchComputationRequest>,
    ) -> Result<tonic::Response<LaunchComputationResponse>, tonic::Status> {
        tracing::info!("Launching computation");
        let request = request.into_inner();

        let session_id = bincode::deserialize::<SessionId>(&request.session_id).map_err(|_e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                "failed to parse session id".to_string(),
            )
        })?;

        match self.result_stores.entry(session_id.clone()) {
            Entry::Occupied(_) => Err(tonic::Status::new(
                tonic::Code::Aborted,
                "session id exists already or inconsistent metric and result map".to_string(),
            )),
            Entry::Vacant(result_stores_entry) => {
                tracing::debug!("I've  launched a new computation");

                let result_cell = AsyncCell::shared();
                result_stores_entry.insert(result_cell);

                let computation = bincode::deserialize(&request.computation).map_err(|_e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        "failed to parse computation".to_string(),
                    )
                })?;

                let role_assignments: HashMap<Role, Identity> =
                    bincode::deserialize(&request.role_assignment).map_err(|_e| {
                        tonic::Status::new(
                            tonic::Code::Aborted,
                            "failed to parse role assignment".to_string(),
                        )
                    })?;

                let threshold: u8 = bincode::deserialize(&request.threshold).map_err(|_e| {
                    tonic::Status::new(
                        tonic::Code::Aborted,
                        "failed to parse threshold".to_string(),
                    )
                })?;

                let own_identity = self.own_identity.clone();
                let networking = (self.networking_strategy)(session_id.clone());

                tracing::info!("own identity: {:?}", own_identity);

                let session = DistributedSession::new(
                    session_id.clone(),
                    role_assignments,
                    Arc::clone(&networking),
                    threshold,
                );
                let execution_start_timer = Instant::now();
                let result_stores = Arc::clone(&self.result_stores);

                tokio::spawn(async move {
                    let mut rng = AesRng::from_random_seed();
                    let outputs =
                        execute_small_circuit(&session, &computation, &own_identity, &mut rng)
                            .await
                            .unwrap();

                    let mut results = Vec::with_capacity(outputs.len());
                    for output_value in outputs {
                        results.push(output_value);
                    }
                    tracing::info!("Results ready, {:?}", results);

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
                        "Result were computed in {:?} microseconds",
                        elapsed_time.as_micros()
                    );
                });

                Ok(tonic::Response::new(LaunchComputationResponse::default()))
            }
        }
    }
}

pub struct FlamingoRuntime {
    role_assignments: HashMap<Role, Identity>,
    channels: HashMap<Role, Channel>,
}

impl FlamingoRuntime {
    pub fn new(
        role_assignments: HashMap<Role, Identity>,
        tls_config: Option<ClientTlsConfig>,
    ) -> Result<FlamingoRuntime, Box<dyn std::error::Error>> {
        let channels = role_assignments
            .iter()
            .map(|(role, identity)| {
                let endpoint: Uri = format!("http://{}", identity).parse()?;
                tracing::debug!("connecting to endpoint: {:?}", endpoint);
                let mut channel = Channel::builder(endpoint);
                if let Some(ref tls_config) = tls_config {
                    channel = channel.tls_config(tls_config.clone())?;
                };
                let channel = channel.connect_lazy();
                Ok((role.clone(), channel))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;

        Ok(FlamingoRuntime {
            role_assignments,
            channels,
        })
    }

    pub async fn launch_computation(
        &self,
        session_id: &SessionId,
        computation: &Circuit,
        threshold: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = bincode::serialize(session_id)?;
        let computation = bincode::serialize(computation)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let threshold = bincode::serialize(&threshold)?;

        for channel in self.channels.values() {
            let mut client = ChoreographyClient::new(channel.clone());

            let request = LaunchComputationRequest {
                session_id: session_id.clone(),
                computation: computation.clone(),
                role_assignment: role_assignment.clone(),
                threshold: threshold.clone(),
            };

            tracing::debug!("launching the computation to {:?}", channel);
            let _response = client.launch_computation(request).await?;
            tracing::debug!("finished launching the computation to {:?}", channel);
        }

        Ok(())
    }
}
