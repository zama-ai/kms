//! gRPC-based choreography.

pub(crate) mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

// use self::gen::networking_client::NetworkingClient;
use self::gen::gnetworking_client::GnetworkingClient;
use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use crate::computation::{RendezvousKey, SessionId};
use crate::execution::player::Identity;
use crate::networking::constants;
use crate::networking::Networking;
use crate::value::Value;
use anyhow::anyhow;
use async_cell::sync::AsyncCell;
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tonic::codegen::http::Uri;
use tonic::transport::Channel;

#[derive(Default)]
pub struct GrpcNetworkingManager {
    channels: Arc<Channels>,
    stores: Arc<SessionStores>,
}

impl GrpcNetworkingManager {
    pub fn new_server(&self) -> GnetworkingServer<impl Gnetworking> {
        GnetworkingServer::new(NetworkingImpl {
            stores: Arc::clone(&self.stores),
        })
    }

    pub fn without_tls() -> Self {
        GrpcNetworkingManager {
            channels: Default::default(),
            stores: Default::default(),
        }
    }

    pub fn new_session(&self, session_id: SessionId) -> Arc<impl Networking> {
        Arc::new(GrpcNetworking {
            session_id,
            channels: Arc::clone(&self.channels),
            stores: Arc::clone(&self.stores),
        })
    }
}

pub struct GrpcNetworking {
    session_id: SessionId,
    channels: Arc<Channels>,
    stores: Arc<SessionStores>,
}

impl GrpcNetworking {
    fn channel(&self, receiver: &Identity) -> anyhow::Result<Channel> {
        let channel = self
            .channels
            .entry(receiver.clone())
            .or_try_insert_with(|| {
                tracing::debug!("Creating channel to '{}'", receiver);
                let endpoint: Uri = format!("http://{}", receiver).parse().map_err(|_e| {
                    anyhow!(format!(
                        "failed to parse identity as endpoint: {:?}",
                        receiver
                    ))
                })?;
                let channel = Channel::builder(endpoint);
                Ok::<Channel, anyhow::Error>(channel.connect_lazy())
            })?
            .clone(); // cloning channels is cheap per tonic documentation
        Ok(channel)
    }
}

#[async_trait]
impl Networking for GrpcNetworking {
    async fn send(
        &self,
        val: &Value,
        receiver: &Identity,
        rendezvous_key: &RendezvousKey,
        _session_id: &SessionId,
    ) -> anyhow::Result<(), anyhow::Error> {
        retry(
            ExponentialBackoff {
                max_elapsed_time: *constants::MAX_ELAPSED_TIME,
                max_interval: *constants::MAX_INTERVAL,
                multiplier: constants::MULTIPLIER,
                ..Default::default()
            },
            || async {
                let tagged_value = TaggedValue {
                    session_id: self.session_id.clone(),
                    value: val.clone(),
                    rendezvous_key: rendezvous_key.clone(),
                };
                let bytes = bincode::serialize(&tagged_value)
                    .map_err(|e| anyhow!("networking error: {:?}", e.to_string()))?;
                let request = SendValueRequest {
                    tagged_value: bytes,
                };
                let channel = self.channel(receiver)?;
                let mut client = GnetworkingClient::new(channel);
                tracing::debug!(
                    "Sending '{:?}' to {:?}, session_id {:?}",
                    val,
                    receiver,
                    self.session_id
                );
                let _response = client
                    .send_value(request)
                    .await
                    .map_err(|e| anyhow!("networking error: {:?}", e.to_string()))?;
                Ok(())
            },
        )
        .await
    }

    async fn receive(
        &self,
        sender: &Identity,
        rendezvous_key: &RendezvousKey,
        session_id: &SessionId,
    ) -> anyhow::Result<Value> {
        let cell = cell(&self.stores, session_id.clone(), rendezvous_key.clone());
        let (actual_sender, value) = cell.take().await;

        match actual_sender {
            Some(actual_sender) => {
                if *sender != actual_sender {
                    Err(anyhow!(
                        "wrong sender: expected {:?} but got {:?}",
                        sender,
                        actual_sender
                    ))
                } else {
                    tracing::debug!("Received '{:?}' from {}", value, sender);
                    Ok(value)
                }
            }
            None => {
                tracing::debug!("Received '{:?}' from {}", value, sender);
                Ok(value)
            }
        }
    }
}

type AuthValue = (Option<Identity>, Value);
type SessionStore = DashMap<RendezvousKey, Arc<AsyncCell<AuthValue>>>;
type SessionStores = DashMap<SessionId, Arc<SessionStore>>;
type Channels = DashMap<Identity, Channel>;

#[derive(Default)]
struct NetworkingImpl {
    pub stores: Arc<SessionStores>,
}

fn cell(
    stores: &Arc<SessionStores>,
    session_id: SessionId,
    rendezvous_key: RendezvousKey,
) -> Arc<AsyncCell<AuthValue>> {
    let session_store = stores
        .entry(session_id)
        .or_insert_with(Arc::default)
        .value()
        .clone();

    let cell = session_store
        .entry(rendezvous_key)
        .or_insert_with(AsyncCell::shared)
        .value()
        .clone();

    cell
}

#[async_trait]
impl Gnetworking for NetworkingImpl {
    async fn send_value(
        &self,
        request: tonic::Request<SendValueRequest>,
    ) -> std::result::Result<tonic::Response<SendValueResponse>, tonic::Status> {
        let sender = extract_sender(&request)
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e))?
            .map(Identity::from);

        let request = request.into_inner();
        let tagged_value =
            bincode::deserialize::<TaggedValue>(&request.tagged_value).map_err(|_e| {
                tonic::Status::new(tonic::Code::Aborted, "failed to parse value".to_string())
            })?;

        let cell = cell(
            &self.stores,
            tagged_value.session_id,
            tagged_value.rendezvous_key,
        );

        cell.set((sender, tagged_value.value));

        Ok(tonic::Response::new(SendValueResponse::default()))
    }
}

fn extract_sender<T>(request: &tonic::Request<T>) -> Result<Option<String>, String> {
    match request.peer_certs() {
        None => Ok(None),
        Some(certs) => {
            if certs.len() != 1 {
                return Err(format!(
                    "cannot extract identity from certificate chain of length {:?}",
                    certs.len()
                ));
            }

            let (_rem, cert) =
                x509_parser::parse_x509_certificate(certs[0].as_ref()).map_err(|err| {
                    format!("failed to parse X509 certificate: {:?}", err.to_string())
                })?;

            let cns: Vec<_> = cert
                .subject()
                .iter_common_name()
                .map(|attr| attr.as_str().map_err(|err| err.to_string()))
                .collect::<Result<_, _>>()?;

            if let Some(cn) = cns.first() {
                Ok(Some(cn.to_string()))
            } else {
                Err("certificate common name was empty".to_string())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TaggedValue {
    session_id: SessionId,
    rendezvous_key: RendezvousKey,
    value: Value,
}
