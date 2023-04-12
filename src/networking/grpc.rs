//! gRPC-based choreography.

pub(crate) mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

// use self::gen::networking_client::NetworkingClient;
use self::gen::gnetworking_client::GnetworkingClient;
use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use crate::computation::SessionId;
use crate::execution::player::Identity;
use crate::networking::constants;
use crate::networking::Networking;
use crate::value::Value;
use anyhow::anyhow;
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use dashmap::mapref::one::RefMut;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::*;
use tonic::codegen::http::Uri;
use tonic::transport::Channel;

#[derive(Default)]
pub struct GrpcNetworkingManager {
    channels: Arc<Channels>,
    own_send_channels: Arc<SessionSendStores>,
    own_recv_channels: Arc<SessionRecvStores>,
}

impl GrpcNetworkingManager {
    pub fn new_server(&self) -> GnetworkingServer<impl Gnetworking> {
        GnetworkingServer::new(NetworkingImpl {
            send_stores: Arc::clone(&self.own_send_channels),
            recv_stores: Arc::clone(&self.own_recv_channels),
        })
    }

    pub fn without_tls() -> Self {
        GrpcNetworkingManager {
            channels: Default::default(),
            own_send_channels: Default::default(),
            own_recv_channels: Default::default(),
        }
    }

    pub fn new_session(&self, session_id: SessionId) -> Arc<impl Networking> {
        Arc::new(GrpcNetworking {
            session_id,
            channels: Arc::clone(&self.channels),
            send_channels: Arc::clone(&self.own_send_channels),
            recv_channels: Arc::clone(&self.own_recv_channels),
        })
    }
}

pub struct GrpcNetworking {
    session_id: SessionId,
    channels: Arc<Channels>,
    send_channels: Arc<SessionSendStores>,
    recv_channels: Arc<SessionRecvStores>,
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

    async fn receive(&self, sender: &Identity, session_id: &SessionId) -> anyhow::Result<Value> {
        let mut cell = cell_receive(&self.send_channels, &self.recv_channels, session_id);
        let (actual_sender, value) = cell
            .value_mut()
            .recv()
            .await
            .ok_or(anyhow!("Couldn't receive data from local channel"))?;

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
type SessionSendStores = DashMap<SessionId, Arc<UnboundedSender<AuthValue>>>;
type SessionRecvStores = DashMap<SessionId, UnboundedReceiver<AuthValue>>;
type Channels = DashMap<Identity, Channel>;

#[derive(Default)]
struct NetworkingImpl {
    pub send_stores: Arc<SessionSendStores>,
    pub recv_stores: Arc<SessionRecvStores>,
}

fn cell_send(
    send_channels: &Arc<SessionSendStores>,
    recv_channels: &Arc<SessionRecvStores>,
    session_id: &SessionId,
) -> Arc<UnboundedSender<AuthValue>> {
    let cell = send_channels
        .entry(session_id.clone())
        .or_insert_with(|| {
            let (tx, rx) = mpsc::unbounded_channel::<AuthValue>();
            recv_channels.insert(session_id.clone(), rx);
            tracing::debug!(
                "I have created a new channel pair for session: {:?} inside sending",
                session_id
            );
            Arc::new(tx)
        })
        .clone();
    cell
}
fn cell_receive<'a>(
    send_channels: &'a Arc<SessionSendStores>,
    recv_channels: &'a Arc<SessionRecvStores>,
    session_id: &SessionId,
) -> RefMut<'a, SessionId, UnboundedReceiver<AuthValue>> {
    let cell = recv_channels.entry(session_id.clone()).or_insert_with(|| {
        let (tx, rx) = mpsc::unbounded_channel::<AuthValue>();
        send_channels.insert(session_id.clone(), Arc::new(tx));
        tracing::debug!(
            "I have created a new channel pair for session: {:?}, inside receiving",
            session_id
        );
        rx
    });
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

        let cell = cell_send(
            &self.send_stores,
            &self.recv_stores,
            &tagged_value.session_id,
        );

        let _ = cell.send((sender, tagged_value.value));

        // TODO(Dragos) why does this end up in a deadlock?
        // tracing::info!(
        //     "I have sent the message to local queue: {:?} {:?}",
        //     &self.send_stores,
        //     &self.recv_stores
        // );

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
    value: Value,
}
