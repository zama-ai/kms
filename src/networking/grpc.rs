//! gRPC-based networking.

mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

use self::gen::gnetworking_client::GnetworkingClient;
use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use crate::computation::SessionId;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::party::{Identity, RoleAssignment};
use crate::networking::constants;
use crate::networking::Networking;
use crate::value::NetworkValue;
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;
use tonic::codegen::http::Uri;
use tonic::transport::Channel;

use super::constants::MESSAGE_LIMIT;

pub struct GrpcNetworkingManager {
    channels: Arc<Channels>,
    message_queues: Arc<MessageQueueStores>,
    owner: Identity,
}

impl GrpcNetworkingManager {
    pub fn new_server(&self) -> GnetworkingServer<impl Gnetworking> {
        GnetworkingServer::new(NetworkingImpl {
            message_queues: Arc::clone(&self.message_queues),
        })
    }

    pub fn without_tls(owner: Identity) -> Self {
        GrpcNetworkingManager {
            channels: Default::default(),
            message_queues: Default::default(),
            owner,
        }
    }

    pub fn new_session(
        &self,
        session_id: SessionId,
        roles: RoleAssignment,
    ) -> Arc<impl Networking> {
        let message_store = DashMap::new();
        for (_role, identity) in roles {
            let (tx, rx) = async_channel::bounded(MESSAGE_LIMIT);
            message_store.insert(identity, (Arc::new(tx), Arc::new(rx)));
        }
        self.message_queues
            .insert(session_id, Arc::new(message_store));
        Arc::new(GrpcNetworking {
            session_id,
            channels: Arc::clone(&self.channels),
            message_queues: Arc::clone(&self.message_queues),
            network_round: Arc::new(Mutex::new(0)),
            owner: self.owner.clone(),
        })
    }
}

pub struct GrpcNetworking {
    session_id: SessionId,
    channels: Arc<Channels>,
    message_queues: Arc<MessageQueueStores>,
    network_round: Arc<Mutex<usize>>,
    owner: Identity,
}

impl GrpcNetworking {
    fn channel(&self, receiver: &Identity) -> anyhow::Result<Channel> {
        let channel: Channel = self
            .channels
            .entry(receiver.clone())
            .or_try_insert_with(|| {
                tracing::debug!("Creating channel to '{}'", receiver);
                let endpoint: Uri = format!("http://{}", receiver).parse().map_err(|_e| {
                    anyhow_error_and_log(format!(
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
        value: NetworkValue,
        receiver: &Identity,
        _session_id: &SessionId,
    ) -> anyhow::Result<(), anyhow::Error> {
        let ctr: usize = *self
            .network_round
            .lock()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;

        retry(
            ExponentialBackoff {
                max_elapsed_time: *constants::MAX_ELAPSED_TIME,
                max_interval: *constants::MAX_INTERVAL,
                multiplier: constants::MULTIPLIER,
                ..Default::default()
            },
            || async {
                let tagged_value = TaggedValue {
                    value: value.clone(),
                    sender: self.owner.clone(),
                    session_id: self.session_id,
                    round_counter: ctr,
                };

                let bytes = bincode::serialize(&tagged_value).map_err(|e| {
                    anyhow_error_and_log(format!("networking error: {:?}", e.to_string()))
                })?;
                let request = SendValueRequest {
                    tagged_value: bytes,
                };
                let channel = self.channel(receiver)?;
                let mut client = GnetworkingClient::new(channel);
                tracing::debug!(
                    "Sending '{:?}' to {:?}, session_id {:?}",
                    value,
                    receiver,
                    self.session_id
                );
                let _response = client.send_value(request).await.map_err(|e| {
                    anyhow_error_and_log(format!("networking error: {:?}", e.to_string()))
                })?;

                Ok(())
            },
        )
        .await
    }

    async fn receive(
        &self,
        sender: &Identity,
        _session_id: &SessionId,
    ) -> anyhow::Result<NetworkValue> {
        if !self.message_queues.contains_key(&self.session_id) {
            return Err(anyhow_error_and_log(
                "Did not have session id key for message storage inside receive call".to_string(),
            ));
        }

        let session_store = self.message_queues.get(&self.session_id).ok_or_else(|| {
            anyhow_error_and_log("couldn't retrieve channels from store".to_string())
        })?;

        let channels = session_store.get(sender).ok_or_else(|| {
            anyhow_error_and_log("couldn't retrieve session store from message stores".to_string())
        })?;
        let (_, rx) = channels.value();

        tracing::debug!("Waiting to receive from {:?}", sender);

        let network_round: usize = *self
            .network_round
            .lock()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;

        let mut local_packet = rx.recv().await?;

        // drop old messages
        while local_packet.round_counter < network_round {
            tracing::debug!("Dropped value: {:?}", local_packet);
            local_packet = rx.recv().await?;
        }

        Ok(local_packet.value)
    }

    async fn increase_round_counter(&self) -> anyhow::Result<()> {
        if let Ok(mut net_round) = self.network_round.lock() {
            *net_round += 1;
            tracing::debug!("changed network round to: {:?}", *net_round);
        } else {
            return Err(anyhow_error_and_log("Couldn't lock mutex".to_string()));
        }
        Ok(())
    }
}

// we need a counter for each value sent over the local queues
// so that messages that haven't been pickup up using receive() calls will get dropped
#[derive(Debug)]
struct NetworkRoundValue {
    pub value: NetworkValue,
    pub round_counter: usize,
}

type Channels = DashMap<Identity, Channel>;
type MessageQueueStore = DashMap<
    Identity,
    (
        Arc<async_channel::Sender<NetworkRoundValue>>,
        Arc<async_channel::Receiver<NetworkRoundValue>>,
    ),
>;
type MessageQueueStores = DashMap<SessionId, Arc<MessageQueueStore>>;

#[derive(Default)]
struct NetworkingImpl {
    pub message_queues: Arc<MessageQueueStores>,
}

#[async_trait]
impl Gnetworking for NetworkingImpl {
    async fn send_value(
        &self,
        request: tonic::Request<SendValueRequest>,
    ) -> std::result::Result<tonic::Response<SendValueResponse>, tonic::Status> {
        let tls_sender = extract_sender(&request)
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e))?
            .map(Identity::from);

        let request = request.into_inner();
        let tagged_value =
            bincode::deserialize::<TaggedValue>(&request.tagged_value).map_err(|_e| {
                tonic::Status::new(tonic::Code::Aborted, "failed to parse value".to_string())
            })?;

        if let Some(sender) = tls_sender {
            if tagged_value.sender != sender {
                return Err(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    format!(
                        "wrong sender: expected {:?} but got {:?}",
                        tagged_value.sender, sender
                    ),
                ));
            }
        }

        if self.message_queues.contains_key(&tagged_value.session_id) {
            let session_store = self
                .message_queues
                .get(&tagged_value.session_id)
                .ok_or_else(|| {
                    anyhow_error_and_log(
                        "couldn't retrieve session store from message stores".to_string(),
                    )
                })
                .map_err(|e| tonic::Status::new(tonic::Code::NotFound, e.to_string()))?;

            let channels = session_store
                .get(&tagged_value.sender)
                .ok_or_else(|| {
                    anyhow_error_and_log(
                        "couldn't retrieve channels from session store".to_string(),
                    )
                })
                .map_err(|e| tonic::Status::new(tonic::Code::NotFound, e.to_string()))?;

            let (tx, _) = channels.value();

            let _ = tx
                .send(NetworkRoundValue {
                    value: tagged_value.value,
                    round_counter: tagged_value.round_counter,
                })
                .await;

            Ok(tonic::Response::new(SendValueResponse::default()))
        } else {
            Err(tonic::Status::new(
                tonic::Code::NotFound,
                "unknown session id".to_string(),
            ))
        }
    }
}

fn extract_sender<T>(request: &tonic::Request<T>) -> Result<Option<String>, String> {
    match request.peer_certs() {
        None => Ok(None),
        Some(certs) => {
            if certs.len() != 1 {
                anyhow_error_and_log(format!(
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
    sender: Identity,
    value: NetworkValue,
    round_counter: usize,
}
