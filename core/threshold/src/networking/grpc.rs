//! gRPC-based networking.

mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use super::constants::{
    MAX_ELAPSED_TIME, MAX_EN_DECODE_MESSAGE_SIZE, MAX_INTERVAL, MESSAGE_LIMIT, MULTIPLIER,
    NETWORK_TIMEOUT_ASYNC, NETWORK_TIMEOUT_BK, NETWORK_TIMEOUT_BK_SNS, NETWORK_TIMEOUT_LONG,
};
use super::sending_service::{GrpcSendingService, NetworkSession, SendingService};
use super::tls::{extract_subject_from_cert, SendingServiceTLSConfig};
use super::NetworkMode;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::{Identity, RoleAssignment};
use crate::networking::Networking;
use crate::session_id::SessionId;
use async_trait::async_trait;
use dashmap::DashMap;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::Duration;
use x509_parser::parse_x509_certificate;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(deny_unknown_fields)]
pub struct CoreToCoreNetworkConfig {
    pub message_limit: u64,
    pub multiplier: f64,
    pub max_interval: u64,
    pub max_elapsed_time: Option<u64>,
    pub network_timeout: u64,
    pub network_timeout_bk: u64,
    pub network_timeout_bk_sns: u64,
    pub max_en_decode_message_size: u64,
}

#[derive(Debug, Clone)]
pub struct OptionConfigWrapper {
    pub conf: Option<CoreToCoreNetworkConfig>,
}

impl OptionConfigWrapper {
    pub fn get_message_limit(&self) -> usize {
        if let Some(conf) = self.conf {
            conf.message_limit as usize
        } else {
            MESSAGE_LIMIT
        }
    }

    pub fn get_multiplier(&self) -> f64 {
        if let Some(conf) = self.conf {
            conf.multiplier
        } else {
            MULTIPLIER
        }
    }

    pub fn get_max_interval(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.max_interval)
        } else {
            *MAX_INTERVAL
        }
    }

    pub fn get_max_elapsed_time(&self) -> Option<Duration> {
        if let Some(conf) = self.conf {
            conf.max_elapsed_time.map(Duration::from_secs)
        } else {
            *MAX_ELAPSED_TIME
        }
    }

    pub fn get_network_timeout(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.network_timeout)
        } else {
            *NETWORK_TIMEOUT_LONG
        }
    }

    pub fn get_network_timeout_bk(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.network_timeout_bk)
        } else {
            *NETWORK_TIMEOUT_BK
        }
    }

    pub fn get_network_timeout_bk_sns(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.network_timeout_bk_sns)
        } else {
            *NETWORK_TIMEOUT_BK_SNS
        }
    }

    pub fn get_max_en_decode_message_size(&self) -> usize {
        if let Some(conf) = self.conf {
            conf.max_en_decode_message_size as usize
        } else {
            *MAX_EN_DECODE_MESSAGE_SIZE
        }
    }
}

//TODO: Most likely need this to create NetworkStack instead of GrpcNetworking
/// GrpcNetworkingManager is responsible for managing
/// channels and message queues between MPC parties.
#[derive(Debug, Clone)]
pub struct GrpcNetworkingManager {
    pub message_queues: Arc<MessageQueueStores>,
    owner: Identity,
    conf: OptionConfigWrapper,
    pub sending_service: GrpcSendingService,
}

pub type GrpcServer = GnetworkingServer<NetworkingImpl>;

impl GrpcNetworkingManager {
    /// Create a new server from the networking manager.
    /// The server can be used as a tower Service.
    pub fn new_server(&self) -> GnetworkingServer<impl Gnetworking> {
        GnetworkingServer::new(NetworkingImpl {
            message_queues: Arc::clone(&self.message_queues),
        })
        .max_decoding_message_size(self.conf.get_max_en_decode_message_size())
        .max_encoding_message_size(self.conf.get_max_en_decode_message_size())
    }

    /// Owner should be the external address
    pub fn new(
        owner: Identity,
        tls_conf: Option<SendingServiceTLSConfig>,
        conf: Option<CoreToCoreNetworkConfig>,
    ) -> anyhow::Result<Self> {
        Ok(GrpcNetworkingManager {
            message_queues: Default::default(),
            owner,
            conf: OptionConfigWrapper { conf },
            sending_service: GrpcSendingService::new(tls_conf, conf)?,
        })
    }

    /// Create a new session from the network manager.
    ///
    /// All the communication are performed using sessions.
    /// There may be multiple session in parallel,
    /// identified by different session IDs.
    pub fn make_session(
        &self,
        session_id: SessionId,
        roles: RoleAssignment,
        network_mode: NetworkMode,
    ) -> Arc<impl Networking> {
        let others = roles
            .iter()
            .filter_map(|(_role, identity)| {
                if identity != &self.owner {
                    Some(identity.clone())
                } else {
                    None
                }
            })
            .collect_vec();

        // Tell the sending service to spawns network threads to communicate wit the others
        let connection_channel = self.sending_service.add_connections(others).unwrap();

        // Create the message queue for this session id (this queue will be written to by the grpc server and read by the NetworkSession)
        let message_store = DashMap::new();
        for (_role, identity) in roles {
            let (tx, rx) = channel::<NetworkRoundValue>(self.conf.get_message_limit());
            message_store.insert(identity, (Arc::new(tx), Arc::new(Mutex::new(rx))));
        }
        let message_store = Arc::new(message_store);
        self.message_queues
            .insert(session_id, message_store.clone());

        let timeout = match network_mode {
            NetworkMode::Async => *NETWORK_TIMEOUT_ASYNC,
            NetworkMode::Sync => self.conf.get_network_timeout(),
        };
        Arc::new(NetworkSession {
            owner: self.owner.clone(),
            session_id,
            sending_channels: connection_channel,
            receiving_channels: message_store,
            round_counter: RwLock::new(0),
            network_mode,
            conf: self.conf.clone(),
            init_time: OnceLock::new(),
            current_network_timeout: RwLock::new(timeout),
            next_network_timeout: RwLock::new(timeout),
            max_elapsed_time: RwLock::new(Duration::ZERO),
            #[cfg(feature = "choreographer")]
            num_byte_sent: RwLock::new(0),
        })
    }
}

// we need a counter for each value sent over the local queues
// so that messages that haven't been pickup up using receive() calls will get dropped
#[derive(Debug)]
pub struct NetworkRoundValue {
    pub value: Vec<u8>,
    pub round_counter: usize,
}

pub(crate) type MessageQueueStore = DashMap<
    Identity,
    (
        Arc<Sender<NetworkRoundValue>>,
        Arc<Mutex<Receiver<NetworkRoundValue>>>,
    ),
>;
type MessageQueueStores = DashMap<SessionId, Arc<MessageQueueStore>>;

#[derive(Default)]
pub struct NetworkingImpl {
    message_queues: Arc<MessageQueueStores>,
}

// We do the measurement of received bytes here because
// some messages may never reach the application level
// (i.e. in the Networking trait)
#[cfg(feature = "choreographer")]
lazy_static::lazy_static! {
    pub static ref NETWORK_RECEIVED_MEASUREMENT: DashMap<SessionId,usize> =
        DashMap::new();
}

const NUM_RETRIES_FETCH_MESSAGE_QUEUE: usize = 50;
#[async_trait]
impl Gnetworking for NetworkingImpl {
    async fn send_value(
        &self,
        request: tonic::Request<SendValueRequest>,
    ) -> std::result::Result<tonic::Response<SendValueResponse>, tonic::Status> {
        // If TLS is enabled, A SAN may look like:
        // DNS:party1.com, IP Address:127.0.0.1, DNS:localhost, IP Address:192.168.0.1, IP Address:0:0:0:0:0:0:0:1
        // which is a collection of DNS names and IP addresses.
        // The DNS component must match the "tag" that's in the request for identity verification,
        // in this case it's party1.com.
        // We also require party1.com to be the subject and the issuer CN too,
        // since we're using self-signed certificates at the moment.
        let valid_tls_sender = request
            .peer_certs()
            .map(|certs| {
                if certs.len() != 1 {
                    // it shouldn't happen because we expect TLS certificates to
                    // be signed by party CA certificates directly, without any
                    // intermediate CAs
                    tracing::warn!(
                        "Received more than one certificate from peer, checking the first one only"
                    );
                }

                parse_x509_certificate(certs[0].as_ref())
                    .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))
                    .and_then(|(_rem, cert)| {
                        extract_subject_from_cert(&cert)
                            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))
                    })
            })
            .transpose()?;

        let request = request.into_inner();
        let tag = bincode::deserialize::<Tag>(&request.tag).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "failed to parse value".to_string())
        })?;

        #[cfg(feature = "choreographer")]
        {
            match NETWORK_RECEIVED_MEASUREMENT.entry(tag.session_id) {
                dashmap::Entry::Occupied(mut occupied_entry) => {
                    let entry = occupied_entry.get_mut();
                    *entry += request.tag.len() + request.value.len()
                }
                dashmap::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(request.tag.len() + request.value.len());
                }
            };
        }

        if let Some(sender) = valid_tls_sender {
            // tag.sender has the form hostname:port
            // we remove the port component since the tls_sender does not have it
            let host_and_port: Vec<_> = tag.sender.0.split(':').collect();
            if host_and_port.len() != 2 {
                return Err(tonic::Status::new(
                    tonic::Code::Unknown,
                    format!(
                        "wrong sender tag (could not split at ':'): {:?}",
                        tag.sender,
                    ),
                ));
            }
            let host = host_and_port[0];
            if sender != host {
                return Err(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    format!("wrong sender: expected {:?} to be in {:?}", host, sender),
                ));
            }
        } else {
            tracing::warn!("No valid TLS senders known.");
        }
        tracing::debug!("passed sender verification, tag is {:?}", tag);

        for _ in 0..NUM_RETRIES_FETCH_MESSAGE_QUEUE {
            if self.message_queues.contains_key(&tag.session_id) {
                let tx = self
                    .message_queues
                    .get(&tag.session_id)
                    .ok_or_else(|| {
                        anyhow_error_and_log("couldn't retrieve session store from message stores")
                    })
                    .map(|s| {
                        s.get(&tag.sender)
                            .ok_or_else(|| {
                                anyhow_error_and_log(
                                    "couldn't retrieve channels from session store",
                                )
                            })
                            .map(|s| s.value().0.clone())
                            .map_err(|e| tonic::Status::new(tonic::Code::NotFound, e.to_string()))
                    })
                    .map_err(|e| tonic::Status::new(tonic::Code::NotFound, e.to_string()))??;

                let _ = tx
                    .send(NetworkRoundValue {
                        value: request.value,
                        round_counter: tag.round_counter,
                    })
                    .await;
                return Ok(tonic::Response::new(SendValueResponse::default()));
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        }

        let msg = format!(
            "unknown session id {:?} for from sender {:?} (round {})",
            tag.session_id, tag.sender, tag.round_counter
        );
        tracing::error!(msg);
        Err(tonic::Status::new(tonic::Code::NotFound, msg))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Tag {
    session_id: SessionId,
    sender: Identity,
    round_counter: usize,
}
