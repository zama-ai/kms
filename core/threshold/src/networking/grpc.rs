//! gRPC-based networking.

mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use super::sending_service::{GrpcSendingService, NetworkSession, SendingService};
use super::tls::extract_subject_from_cert;
use super::NetworkMode;
use crate::networking::constants::{
    DISCARD_INACTIVE_SESSION_INTERVAL_SECS, INITIAL_INTERVAL_MS, MAX_ELAPSED_TIME,
    MAX_EN_DECODE_MESSAGE_SIZE, MAX_INTERVAL, MAX_OPENED_INACTIVE_SESSIONS_PER_PARTY,
    MAX_WAITING_TIME_MESSAGE_QUEUE, MESSAGE_LIMIT, MULTIPLIER, NETWORK_TIMEOUT_ASYNC,
    NETWORK_TIMEOUT_BK, NETWORK_TIMEOUT_BK_SNS, NETWORK_TIMEOUT_LONG,
    SESSION_CLEANUP_INTERVAL_SECS, SESSION_STATUS_UPDATE_INTERVAL_SECS,
};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::{Identity, Role, RoleAssignment};
use crate::networking::Networking;
use crate::session_id::SessionId;
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock, Weak};

use tokio::time::{Duration, Instant};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex, RwLock,
};

use tonic::transport::server::TcpConnectInfo;
use tonic::transport::CertificateDer;
use x509_parser::parse_x509_certificate;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(deny_unknown_fields)]
pub struct CoreToCoreNetworkConfig {
    pub message_limit: u64,
    pub multiplier: f64,
    pub max_interval: u64,
    pub max_elapsed_time: Option<u64>,
    /// Initial interval for exponential backoff in milliseconds (default: 1000ms)
    pub initial_interval_ms: Option<u64>,
    pub network_timeout: u64,
    pub network_timeout_bk: u64,
    pub network_timeout_bk_sns: u64,
    pub max_en_decode_message_size: u64,
    /// Background interval for updating session status (default: 60)
    pub session_update_interval_secs: Option<u64>,
    /// Background interval for cleaning up completed sessions (default: 3600)
    pub session_cleanup_interval_secs: Option<u64>,
    /// Background interval for discarding inactive sessions (default: 900)
    pub discard_inactive_sessions_interval: Option<u64>,
    /// Maximum waiting time for trying to push the message in the queue (default: 60 seconds)
    pub max_waiting_time_for_message_queue: Option<u64>,
    /// Maximum number of "Inactive" sessions a party can open before I refuse to open more (default: 100)
    pub max_opened_inactive_sessions_per_party: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
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

    pub fn get_initial_interval(&self) -> Duration {
        if let Some(conf) = self.conf {
            if let Some(initial_interval_ms) = conf.initial_interval_ms {
                Duration::from_millis(initial_interval_ms)
            } else {
                Duration::from_millis(INITIAL_INTERVAL_MS)
            }
        } else {
            Duration::from_millis(INITIAL_INTERVAL_MS)
        }
    }

    pub fn get_session_update_interval(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(
                conf.session_update_interval_secs
                    .unwrap_or(SESSION_STATUS_UPDATE_INTERVAL_SECS),
            )
        } else {
            Duration::from_secs(SESSION_STATUS_UPDATE_INTERVAL_SECS)
        }
    }

    pub fn get_session_cleanup_interval(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(
                conf.session_cleanup_interval_secs
                    .unwrap_or(SESSION_CLEANUP_INTERVAL_SECS),
            )
        } else {
            Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS)
        }
    }

    pub fn get_discard_inactive_sessions_interval(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(
                conf.discard_inactive_sessions_interval
                    .unwrap_or(DISCARD_INACTIVE_SESSION_INTERVAL_SECS),
            )
        } else {
            Duration::from_secs(DISCARD_INACTIVE_SESSION_INTERVAL_SECS)
        }
    }

    pub fn get_max_opened_inactive_sessions_per_party(&self) -> u64 {
        if let Some(conf) = self.conf {
            conf.max_opened_inactive_sessions_per_party
                .unwrap_or(MAX_OPENED_INACTIVE_SESSIONS_PER_PARTY)
        } else {
            MAX_OPENED_INACTIVE_SESSIONS_PER_PARTY
        }
    }

    pub fn get_max_waiting_time_for_message_queue(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(
                conf.max_waiting_time_for_message_queue
                    .unwrap_or(MAX_WAITING_TIME_MESSAGE_QUEUE),
            )
        } else {
            Duration::from_secs(MAX_WAITING_TIME_MESSAGE_QUEUE) // Default to 60 seconds if not specified
        }
    }
}

//TODO: Most likely need this to create NetworkStack instead of GrpcNetworking
/// GrpcNetworkingManager is responsible for managing
/// channels and message queues between MPC parties.
#[derive(Debug, Clone)]
pub struct GrpcNetworkingManager {
    // Session reference storage to prevent premature cleanup under high concurrency
    pub session_store: Arc<SessionStore>,
    // Keeps tracks of how many sessions were opened by each party
    // NOTE: Always lock session_store before opened_sessions_tracker to prevent deadlocks
    pub opened_sessions_tracker: Arc<DashMap<Role, u64>>,
    owner: Role,
    conf: OptionConfigWrapper,
    pub sending_service: GrpcSendingService,
    #[cfg(feature = "testing")]
    pub force_tls: bool,
}

pub type GrpcServer = GnetworkingServer<NetworkingImpl>;

impl GrpcNetworkingManager {
    /// Create a new server from the networking manager.
    /// The server can be used as a tower Service.
    pub fn new_server(
        &self,
        tls_extension: TlsExtensionGetter,
    ) -> GnetworkingServer<NetworkingImpl> {
        GnetworkingServer::new(NetworkingImpl::new(
            Arc::clone(&self.session_store),
            Arc::clone(&self.opened_sessions_tracker),
            self.conf.get_message_limit(),
            self.conf.get_max_opened_inactive_sessions_per_party(),
            self.conf.get_max_waiting_time_for_message_queue(),
            tls_extension,
            #[cfg(feature = "testing")]
            self.force_tls,
        ))
        .max_decoding_message_size(self.conf.get_max_en_decode_message_size())
        .max_encoding_message_size(self.conf.get_max_en_decode_message_size())
    }

    /// Starts a background task that periodically cleans up the session store, it wakes up at every update_interval.
    ///
    /// The task discards sessions that have been completed for longer than the cleanup interval
    /// and inactive session that have been inactive for longer than the discard_inactive_interval.
    ///
    /// It also updates the status of active sessions by checking if their weak references are still valid,
    /// and if not, marks them as completed.
    fn start_background_cleaning_task(
        session_store: Arc<SessionStore>,
        update_interval: Duration,
        cleanup_interval: Duration,
        discard_inactive_interval: Duration,
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(update_interval);
            loop {
                interval.tick().await;

                session_store.retain(|session_id, status| match status {
                    SessionStatus::Completed(started) => started.elapsed() < cleanup_interval,
                    SessionStatus::Inactive((_, started)) => {
                        if started.elapsed() > discard_inactive_interval {
                            tracing::warn!(
                                "Discarding Inactive session {:?} after {:?} seconds. We never heard about such session.",
                                session_id,
                                started.elapsed().as_secs()
                            );
                            false
                        } else {
                            true
                        }
                    }
                    SessionStatus::Active(session) => {
                        if session.upgrade().is_none() {
                            *status = SessionStatus::Completed(Instant::now());
                        }
                        true
                    }
                });
            }
        });
    }

    /// Owner should be the external address
    pub fn new(
        owner: Role,
        tls_conf: Option<tokio_rustls::rustls::client::ClientConfig>,
        conf: Option<CoreToCoreNetworkConfig>,
        peer_tcp_proxy: bool,
        role_assignment: Arc<RwLock<RoleAssignment>>,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "testing")]
        let force_tls = tls_conf.is_some();

        #[cfg(not(feature = "testing"))]
        if tls_conf.is_none() {
            return Err(crate::error::error_handler::anyhow_error_and_log(
                "TLS configuration must be provided in non-testing environments",
            ));
        }

        let conf = OptionConfigWrapper { conf };
        let session_store = Arc::new(SessionStore::default());

        // We need to spawn background cleanup task to remove dead weak references from session_store, otherwise they accumulate and eat RAM + perf
        let cleanup_session_store = Arc::clone(&session_store);
        let update_interval = conf.get_session_update_interval();
        let cleanup_interval = conf.get_session_cleanup_interval();
        let discard_inactive_interval = conf.get_discard_inactive_sessions_interval();
        Self::start_background_cleaning_task(
            cleanup_session_store,
            update_interval,
            cleanup_interval,
            discard_inactive_interval,
        );

        Ok(GrpcNetworkingManager {
            session_store,
            opened_sessions_tracker: Arc::new(DashMap::new()),
            owner,
            conf,
            sending_service: GrpcSendingService::new(tls_conf, conf, peer_tcp_proxy,
                role_assignment)?,
            #[cfg(feature = "testing")]
            force_tls,
        })
    }

    /// Create a new session from the network manager.
    ///
    /// All the communication are performed using sessions.
    /// There may be multiple session in parallel,
    /// identified by different session IDs.
    pub async fn make_session(
        &self,
        session_id: SessionId,
        role_assignment: Arc<RwLock<RoleAssignment>>,
        network_mode: NetworkMode,
    ) -> anyhow::Result<Arc<impl Networking>> {
        let role_assignment = role_assignment.read().await;

        let others = role_assignment
            .iter()
            .filter_map(|(role, _identity)| {
                if *role != self.owner {
                    Some(role)
                } else {
                    None
                }
            })
            .cloned()
            .collect_vec();
        }

        let timeout = match network_mode {
            NetworkMode::Async => *NETWORK_TIMEOUT_ASYNC,
            NetworkMode::Sync => self.conf.get_network_timeout(),
        };

        let session = match self.session_store.entry(session_id) {
            // Turn an inactive session into an active one
            dashmap::Entry::Occupied(mut status) => {
                let mutable_status = status.get_mut();

                let message_store = if let SessionStatus::Inactive(message_store) = mutable_status {
                    message_store.clone()
                } else {
                    return Err(anyhow::anyhow!(
                        "Session {:?} already exists and is not inactive for {}",
                        session_id,
                        self.owner
                    ));
                };

                message_store.0.retain(|other_identity,_| {
                    if !others.contains(other_identity) {
                        tracing::warn!(
                            "Session {:?} already has a message queue for {:?}, but it is not in the roles list.",
                            session_id,
                            other_identity
                        );
                        false
                    } else {
                        //NOTE: I hold the session store write lock here, so this is safe
                        self.opened_sessions_tracker
                            .entry(other_identity.clone())
                            .and_modify(|count| {*count = count.saturating_sub(1);})
                            .or_insert(0);
                        true
                    }
                });

                for identity in others.iter() {
                    if !message_store.0.contains_key(identity) {
                        let (tx, rx) = channel::<NetworkRoundValue>(self.conf.get_message_limit());
                        message_store
                            .0
                            .insert(identity.clone(), (Arc::new(tx), Arc::new(Mutex::new(rx))));
                    }
                }

                let connection_channel = self.sending_service.add_connections(others)?;

                let session = Arc::new(NetworkSession {
                    owner: self.owner.clone(),
                    session_id,
                    sending_channels: connection_channel,
                    receiving_channels: message_store.0,
                    round_counter: tokio::sync::RwLock::new(0),
                    network_mode,
                    conf: self.conf,
                    init_time: OnceLock::new(),
                    current_network_timeout: RwLock::new(timeout),
                    next_network_timeout: RwLock::new(timeout),
                    max_elapsed_time: RwLock::new(Duration::ZERO),
                    #[cfg(feature = "choreographer")]
                    num_byte_sent: RwLock::new(0),
                });

                *mutable_status = SessionStatus::Active(Arc::downgrade(&session));

                session
            }
            dashmap::Entry::Vacant(vacant) => {
                let message_store = DashMap::with_capacity(party_count);
                for identity in others.iter() {
                    let (tx, rx) = channel::<NetworkRoundValue>(self.conf.get_message_limit());
                    message_store
                        .insert(identity.clone(), (Arc::new(tx), Arc::new(Mutex::new(rx))));
                }

                let connection_channel = self.sending_service.add_connections(others)?;

                let session = Arc::new(NetworkSession {
                    owner: self.owner.clone(),
                    session_id,
                    sending_channels: connection_channel,
                    receiving_channels: message_store,
                    round_counter: tokio::sync::RwLock::new(0),
                    network_mode,
                    conf: self.conf,
                    init_time: OnceLock::new(),
                    current_network_timeout: RwLock::new(timeout),
                    next_network_timeout: RwLock::new(timeout),
                    max_elapsed_time: RwLock::new(Duration::ZERO),
                    #[cfg(feature = "choreographer")]
                    num_byte_sent: RwLock::new(0),
                });

                vacant.insert(SessionStatus::Active(Arc::downgrade(&session)));

                session
            }
        };

        tracing::info!(
            "[SESSION_CREATION] Starting session {:?} with {} parties. (Owner: {:?})",
            session_id,
            party_count,
            self.owner
        );

        Ok(session)
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
    Role,
    (
        Identity,
        Arc<Sender<NetworkRoundValue>>,
        Arc<Mutex<Receiver<NetworkRoundValue>>>,
    ),
>;

pub(crate) type SessionStore = DashMap<SessionId, SessionStatus>;

#[derive(Debug)]
/// Represents the status of a session in the session store.
/// It can be:
/// - Completed: The session has been completed and the timestamp of completion is stored.
/// - Inactive: The session is inactive (I haven't yet heard about the request) and has a message queue store for senders.
/// - Active: The session is active (I know about the request) and holds a weak reference to the `NetworkSession`.
pub enum SessionStatus {
    Completed(Instant),
    Inactive((MessageQueueStore, Instant)),
    Active(Weak<NetworkSession>),
}

// Because we can use a custom TCP Incoming, we need to specify how
// to extract the TLS extension from the incoming connection
#[derive(Default)]
pub enum TlsExtensionGetter {
    #[default]
    TlsConnectInfo,
    SslConnectInfo,
}

#[derive(Default)]
pub struct NetworkingImpl {
    session_store: Arc<SessionStore>,
    opened_sessions_tracker: Arc<DashMap<Identity, u64>>,
    channel_size_limit: usize,
    max_opened_inactive_sessions: u64,
    max_waiting_time_for_message_queue: Duration,
    tls_extension: TlsExtensionGetter,
    // We gate this behind the testing feature because in non-testing environments
    // we want to ALWAYS use TLS for security reasons.
    #[cfg(feature = "testing")]
    force_tls: bool,
}

impl NetworkingImpl {
    pub fn new(
        session_store: Arc<SessionStore>,
        opened_sessions_tracker: Arc<DashMap<Identity, u64>>,
        channel_size_limit: usize,
        max_opened_inactive_sessions: u64,
        max_waiting_time_for_message_queue: Duration,
        tls_extension: TlsExtensionGetter,
        #[cfg(feature = "testing")] force_tls: bool,
    ) -> Self {
        Self {
            session_store: session_store.clone(),
            opened_sessions_tracker: opened_sessions_tracker.clone(),
            channel_size_limit,
            max_opened_inactive_sessions,
            max_waiting_time_for_message_queue,
            tls_extension,
            #[cfg(feature = "testing")]
            force_tls,
        }
    }

    // Did not find a better soluton yet.
    // See https://github.com/hyperium/tonic/issues/2253
    #[allow(clippy::result_large_err)]
    /// Fetches the channel for the given session and tag.
    /// - If the session is inactive, it creates a new channel for the sender (assuming the sender hasn't opened too many channels for inactive sessions yet).
    /// - If the session is active, it returns the existing channel (assuming the sender is part of the session).
    /// - If the session is completed, it returns None
    ///   to indicate that the message can be accepted but will not be processed.
    fn fetch_tx_channel(
        &self,
        session_status: &SessionStatus,
        tag: &Tag,
    ) -> Result<Option<Arc<Sender<NetworkRoundValue>>>, tonic::Status> {
        match session_status {
            SessionStatus::Completed(_) => {
                tracing::debug!(
                        "Session {:?} found in session_store but is completed. Will be removed by background cleanup.",
                        tag.session_id
                    );
                // We accept the message even if we won't do anything with it
                // to avoid blocking the sender
                Ok(None)
            }

            SessionStatus::Inactive(message_queue) => {
                tracing::debug!(
                    "Session {:?} found in session_store but is inactive.",
                    tag.session_id
                );
                match message_queue.0.entry(tag.sender.clone()) {
                    dashmap::Entry::Occupied(occupied_entry) => {
                        Ok(Some(occupied_entry.get().0.clone()))
                    }
                    dashmap::Entry::Vacant(vacant_entry) => {
                        let mut opened_session_tracker_entry = self
                            .opened_sessions_tracker
                            .entry(tag.sender.clone())
                            .or_insert(0);
                        if *opened_session_tracker_entry >= self.max_opened_inactive_sessions {
                            tracing::warn!(
                                "Too many inactive sessions opened by {:?}. Have {}, Max allowed: {}",
                                tag.sender,
                                *opened_session_tracker_entry,
                                self.max_opened_inactive_sessions
                            );
                            return Err(tonic::Status::new(
                                tonic::Code::ResourceExhausted,
                                format!(
                                    "Too many inactive sessions opened by {:?}. Have {}, Max allowed: {}",
                                    tag.sender, *opened_session_tracker_entry, self.max_opened_inactive_sessions
                                ),
                            ));
                        }
                        // Create a new channel for the sender
                        let (tx, rx) = channel::<NetworkRoundValue>(self.channel_size_limit);
                        let tx = Arc::new(tx);
                        vacant_entry.insert((Arc::clone(&tx), Arc::new(Mutex::new(rx))));

                        // Update the opened sessions tracker
                        *opened_session_tracker_entry += 1;
                        Ok(Some(tx))
                    }
                }
            }
            // Session is active, we can proceed with sending the message
            SessionStatus::Active(weak_session) => {
                tracing::debug!(
                    "Session {:?} found in session_store and is active.",
                    tag.session_id
                );
                // Attempt to upgrade weak reference to strong reference
                if let Some(session) = weak_session.upgrade() {
                    // Get the message queue from the session's receiving channels
                    if let Some(session_store) = session.receiving_channels.get(&tag.sender) {
                        Ok(Some(session_store.value().0.clone()))
                    } else {
                        let available_senders: Vec<_> = session
                            .receiving_channels
                            .iter()
                            .map(|entry| entry.key().clone())
                            .collect();

                        tracing::warn!(
                            "Sender {:?} not found in session {:?}. Available senders: {:?}",
                            tag.sender,
                            tag.session_id,
                            available_senders
                        );

                        Err(tonic::Status::new(
                            tonic::Code::NotFound,
                            format!(
                                "Sender {:?} not found in session {:?}",
                                tag.sender, tag.session_id
                            ),
                        ))
                    }
                } else {
                    // Session has been dropped, accept the message even if we won't do anything with it
                    Ok(None)
                }
            }
        }
    }
}

// We do the measurement of received bytes here because
// some messages may never reach the application level
// (i.e. in the Networking trait)
#[cfg(feature = "choreographer")]
lazy_static::lazy_static! {
    pub static ref NETWORK_RECEIVED_MEASUREMENT: DashMap<SessionId,usize> =
        DashMap::new();
}

fn parse_identity_from_cert(
    certs: Arc<Vec<CertificateDer<'static>>>,
) -> Result<String, Box<tonic::Status>> {
    if certs.len() != 1 {
        // it shouldn't happen because we expect TLS certificates to
        // be signed by party CA certificates directly, without any
        // intermediate CAs
        tracing::warn!("Received more than one certificate from peer, checking the first one only");
    }

    parse_x509_certificate(certs[0].as_ref())
        .map_err(|e| Box::new(tonic::Status::new(tonic::Code::Aborted, e.to_string())))
        .and_then(|(_rem, cert)| {
            extract_subject_from_cert(&cert)
                .map_err(|e| Box::new(tonic::Status::new(tonic::Code::Aborted, e.to_string())))
        })
}

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
        let valid_tls_sender = match self.tls_extension {
            TlsExtensionGetter::TlsConnectInfo => request
                .extensions()
                .get::<tonic::transport::server::TlsConnectInfo<TcpConnectInfo>>()
                .and_then(|i| i.peer_certs().map(parse_identity_from_cert)),
            TlsExtensionGetter::SslConnectInfo => request
                .extensions()
                .get::<tonic_tls::rustls::SslConnectInfo<TcpConnectInfo>>()
                .and_then(|i| i.peer_certs().map(parse_identity_from_cert)),
        }
        .transpose()
        .map_err(|boxed| *boxed)?;

        let request = request.into_inner();
        let tag = bc2wrap::deserialize::<Tag>(&request.tag).map_err(|_e| {
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
            // tag.sender is an Identity(hostname, port) struct, so we can directly access the hostname
            // We only need the hostname component since the tls_sender does not include the port
            let host = &tag.sender.hostname();
            if sender != *host {
                return Err(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    format!("wrong sender: expected {host:?} to be in {sender:?}"),
                ));
            }
            tracing::debug!("TLS Check went fine for sender: {:?}", sender);
        } else {
            tracing::warn!(
                "Could not find a TLS certificate in the request to verify user's identity."
            );

            // With testing feature, TLS is optional
            #[cfg(feature = "testing")]
            {
                if self.force_tls {
                    // If force_tls is enabled, we require a TLS certificate
                    tracing::error!(
                        "Force TLS is enabled, but no certificate found in the request."
                    );
                    return Err(tonic::Status::new(
                        tonic::Code::Unauthenticated,
                        "Could not find a TLS certificate in the request to verify user's identity."
                            .to_string(),
                    ));
                } else {
                    tracing::warn!(
                        "Force TLS is disabled, and no certificate found in the request."
                    );
                }
            }

            // Without testing feature, TLS is mandatory
            #[cfg(not(feature = "testing"))]
            {
                tracing::error!(
                    "Could not find a TLS certificate in the request to verify user's identity."
                );
                return Err(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    "Could not find a TLS certificate in the request to verify user's identity."
                        .to_string(),
                ));
            }
        }
        tracing::debug!("passed sender verification, tag is {:?}", tag);

        tracing::debug!(
            "Starting session lookup for session_id={:?}, sender={:?}, round={}",
            tag.session_id,
            tag.sender,
            tag.round_counter
        );

        // First try with only read lock to avoid blocking
        let tx = if let Some(session_status) = self.session_store.get(&tag.session_id) {
            match self.fetch_tx_channel(session_status.value(), &tag)? {
                Some(tx) => tx,
                None => {
                    // If the session is completed or inactive, we return early
                    return Ok(tonic::Response::new(SendValueResponse::default()));
                }
            }
        } else {
            // We write lock the session store to create a new one
            match self.session_store.entry(tag.session_id) {
                dashmap::Entry::Occupied(occupied_entry) => {
                    // Can be occupied if ever state has changed by the time we reach this branch of the if statement
                    match self.fetch_tx_channel(occupied_entry.get(), &tag)? {
                        Some(tx) => tx,
                        None => {
                            // If the session is completed or inactive, we return early
                            return Ok(tonic::Response::new(SendValueResponse::default()));
                        }
                    }
                }
                dashmap::Entry::Vacant(vacant_entry) => {
                    tracing::debug!(
                        "Session {:?} not found in session_store, creating a new inactive one.",
                        tag.session_id
                    );
                    let mut opened_session_tracker_entry = self
                        .opened_sessions_tracker
                        .entry(tag.sender.clone())
                        .or_insert(0);
                    if *opened_session_tracker_entry >= self.max_opened_inactive_sessions {
                        tracing::warn!(
                            "Too many inactive sessions opened by {:?}. Got {}, Max allowed: {}",
                            tag.sender,
                            *opened_session_tracker_entry,
                            self.max_opened_inactive_sessions
                        );
                        return Err(tonic::Status::new(
                            tonic::Code::ResourceExhausted,
                            format!(
                                "Too many inactive sessions opened by {:?}. Got {}, Max allowed: {}",
                                tag.sender,*opened_session_tracker_entry, self.max_opened_inactive_sessions
                            ),
                        ));
                    }
                    // Create a new session with an inactive status
                    let message_store = DashMap::new();
                    let (tx, rx) = channel::<NetworkRoundValue>(self.channel_size_limit);
                    let tx = Arc::new(tx);
                    message_store.insert(
                        tag.sender.clone(),
                        (Arc::clone(&tx), Arc::new(Mutex::new(rx))),
                    );

                    // Insert the new session into the store
                    vacant_entry.insert(SessionStatus::Inactive((message_store, Instant::now())));
                    *opened_session_tracker_entry += 1;
                    tx
                }
            }
        };

        // Send message - ignore send errors as receiver may have dropped
        let send_result = tokio::time::timeout(
            self.max_waiting_time_for_message_queue,
            tx.send(NetworkRoundValue {
                value: request.value,
                round_counter: tag.round_counter,
            }),
        )
        .await;

        if let Err(e) = send_result {
            tracing::warn!(
            "Failed to process value for session {:?}, sender {:?}, round {}. Queue has been full for {} seconds.",
            tag.session_id,
            tag.sender,
            tag.round_counter,
            self.max_waiting_time_for_message_queue.as_secs()
        );

            return Err(tonic::Status::new(
                tonic::Code::ResourceExhausted,
                format!(
                    "Failed to process value for session {:?}, sender {:?}, round {}: {:?}",
                    tag.session_id, tag.sender, tag.round_counter, e
                ),
            ));
        }

        Ok(tonic::Response::new(SendValueResponse::default()))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Tag {
    session_id: SessionId,
    sender: Role,
    round_counter: usize,
}
