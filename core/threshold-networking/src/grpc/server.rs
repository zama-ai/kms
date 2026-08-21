//! The [`Gnetworking`] gRPC server implementation ([`NetworkingImpl`]) plus the
//! [`Tag`]/[`HealthTag`] wire types and TLS-identity helpers.

use crate::ggen::gnetworking_server::Gnetworking;
use crate::ggen::{
    HealthCheckRequest, HealthCheckResponse, SendValueRequest, SendValueResponse, Status,
};
use crate::grpc::{
    ChannelPair, MessageQueueStore, NetworkRoundValue, ReceiverState, SessionStatus, SessionStore,
};
use crate::tls::extract_subject_from_cert;
use async_trait::async_trait;
use dashmap::DashMap;
use observability::metrics::{self, NetworkDebugEvent};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use threshold_types::party::MpcIdentity;
use threshold_types::session_id::SessionId;
use tokio::sync::{
    Mutex,
    mpsc::{Sender, channel},
};
use tokio::time::{Duration, Instant};
use tonic::transport::CertificateDer;
use tonic::transport::server::TcpConnectInfo;
use x509_parser::parse_x509_certificate;

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
    channel_size_limit: usize,
    max_waiting_time_for_message_queue: Duration,
    tls_extension: TlsExtensionGetter,
    // We gate this behind the testing feature because in non-testing environments
    // we want to ALWAYS use TLS for security reasons.
    #[cfg(feature = "testing")]
    force_tls: bool,
}

impl NetworkingImpl {
    pub(crate) fn new(
        session_store: Arc<SessionStore>,
        channel_size_limit: usize,
        max_waiting_time_for_message_queue: Duration,
        tls_extension: TlsExtensionGetter,
        #[cfg(feature = "testing")] force_tls: bool,
    ) -> Self {
        Self {
            session_store: session_store.clone(),
            channel_size_limit,
            max_waiting_time_for_message_queue,
            tls_extension,
            #[cfg(feature = "testing")]
            force_tls,
        }
    }

    /// Extract and parse the sender identity from the request's TLS certificate,
    /// according to the configured [`TlsExtensionGetter`].
    ///
    /// Returns `Ok(None)` when no client certificate is present (whether that is
    /// acceptable is decided later by [`sender_verification`]). This is the single
    /// source of truth for identity extraction so `health_check` and `send_value`
    /// — which must perform the *exact same* check — cannot diverge.
    fn extract_tls_sender<T>(
        &self,
        request: &tonic::Request<T>,
    ) -> Result<Option<String>, tonic::Status> {
        match self.tls_extension {
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
        .map_err(|boxed| *boxed)
    }

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
                metrics::METRICS
                    .increment_network_debug_event(NetworkDebugEvent::MessageToCompleted);
                tracing::debug!(
                    "Session {:?} found in session_store but is completed. Will be removed by background cleanup.",
                    tag.session_id
                );
                // We accept the message even if we won't do anything with it
                // to avoid blocking the sender
                Ok(None)
            }
            // Session is inactive, we may need to create a new channel for the sender
            SessionStatus::Inactive(message_queue) => {
                metrics::METRICS
                    .increment_network_debug_event(NetworkDebugEvent::MessageToInactive);
                tracing::debug!(
                    "Session {:?} found in session_store but is inactive.",
                    tag.session_id
                );
                // Check if the sender already has a channel, if it does, return it
                // if it doesn't then create a new one.
                // Note that we need to do this atomically to avoid race conditions.
                match message_queue.0.entry(tag.sender.clone()).map_err(|e| {
                    tonic::Status::internal(format!(
                        "Failed to access message queue for session {:?}: {}",
                        tag.session_id, e
                    ))
                })? {
                    dashmap::Entry::Occupied(occupied_entry) => {
                        Ok(Some(occupied_entry.get().tx.clone()))
                    }
                    dashmap::Entry::Vacant(vacant_entry_tx) => {
                        // Create a new channel for the sender
                        let (tx, rx) = channel::<NetworkRoundValue>(self.channel_size_limit);
                        let tx = Arc::new(tx);
                        vacant_entry_tx.insert(ChannelPair {
                            tx: Arc::clone(&tx),
                            rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
                        });
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
                    if let Some(session_store) = session
                        .receiving_channels
                        .get_tx(&tag.sender)
                        .map_err(|e| *e)?
                    {
                        Ok(Some(session_store.clone()))
                    } else {
                        let available_senders: Vec<_> = session
                            .receiving_channels
                            .iter_keys()
                            .map_err(|e| *e)?
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
                    metrics::METRICS
                        .increment_network_debug_event(NetworkDebugEvent::MessageToDroppedActive);
                    Ok(None)
                }
            }
        }
    }
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

// Verify that the sender in the tag matches the identity extracted from the TLS certificate
fn sender_verification(
    #[cfg(feature = "testing")] force_tls: bool,
    tag_sender: &MpcIdentity,
    valid_tls_sender: Option<String>,
) -> Result<(), Box<tonic::Status>> {
    if let Some(sender) = valid_tls_sender {
        // tag.sender is an the MPC identity, this should match the CN in the certificate
        if sender != tag_sender.0 {
            return Err(Box::new(tonic::Status::new(
                tonic::Code::Unauthenticated,
                format!(
                    "wrong sender: expected {sender} to be in in tag {}",
                    tag_sender
                ),
            )));
        }
        tracing::debug!("TLS Check went fine for sender: {:?}", sender);
    } else {
        // With testing feature, TLS is optional
        #[cfg(feature = "testing")]
        {
            if force_tls {
                // If force_tls is enabled, we require a TLS certificate
                tracing::error!("Force TLS is enabled, but no certificate found in the request.");
                return Err(Box::new(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    "Could not find a TLS certificate in the request to verify user's identity."
                        .to_string(),
                )));
            } else {
                // since we log this on _every_ send call and only use this for testing builds, we use debug level to reduce log spam
                tracing::debug!("Force TLS is disabled, and no certificate found in the request.");
            }
        }

        // Without testing feature, TLS is mandatory
        #[cfg(not(any(test, feature = "testing")))]
        {
            tracing::error!(
                "Could not find a TLS certificate in the request to verify user's identity."
            );
            return Err(Box::new(tonic::Status::new(
                tonic::Code::Unauthenticated,
                "Could not find a TLS certificate in the request to verify user's identity."
                    .to_string(),
            )));
        }
    }
    Ok(())
}

#[async_trait]
impl Gnetworking for NetworkingImpl {
    async fn health_check(
        &self,
        request: tonic::Request<HealthCheckRequest>,
    ) -> std::result::Result<tonic::Response<HealthCheckResponse>, tonic::Status> {
        // Perform the exact same check as we do for a "real" MPC message
        let valid_tls_sender = self.extract_tls_sender(&request)?;
        let request = request.into_inner();
        let health_tag = bc2wrap::deserialize_slice::<HealthTag>(&request.tag).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("failed to parse value: {} as a HealthTag", e),
            )
        })?;

        sender_verification(
            #[cfg(feature = "testing")]
            self.force_tls,
            &health_tag.sender,
            valid_tls_sender,
        )
        .map_err(|e| *e)?;

        tracing::debug!("Received a HealthPing from {}", health_tag.sender);
        Ok(tonic::Response::new(HealthCheckResponse::default()))
    }

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
        let valid_tls_sender = self.extract_tls_sender(&request)?;

        let request = request.into_inner();
        let tag = bc2wrap::deserialize_slice::<Tag>(&request.tag).map_err(|e| {
            tonic::Status::new(
                tonic::Code::Aborted,
                format!("failed to parse value: {}", e),
            )
        })?;

        sender_verification(
            #[cfg(feature = "testing")]
            self.force_tls,
            &tag.sender,
            valid_tls_sender,
        )
        .map_err(|e| *e)?;

        tracing::debug!(
            "Starting session lookup for session_id={:?}, sender={:?}, round={}",
            tag.session_id,
            tag.sender,
            tag.round_counter
        );

        // First try with only read lock to avoid blocking
        let tx = if let Some(session_status) = self.session_store.get(&tag.session_id) {
            let status = session_status.value();
            match self.fetch_tx_channel(status, &tag)? {
                Some(tx) => tx,
                None => {
                    // If the session is completed or inactive, we return early
                    return Ok(tonic::Response::new(status.into()));
                }
            }
        } else {
            // We write lock the session store to create a new one
            match self.session_store.entry(tag.session_id) {
                dashmap::Entry::Occupied(occupied_entry) => {
                    // Can be occupied if ever state has changed by the time we reach this branch of the if statement
                    let status = occupied_entry.get();
                    match self.fetch_tx_channel(status, &tag)? {
                        Some(tx) => tx,
                        None => {
                            // If the session is completed or inactive, we return early
                            return Ok(tonic::Response::new(status.into()));
                        }
                    }
                }
                dashmap::Entry::Vacant(vacant_entry) => {
                    tracing::debug!(
                        "Session {:?} not found in session_store, creating a new inactive one.",
                        tag.session_id
                    );
                    // Create a new session with an inactive status
                    let channel_maps = DashMap::new();
                    let (tx, rx) = channel::<NetworkRoundValue>(self.channel_size_limit);
                    let tx = Arc::new(tx);
                    channel_maps.insert(
                        tag.sender.clone(),
                        ChannelPair {
                            tx: Arc::clone(&tx),
                            rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
                        },
                    );

                    // Insert the new session into the store
                    vacant_entry.insert(SessionStatus::Inactive((
                        MessageQueueStore::new_uninitialized(channel_maps),
                        Instant::now(),
                    )));
                    metrics::METRICS
                        .increment_network_debug_event(NetworkDebugEvent::SessionInactiveCreated);
                    tx
                }
            }
        };

        // Send message - ignore send errors as receiver may have dropped
        let send_result = tokio::time::timeout(
            self.max_waiting_time_for_message_queue,
            tx.send(NetworkRoundValue {
                value: request.value,
                // Narrow the fixed-width wire round back to the in-memory `usize`.
                round_counter: tag.round_counter as usize,
            }),
        )
        .await;

        if let Err(e) = send_result {
            metrics::METRICS.increment_network_debug_event(NetworkDebugEvent::QueueFull);

            return Err(tonic::Status::new(
                tonic::Code::ResourceExhausted,
                format!(
                    "Failed to process value for session {:?}, sender {:?}, round {}: {:?}",
                    tag.session_id, tag.sender, tag.round_counter, e
                ),
            ));
        }

        metrics::METRICS.increment_network_debug_event(NetworkDebugEvent::MessageEnqueued);

        Ok(tonic::Response::new(SendValueResponse {
            status: Status::Active.into(),
        }))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tag {
    pub(crate) session_id: SessionId,
    pub(crate) sender: MpcIdentity,
    /// Round the message belongs to. This is a *wire* field, so it is a
    /// fixed-width `u64` rather than a platform-dependent `usize`: the encoding
    /// (bincode legacy/fixint via `bc2wrap`) must not vary with the sender's
    /// pointer width. The in-memory round counter is `usize`; conversions happen
    /// at the send/receive boundary.
    pub(crate) round_counter: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthTag {
    pub(crate) sender: MpcIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sending_service::NetworkSession;
    use std::sync::Weak;
    use threshold_types::party::{Identity, RoleAssignment};
    use threshold_types::role::Role;
    use tokio::sync::mpsc::channel;

    #[test]
    fn test_fetch_tx_channel_completed_session() {
        let session_store: Arc<SessionStore> = Arc::new(DashMap::new());
        let session_id = SessionId::from(1u128);

        // Insert a completed session
        session_store.insert(session_id, SessionStatus::Completed(Instant::now()));

        let networking_impl = NetworkingImpl::new(
            session_store.clone(),
            100,
            Duration::from_secs(60),
            TlsExtensionGetter::default(),
            #[cfg(feature = "testing")]
            false,
        );

        let tag = Tag {
            session_id,
            sender: MpcIdentity("party1".to_string()),
            round_counter: 0,
        };
        let session_status = session_store.get(&session_id).unwrap();

        let result = networking_impl.fetch_tx_channel(session_status.value(), &tag);

        // Should return Ok(None) for completed sessions
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_inactive_session_creates_new_channel() {
        let session_store: Arc<SessionStore> = Arc::new(DashMap::new());
        let session_id = SessionId::from(2u128);

        // Insert an inactive session with empty message queue
        let channel_maps = DashMap::new();
        session_store.insert(
            session_id,
            SessionStatus::Inactive((
                MessageQueueStore::new_uninitialized(channel_maps),
                Instant::now(),
            )),
        );

        let networking_impl = NetworkingImpl::new(
            session_store.clone(),
            100,
            Duration::from_secs(60),
            TlsExtensionGetter::default(),
            #[cfg(feature = "testing")]
            false,
        );

        let tag = Tag {
            session_id,
            sender: MpcIdentity("party1".to_string()), // Sender does not exist
            round_counter: 0,
        };
        let session_status = session_store.get(&session_id).unwrap();

        let result = networking_impl.fetch_tx_channel(session_status.value(), &tag);

        // Should return Ok(Some(tx)) for inactive sessions with new sender
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_inactive_session_existing_sender() {
        let session_store: Arc<SessionStore> = Arc::new(DashMap::new());
        let session_id = SessionId::from(3u128);
        let sender = MpcIdentity("party1".to_string());

        // Insert an inactive session with existing sender channel
        let channel_maps = DashMap::new();
        let (tx, rx) = channel::<NetworkRoundValue>(100);
        channel_maps.insert(
            sender.clone(),
            ChannelPair {
                tx: Arc::new(tx),
                rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
            },
        );

        session_store.insert(
            session_id,
            SessionStatus::Inactive((
                MessageQueueStore::new_uninitialized(channel_maps),
                Instant::now(),
            )),
        );

        let networking_impl = NetworkingImpl::new(
            session_store.clone(),
            100,
            Duration::from_secs(60),
            TlsExtensionGetter::default(),
            #[cfg(feature = "testing")]
            false,
        );

        let tag = Tag {
            session_id,
            sender: MpcIdentity("party1".to_string()),
            round_counter: 0,
        };
        let session_status = session_store.get(&session_id).unwrap();

        let result = networking_impl.fetch_tx_channel(session_status.value(), &tag);

        // Should return Ok(Some(tx)) for inactive sessions with existing sender
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_active_session_weak_reference_dead() {
        let session_store: Arc<SessionStore> = Arc::new(DashMap::new());
        let session_id = SessionId::from(5u128);

        // Create a weak reference that's already dead (no strong reference)
        let weak: Weak<NetworkSession> = Weak::new();
        session_store.insert(session_id, SessionStatus::Active(weak));

        let networking_impl = NetworkingImpl::new(
            session_store.clone(),
            100,
            Duration::from_secs(60),
            TlsExtensionGetter::default(),
            #[cfg(feature = "testing")]
            false,
        );

        let tag = Tag {
            session_id,
            sender: MpcIdentity("party1".to_string()),
            round_counter: 0,
        };
        let session_status = session_store.get(&session_id).unwrap();

        let result = networking_impl.fetch_tx_channel(session_status.value(), &tag);

        // Should return Ok(None) when weak reference is dead
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_session_status_into_send_value_response() {
        // Test Completed status
        let completed = SessionStatus::Completed(Instant::now());
        let response: SendValueResponse = completed.into();
        assert_eq!(response.status(), Status::Completed);

        // Test Inactive status
        let channel_maps = DashMap::new();
        let inactive = SessionStatus::Inactive((
            MessageQueueStore::new_uninitialized(channel_maps),
            Instant::now(),
        ));
        let response: SendValueResponse = inactive.into();
        assert_eq!(response.status(), Status::Inactive);

        // Test Active status (with dead weak reference)
        let weak: Weak<NetworkSession> = Weak::new();
        let active = SessionStatus::Active(weak);
        let response: SendValueResponse = active.into();
        assert_eq!(response.status(), Status::Active);
    }

    #[test]
    fn test_message_queue_store_get_tx_initialized() {
        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new("127.0.0.1".to_string(), 6001, Some("party1".to_string()));
        let mut role_assignment: RoleAssignment<Role> = RoleAssignment::default();
        role_assignment.insert(role_1, id_1.clone());

        let store = MessageQueueStore::new_initialized(100, &role_assignment);

        // Should get Some(tx) for existing identity
        let result = store.get_tx(&id_1.mpc_identity());
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        // Should get None for non-existing identity
        let other_sender = MpcIdentity("party2".to_string());
        let result = store.get_tx(&other_sender);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
