//! [`GrpcNetworkingManager`]: owns the session store, background cleanup, and
//! session/health-check creation, wiring the other submodules together.

use crate::ggen::gnetworking_server::GnetworkingServer;
use crate::grpc::{
    CoreToCoreNetworkConfig, MessageQueueStore, NETWORK_RECEIVED_MEASUREMENT, NetworkingImpl,
    SessionStatus, SessionStore, TlsExtensionGetter,
};
use crate::health_check::HealthCheckSession;
use crate::sending_service::{
    GrpcSendingService, NetworkSession, SendingService, now_activity_millis,
};
use observability::metrics::{self, NetworkDebugEvent};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use threshold_types::network::{NetworkMode, Networking};
use threshold_types::party::RoleAssignment;
use threshold_types::role::RoleTrait;
use threshold_types::session_id::SessionId;
use tokio::time::{Duration, Instant};

//TODO: Most likely need this to create NetworkStack instead of GrpcNetworking
/// GrpcNetworkingManager is responsible for managing
/// channels and message queues between MPC parties.
#[derive(Debug, Clone)]
pub struct GrpcNetworkingManager {
    // Session reference storage to prevent premature cleanup under high concurrency
    pub(crate) session_store: Arc<SessionStore>,
    inactive_session_count: Arc<AtomicU64>,
    active_session_count: Arc<AtomicU64>,
    conf: CoreToCoreNetworkConfig,
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
            self.conf.get_message_limit(),
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
    ///
    /// Finally it also updates the counts of inactive and active sessions.
    fn start_background_cleaning_task(
        session_store: Arc<SessionStore>,
        inactive_session_count: Arc<AtomicU64>,
        active_session_count: Arc<AtomicU64>,
        update_interval: Duration,
        cleanup_interval: Duration,
        discard_inactive_interval: Duration,
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(update_interval);
            loop {
                interval.tick().await;
                let mut internal_inactive_sessions_count = 0;
                let mut internal_active_sessions_count = 0;
                let mut internal_completed_sessions_count = 0;
                let mut to_remove = Vec::new();
                for mut cur in session_store.iter_mut() {
                    let (session_id, status) = cur.pair_mut();
                    match status {
                        SessionStatus::Completed(started) => {
                            // Remove completed sessions that have been completed for a very long time
                            if started.elapsed() > cleanup_interval {
                                metrics::METRICS.increment_network_debug_event(
                                    NetworkDebugEvent::SessionCompletedRemoved,
                                );
                                to_remove.push(*session_id);
                            } else {
                                internal_completed_sessions_count += 1;
                            }
                        }
                        SessionStatus::Inactive((_, started)) => {
                            // Remove inactive sessions that have been inactive for awhile
                            if started.elapsed() > discard_inactive_interval {
                                metrics::METRICS.increment_network_debug_event(
                                    NetworkDebugEvent::SessionInactiveDiscarded,
                                );
                                to_remove.push(*session_id);
                                continue;
                            } else {
                                internal_inactive_sessions_count += 1;
                            }
                        }
                        SessionStatus::Active(session) => match session.upgrade() {
                            Some(network_session) => {
                                let time_since_last_rec = Duration::from_millis(
                                    now_activity_millis().saturating_sub(
                                        network_session
                                            .last_rec_activity_time
                                            .load(Ordering::Relaxed),
                                    ),
                                );
                                if time_since_last_rec > discard_inactive_interval {
                                    metrics::METRICS.increment_network_debug_event(
                                        NetworkDebugEvent::SessionActiveDiscarded,
                                    );
                                    to_remove.push(*session_id);
                                    continue;
                                }
                                internal_active_sessions_count += 1;
                            }
                            None => {
                                *status = SessionStatus::Completed(Instant::now());
                                internal_completed_sessions_count += 1;
                                metrics::METRICS.increment_network_debug_event(
                                    NetworkDebugEvent::SessionCompleted,
                                );
                            }
                        },
                    };
                }
                for session_id in to_remove {
                    session_store.remove(&session_id);
                }
                inactive_session_count.store(internal_inactive_sessions_count, Ordering::Relaxed);
                active_session_count.store(internal_active_sessions_count, Ordering::Relaxed);
                metrics::METRICS.record_completed_sessions(internal_completed_sessions_count);
                metrics::METRICS.record_network_measurement_sessions(
                    u64::try_from(NETWORK_RECEIVED_MEASUREMENT.len()).unwrap_or(u64::MAX),
                );
            }
        });
    }

    /// Owner should be the external address
    pub fn new(
        tls_conf: Option<tokio_rustls::rustls::client::ClientConfig>,
        conf: CoreToCoreNetworkConfig,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "testing")]
        let force_tls = tls_conf.is_some();
        #[cfg(feature = "testing")]
        if !force_tls {
            tracing::warn!(
                "force_tls is DISABLED. Testing feature is enabled - this is NOT recommended in production environments."
            );
        }

        #[cfg(not(any(test, feature = "testing")))]
        if tls_conf.is_none() {
            return Err(error_utils::anyhow_error_and_log(
                "TLS configuration must be provided in non-testing environments",
            ));
        }

        // `conf` is already resolved: an absent config is `CoreToCoreNetworkConfig::default()`
        // (all fields `None`), so every `get_*` accessor falls back to its constant.
        let session_store = Arc::new(SessionStore::default());

        // We need to spawn background cleanup task to remove dead weak references from session_store, otherwise they accumulate and eat RAM + perf
        let cleanup_session_store = Arc::clone(&session_store);
        let update_interval = conf.get_session_update_interval();
        let cleanup_interval = conf.get_session_cleanup_interval();
        let discard_inactive_interval = conf.get_discard_inactive_sessions_interval();
        let inactive_session_count = Arc::new(AtomicU64::new(0));
        let active_session_count = Arc::new(AtomicU64::new(0));
        Self::start_background_cleaning_task(
            cleanup_session_store,
            Arc::clone(&inactive_session_count),
            Arc::clone(&active_session_count),
            update_interval,
            cleanup_interval,
            discard_inactive_interval,
        );

        Ok(GrpcNetworkingManager {
            session_store,
            inactive_session_count,
            active_session_count,
            conf,
            sending_service: GrpcSendingService::new(tls_conf, conf)?,
            #[cfg(feature = "testing")]
            force_tls,
        })
    }

    pub async fn make_healthcheck_session<R: RoleTrait>(
        &self,
        role_assignment: &RoleAssignment<R>,
        my_role: R,
    ) -> anyhow::Result<HealthCheckSession<R>> {
        let mut others = role_assignment.clone();

        // Removing self from the role_assignment map
        // as we only want to connect to others.
        // Store my own identity in the session
        let owner = match others.remove(&my_role) {
            Some(owner) => owner,
            None => {
                return Err(anyhow::anyhow!(
                    "My role {:?} not found in role assignment {:?}",
                    my_role,
                    role_assignment
                ));
            }
        };

        let mut connection_channels = HashMap::new();
        for (role, identity) in others.inner.into_iter() {
            let channel = self.sending_service.connect_to_party(&identity).await?;
            connection_channels.insert((role, identity), channel);
        }

        Ok(HealthCheckSession::new(
            owner,
            my_role,
            // We use the same timeout in HealthCheck than
            // in Sync MPC protocols
            self.conf.get_network_timeout(),
            connection_channels,
        ))
    }

    /// Create a new session from the network manager.
    ///
    /// All the communication are performed using sessions.
    /// There may be multiple session in parallel,
    /// identified by different session IDs.
    pub async fn make_network_session<R: RoleTrait>(
        &self,
        session_id: SessionId,
        role_assignment: &RoleAssignment<R>,
        my_role: R,
        network_mode: NetworkMode,
    ) -> anyhow::Result<Arc<impl Networking<R> + use<R>>> {
        let mut others = role_assignment.clone();

        // Removing self from the role_assignment map
        // as we only want to connect to others.
        // Store my own identity in the session
        let owner = match others.remove(&my_role) {
            Some(owner) => owner,
            None => {
                return Err(anyhow::anyhow!(
                    "My role {:?} not found in role assignment {:?}",
                    my_role,
                    role_assignment
                ));
            }
        };

        let (connection_channel, completed_parties) =
            self.sending_service.add_connections(&others).await?;

        let session = match self.session_store.entry(session_id) {
            // Turn an inactive session into an active one
            dashmap::Entry::Occupied(mut status) => {
                let mutable_status = status.get_mut();

                let message_store = if let SessionStatus::Inactive(message_store) = mutable_status {
                    // Upgrade the message store from the uninitialized state to the initialized state
                    message_store.0.init(self.conf.get_message_limit(), &others);
                    message_store.clone()
                } else {
                    return Err(anyhow::anyhow!(
                        "Session {:?} already exists and is not inactive for {}",
                        session_id,
                        owner
                    ));
                };

                let session = Arc::new(NetworkSession::new(
                    owner.clone(),
                    session_id,
                    connection_channel,
                    message_store.0,
                    completed_parties,
                    network_mode,
                    self.conf,
                ));

                *mutable_status = SessionStatus::Active(Arc::downgrade(&session));
                metrics::METRICS.increment_network_debug_event(NetworkDebugEvent::SessionActivated);

                session
            }
            dashmap::Entry::Vacant(vacant) => {
                let message_queue =
                    MessageQueueStore::new_initialized(self.conf.get_message_limit(), &others);

                let session = Arc::new(NetworkSession::new(
                    owner.clone(),
                    session_id,
                    connection_channel,
                    message_queue,
                    completed_parties,
                    network_mode,
                    self.conf,
                ));

                vacant.insert(SessionStatus::Active(Arc::downgrade(&session)));
                metrics::METRICS
                    .increment_network_debug_event(NetworkDebugEvent::SessionActiveCreated);

                session
            }
        };

        Ok(session)
    }

    pub async fn active_session_count(&self) -> u64 {
        self.active_session_count.load(Ordering::Relaxed)
    }

    pub async fn inactive_session_count(&self) -> u64 {
        self.inactive_session_count.load(Ordering::Relaxed)
    }
}
