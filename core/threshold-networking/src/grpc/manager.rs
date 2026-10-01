//! [`GrpcNetworkingManager`]: owns the session store, background cleanup, and
//! session/health-check creation, wiring the other submodules together.

use crate::ggen::gnetworking_server::GnetworkingServer;
use crate::grpc::{
    CoreToCoreNetworkConfig, MessageQueueStore, NetworkingImpl, SessionStatus, SessionStore,
    TlsExtensionGetter,
};
use crate::health_check::HealthCheckSession;
use crate::sending_service::{GrpcSendingService, NetworkSession, SendingService};
use dashmap::DashMap;
use observability::metrics::{self, NetworkDebugEvent};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use threshold_types::network::{NetworkMode, Networking};
use threshold_types::party::{MpcIdentity, RoleAssignment};
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
    // Keeps tracks of how many sessions were opened by each party
    // NOTE: Always lock session_store before opened_sessions_tracker to prevent deadlocks
    pub opened_sessions_tracker: Arc<DashMap<MpcIdentity, u64>>,
    conf: CoreToCoreNetworkConfig,
    pub sending_service: GrpcSendingService,
    #[cfg(feature = "insecure")]
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
            #[cfg(feature = "insecure")]
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
    ///
    /// TODO: replace the full sweep. Every `update_interval` it walks the whole store with
    /// `iter_mut`, holding each shard's write lock, so `send_value` lookups queue behind it; and
    /// with completed sessions kept for `cleanup_interval` (24h by default) the store holds every
    /// session of the last day. Entries are created and complete in roughly time order, so a queue
    /// of `(Instant, SessionId)` popped from the front, or one bucket per interval dropped whole,
    /// would expire them without visiting the rest. The sweep also detects active sessions whose
    /// `NetworkSession` was dropped; that would have to move to the session's `Drop`.
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
                                metrics::METRICS.increment_network_event(
                                    NetworkDebugEvent::SessionCompletedRemoved,
                                );
                                to_remove.push(*session_id);
                            } else {
                                internal_completed_sessions_count += 1;
                            }
                        }
                        SessionStatus::Inactive((_, started)) => {
                            // Remove inactive sessions that have been inactive for awhile
                            // TODO: discarding an inactive session must give its senders' slots
                            // back in `opened_sessions_tracker`; today only activation does
                            // (`MessageQueueStore::init`). Every inactive session that is never
                            // activated, e.g. one this party rejected while its peers accepted it,
                            // leaks one slot per sender for good, until the sender hits
                            // `max_opened_inactive_sessions` and all its new sessions are refused.
                            if started.elapsed() > discard_inactive_interval {
                                metrics::METRICS.increment_network_event(
                                    NetworkDebugEvent::SessionInactiveDiscarded,
                                );
                                to_remove.push(*session_id);
                                continue;
                            } else {
                                internal_inactive_sessions_count += 1;
                            }
                        }
                        SessionStatus::Active(session) => match session.upgrade() {
                            Some(_) => {
                                internal_active_sessions_count += 1;
                            }
                            None => {
                                *status = SessionStatus::Completed(Instant::now());
                                internal_completed_sessions_count += 1;
                                metrics::METRICS
                                    .increment_network_event(NetworkDebugEvent::SessionCompleted);
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
            }
        });
    }

    /// Owner should be the external address
    pub fn new(
        tls_conf: Option<tokio_rustls::rustls::client::ClientConfig>,
        conf: CoreToCoreNetworkConfig,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "insecure")]
        let force_tls = tls_conf.is_some();
        #[cfg(feature = "insecure")]
        if !force_tls {
            tracing::warn!(
                "force_tls is DISABLED. Insecure feature is enabled - this is NOT recommended in production environments."
            );
        }

        #[cfg(not(any(test, feature = "insecure")))]
        if tls_conf.is_none() {
            return Err(error_utils::anyhow_error_and_log(
                "TLS configuration must be provided in secure builds",
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
            opened_sessions_tracker: Arc::new(DashMap::new()),
            conf,
            sending_service: GrpcSendingService::new(tls_conf, conf)?,
            #[cfg(feature = "insecure")]
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
                    message_store.0.init(
                        self.conf.get_message_limit(),
                        &others,
                        Arc::clone(&self.opened_sessions_tracker),
                    );
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
                metrics::METRICS.increment_network_event(NetworkDebugEvent::SessionActivated);

                session
            }
            dashmap::Entry::Vacant(vacant) => {
                let message_queue = MessageQueueStore::new_initialized(
                    self.conf.get_message_limit(),
                    &others,
                    Arc::clone(&self.opened_sessions_tracker),
                );

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
                metrics::METRICS.increment_network_event(NetworkDebugEvent::SessionActiveCreated);

                session
            }
        };

        Ok(session)
    }

    /// Records that this party refused to run the given sessions, e.g. because its rate limiter rejected the request
    /// they belong to.
    ///
    /// This gives other peers that is sending to this one a chance to hang up and stop trying to receive.
    ///
    /// A rejected session is marked `Completed` to avoid changing the wire format; we should add a `Rejected` variant
    /// at some point in the future.
    ///
    /// A session marked this way cannot be run later: a retry of the same request on this party fails, since its peers
    /// have already stopped sending to this party.
    pub fn mark_sessions_rejected(&self, session_ids: &[SessionId]) {
        for session_id in session_ids {
            // Lock order: the session store entry before `opened_sessions_tracker`.
            match self.session_store.entry(*session_id) {
                dashmap::Entry::Vacant(vacant) => {
                    vacant.insert(SessionStatus::Completed(Instant::now()));
                }
                dashmap::Entry::Occupied(mut occupied) => {
                    if let SessionStatus::Inactive((queue, _)) = occupied.get() {
                        if let MessageQueueStore::Uninitialized(channel_maps) = queue {
                            for sender in channel_maps.iter() {
                                if let Some(mut count) =
                                    self.opened_sessions_tracker.get_mut(sender.key())
                                {
                                    *count = count.saturating_sub(1);
                                }
                            }
                        }
                        occupied.insert(SessionStatus::Completed(Instant::now()));
                    }
                    // An active session is being run by this party after all, and a completed
                    // one already answers `Completed`: leave both alone.
                }
            }
        }
    }

    pub async fn active_session_count(&self) -> u64 {
        self.active_session_count.load(Ordering::Relaxed)
    }

    pub async fn inactive_session_count(&self) -> u64 {
        self.inactive_session_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use threshold_types::party::Identity;
    use threshold_types::role::Role;

    /// Rejected sessions answer `Completed` to other peers. A session this party is running is left alone.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_mark_sessions_rejected() {
        use crate::grpc::{ChannelPair, MessageQueueStore, NetworkRoundValue, ReceiverState};
        use tokio::sync::{Mutex, mpsc::channel};

        let manager = GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap();
        let role_1 = Role::indexed_from_one(1);
        let role_2 = Role::indexed_from_one(2);
        let mut role_assignment = RoleAssignment::default();
        role_assignment.insert(role_1, Identity::new("127.0.0.1".to_string(), 1, None));
        role_assignment.insert(role_2, Identity::new("127.0.0.1".to_string(), 2, None));

        // Unknown to this party.
        let unknown_id = SessionId::from(1);
        // Already opened by a message from a peer, counted against that peer.
        let inactive_id = SessionId::from(2);
        let peer = MpcIdentity("peer".to_string());
        let channel_maps = DashMap::new();
        let (tx, rx) = channel::<NetworkRoundValue>(1);
        channel_maps.insert(
            peer.clone(),
            ChannelPair {
                tx: Arc::new(tx),
                rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
            },
        );
        manager.session_store.insert(
            inactive_id,
            SessionStatus::Inactive((
                MessageQueueStore::new_uninitialized(channel_maps),
                Instant::now(),
            )),
        );
        manager.opened_sessions_tracker.insert(peer.clone(), 1);
        // Being run by this party.
        let active_id = SessionId::from(3);
        let active = manager
            .make_network_session(active_id, &role_assignment, role_1, NetworkMode::Async)
            .await
            .unwrap();

        manager.mark_sessions_rejected(&[unknown_id, inactive_id, active_id]);

        for id in [unknown_id, inactive_id] {
            assert_eq!(
                status_name(manager.session_store.get(&id).as_deref()),
                "completed",
                "rejected session {id} must answer completed"
            );
        }
        assert_eq!(*manager.opened_sessions_tracker.get(&peer).unwrap(), 0);
        assert_eq!(
            status_name(manager.session_store.get(&active_id).as_deref()),
            "active"
        );
        drop(active);
    }

    /// Name of a session store entry's status, for assertion messages.
    fn status_name(status: Option<&SessionStatus>) -> &'static str {
        match status {
            Some(SessionStatus::Active(_)) => "active",
            Some(SessionStatus::Inactive(_)) => "inactive",
            Some(SessionStatus::Completed(_)) => "completed",
            None => "absent",
        }
    }

    /// Regression test: the task used to discard an active session that had not
    /// received anything for `discard_inactive_sessions_interval`. Sessions that
    /// legitimately idle would thus be discarded, which turned out to be an issue.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_active_session_is_never_discarded() {
        let conf = CoreToCoreNetworkConfig {
            network_timeout: Some(1),
            session_update_interval_secs: Some(1),
            session_cleanup_interval_secs: Some(1),
            discard_inactive_sessions_interval: Some(1),
            ..Default::default()
        };
        let manager = GrpcNetworkingManager::new(None, conf).unwrap();

        let role_1 = Role::indexed_from_one(1);
        let role_2 = Role::indexed_from_one(2);
        let mut role_assignment = RoleAssignment::default();
        role_assignment.insert(role_1, Identity::new("127.0.0.1".to_string(), 1, None));
        role_assignment.insert(role_2, Identity::new("127.0.0.1".to_string(), 2, None));

        // An idle session at round 0, whose 1s round deadline passes right away.
        let idle_id = SessionId::from(7);
        let idle = manager
            .make_network_session(idle_id, &role_assignment, role_1, NetworkMode::Sync)
            .await
            .unwrap();
        // A session budgeted 20 rounds ahead, whose deadline outlasts the test.
        let ahead_id = SessionId::from(8);
        let ahead = manager
            .make_network_session(ahead_id, &role_assignment, role_1, NetworkMode::Sync)
            .await
            .unwrap();
        let advance = 20;
        for _ in 0..advance {
            ahead.increase_round_counter().await;
        }

        // Several sweeps of the cleanup task at a 1s update interval, well past the
        // 1s discard and cleanup intervals and past the idle session's deadline.
        tokio::time::sleep(Duration::from_millis(3500)).await;

        assert!(
            idle.get_timeout_current_round().await < std::time::Instant::now(),
            "the idle session must be past its own round deadline for the test to be meaningful"
        );
        for (id, session) in [(idle_id, &idle), (ahead_id, &ahead)] {
            let entry = manager.session_store.get(&id);
            match entry.as_deref() {
                Some(SessionStatus::Active(weak)) => {
                    let routed = weak.upgrade().unwrap_or_else(|| {
                        panic!("the entry of session {id} must point at a live session")
                    });
                    assert_eq!(
                        Arc::as_ptr(&routed) as *const (),
                        Arc::as_ptr(session) as *const (),
                        "the entry of session {id} must still route to the protocol's session"
                    );
                }
                other => panic!(
                    "session {id} must still be active while the protocol holds it, got {}",
                    status_name(other)
                ),
            }
        }
        assert_eq!(manager.active_session_count().await, 2);
        assert_eq!(ahead.get_current_round().await, advance);

        // Dropping the handles is the only way out of `Active`: the next sweep marks
        // the entries completed and the cleanup interval then removes them.
        drop(idle);
        drop(ahead);
        tokio::time::sleep(Duration::from_millis(3500)).await;
        for id in [idle_id, ahead_id] {
            assert!(
                manager.session_store.get(&id).is_none(),
                "session {id} must be removed once dropped and past the cleanup interval, got {}",
                status_name(manager.session_store.get(&id).as_deref())
            );
        }
        assert_eq!(manager.active_session_count().await, 0);
    }
}
