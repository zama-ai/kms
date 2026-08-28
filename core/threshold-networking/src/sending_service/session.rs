//! [`NetworkSession`]: the application-facing [`Networking`] implementation that
//! stamps/sends tagged messages and performs the round-aware `receive`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use super::{ArcSendValueRequest, AtomicDuration, now_activity_millis};
use crate::grpc::NETWORK_RECEIVED_MEASUREMENT;
use crate::grpc::{CoreToCoreNetworkConfig, MessageQueueStore, NetworkRoundValue, Tag};
use dashmap::DashSet;
use error_utils::anyhow_error_and_log;
use threshold_types::network::{NetworkMode, Networking};
use threshold_types::party::Identity;
use threshold_types::role::{RoleKind, RoleTrait};
use threshold_types::session_id::SessionId;
use tokio::sync::mpsc::UnboundedSender;
use tonic::async_trait;

/// This acts as an interface with the real networking processes.
/// It communicates with the SendingService via the mpsc Sender channel (sending_channels)
/// And retrieves messages via the Grpc Server mpsc Receiver channel (receiving_channels)
/// It also deals with the network round and timeouts
#[derive(Debug)]
pub struct NetworkSession {
    /// My own [`Identity`]
    pub(crate) owner: Identity,
    /// [`SessionId`] of this Network session
    pub(crate) session_id: SessionId,
    /// MPSC channels that are filled by parties and dealt with by the [`SendingService`](super::SendingService)
    /// Sending channels for this session
    pub(crate) sending_channels: HashMap<RoleKind, UnboundedSender<ArcSendValueRequest>>,
    /// Channels which are filled by the grpc server receiving messages from the other parties
    /// owned by the session and thus automatically cleaned up on drop
    pub(crate) receiving_channels: MessageQueueStore,
    // Round counter for the current session, behind a lock to be able to update it without a mut ref to self
    // Observe tokio lock is needed since it must be held across an await point
    pub(crate) round_counter: tokio::sync::RwLock<usize>,
    // Set keeping track of all servers that have already completed the session (i.e. servers which we are out-of-sync with)
    pub(crate) completed_parties: Arc<DashSet<RoleKind>>,
    /// Number of bytes sent by this session. Stored as an atomic (not a lock)
    /// since it is a simple accumulator that is never read-modified-written
    /// across an await point.
    pub(crate) num_byte_sent: AtomicUsize,
    // Network mode is either async or sync
    pub(crate) network_mode: NetworkMode,
    // If Network mode is sync, we need to keep track of the values below to make sure
    // we are within time bound
    pub(crate) conf: CoreToCoreNetworkConfig,
    pub(crate) init_time: OnceLock<Instant>,
    /// Milliseconds since the activity epoch when the last message was received,
    /// or when the session was made active if no message has been received yet.
    /// Used to discard inactive sessions. Stored as an atomic (not a lock) so it
    /// can be read and written without awaiting — in particular from the session
    /// cleanup task while it holds a `DashMap` shard guard.
    pub(crate) last_rec_activity_time: AtomicU64,
    /// Current round's network timeout. Backed by an [`AtomicDuration`] rather
    /// than a lock so the round-transition update in
    /// [`Networking::increase_round_counter`] only needs to hold the
    /// `round_counter` lock, instead of acquiring several locks at once.
    pub(crate) current_network_timeout: AtomicDuration,
    /// Next round's network timeout; see [`current_network_timeout`](Self::current_network_timeout).
    pub(crate) next_network_timeout: AtomicDuration,
    /// Accumulated elapsed-time budget; see [`current_network_timeout`](Self::current_network_timeout).
    pub(crate) max_elapsed_time: AtomicDuration,
}

/// Outcome of a single wait for the next packet from a sender's channel in
/// [`NetworkSession::recv_next`].
enum RecvOutcome {
    /// A packet arrived and should be classified against the current round.
    Packet(NetworkRoundValue),
    /// This tick elapsed without a delivery decision (sender not completed); the
    /// caller should keep waiting.
    Retry,
    /// The sender's channel is closed; no further messages will ever arrive.
    Closed,
    /// The sender declared the session complete and the post-completion grace
    /// period elapsed with no further message; the receive must abort.
    Aborted,
}

impl RecvOutcome {
    /// Map a channel `recv()` result to an outcome: `Some` is a packet, `None`
    /// means the channel is closed.
    fn from_recv(packet: Option<NetworkRoundValue>) -> Self {
        match packet {
            Some(packet) => RecvOutcome::Packet(packet),
            None => RecvOutcome::Closed,
        }
    }
}

#[async_trait]
impl<R: RoleTrait> Networking<R> for NetworkSession {
    /// WARNING: [`increase_round_counter`] MUST be called right before sending.
    /// In particular a call to [`receive`] cannot be interleaved between a counter increase and a send.
    /// Thus sending and receiving MUST not be interleaved.
    ///
    //Note this need not be async, so do we want to keep the trait definition async
    //if we want to add other implems which may require async ?
    async fn send(&self, value: Arc<Vec<u8>>, receiver: &R) -> anyhow::Result<()> {
        // Take the round-counter *read* guard for the duration of the send. This
        // is a read guard, not an exclusive lock: concurrent `send`/`receive`
        // calls (also readers) proceed in parallel, while `increase_round_counter`
        // (the sole writer) simply *waits* until this guard is released — it does
        // not error. Holding it is what binds the stamped round tag to the round
        // the caller intended, by preventing a round transition mid-send.
        let round_counter = *self.round_counter.read().await;
        let tagged_value = Tag {
            session_id: self.session_id,
            sender: self.owner.mpc_identity(),
            // Widen the in-memory `usize` round to the fixed-width wire type.
            round_counter: round_counter as u64,
        };

        let tag = Arc::new(
            bc2wrap::serialize(&tagged_value)
                .map_err(|e| anyhow_error_and_log(format!("networking error: {e:?}")))?,
        );

        self.num_byte_sent
            .fetch_add(tag.len() + value.len(), Ordering::Relaxed);
        let request = ArcSendValueRequest::new(tag, value);

        //Retrieve the local channel that corresponds to the party we want to send to and push into it
        match self.sending_channels.get(&receiver.get_role_kind()) {
            Some(sending_channel) => Ok(sending_channel.send(request)?),
            None => Err(anyhow_error_and_log(format!(
                "Missing local channel for {receiver:?}"
            ))),
        }?;
        Ok(())
    }

    /// Receives messages from other parties, assuming the grpc server filled the [`MessageQueueStore`](crate::grpc::MessageQueueStore) correctly
    ///
    /// WARNING: A call to [`receive`] cannot be interleaved between a counter increase and a send.
    /// Thus sending and receiving MUST not be interleaved.
    async fn receive(&self, sender: &R) -> anyhow::Result<Vec<u8>> {
        // Take the round-counter *read* guard for the whole receive. This is a
        // read guard, not an exclusive lock: other readers (`send`/`receive`) run
        // concurrently, while `increase_round_counter` (the sole writer) *waits*
        // until this guard is dropped — it does not error. Holding it is what
        // fixes `network_round` for the entire call and makes exact-round
        // delivery well-defined against a racing round transition.
        let counter_lock = self.round_counter.read().await;
        let rx = self
            .receiving_channels
            .get_receiver_state(sender)?
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                    "couldn't retrieve receiving channel for P:{sender:?}"
                ))
            })?;
        let mut state = rx.lock().await;

        // The round counter is fixed for the whole call: `receive` holds the
        // read lock and `increase_round_counter` holds the write lock, so no
        // round transition can race this call.
        let network_round = *counter_lock;

        // Fast path: drop buffered messages that have since become stale, then
        // deliver a previously buffered message for exactly this round. Future-
        // round messages are only ever buffered (never delivered early), so this
        // cannot leak a wrong-round packet. The prune + take is done in one place
        // on `ReceiverState` (see `take_current`) so the buffer discipline stays
        // unit-testable without a running session.
        if let Some(value) = state.take_current(network_round) {
            self.last_rec_activity_time
                .store(now_activity_millis(), Ordering::Relaxed);
            return Ok(value);
        }

        tracing::debug!("Waiting to receive from {:?}", sender);
        let mut tick_interval = tokio::time::interval_at(
            (Instant::now() + self.conf.get_max_waiting_time_for_message_queue()).into(),
            self.conf.get_max_waiting_time_for_message_queue(),
        );
        loop {
            // Wait for the next packet from this sender's channel, applying the
            // completed-party grace period. All the subtle wait/abort control
            // flow lives in `recv_next`; here we only act on its verdict.
            let packet = match self
                .recv_next(&mut state.rx, &mut tick_interval, sender)
                .await
            {
                RecvOutcome::Packet(packet) => packet,
                // Nothing decided this tick — keep waiting.
                RecvOutcome::Retry => continue,
                // The channel is closed.
                RecvOutcome::Closed => {
                    return Err(anyhow_error_and_log(
                        "Trying to receive from a closed channel.",
                    ));
                }
                // Sender completed and the grace period elapsed with no message.
                RecvOutcome::Aborted => {
                    return Err(anyhow_error_and_log(format!(
                        "Session {} has been aborted with {}",
                        self.session_id,
                        sender.get_role_kind()
                    )));
                }
            };
            // Update the time we received a message
            self.last_rec_activity_time
                .store(now_activity_millis(), Ordering::Relaxed);

            // Classify the packet against the current round. The round counter
            // is peer-controlled and unauthenticated, so a packet is only
            // deliverable when it is tagged with *exactly* the current round.
            match packet.round_counter.cmp(&network_round) {
                // Stale: a message for a round we already passed. Drop it and
                // keep waiting.
                std::cmp::Ordering::Less => {
                    let val_len = packet.value.len();
                    tracing::debug!(
                        "@ round {} - dropped value {:?} from stale round {}",
                        network_round,
                        packet.value[..val_len.min(16)].to_vec(),
                        packet.round_counter
                    );
                    continue;
                }
                // Exactly our round: deliver.
                std::cmp::Ordering::Equal => return Ok(packet.value),
                // Future round: buffer it (within bounds) until the session
                // advances, so it can never satisfy an earlier round's receive.
                // The look-ahead window, per-sender cap and the
                // at-most-one-value-per-round rule live in `buffer_future`.
                std::cmp::Ordering::Greater => {
                    let round = packet.round_counter;
                    if !state.buffer_future(
                        round,
                        packet.value,
                        network_round,
                        self.conf.get_max_future_rounds(),
                        self.conf.get_max_buffered_future_msgs(),
                    ) {
                        // Note that the sender is never warned of this failure, so a honest party
                        // won't try and re-send the message. But, this is a DoS mitigation: a malicious peer could
                        // otherwise flood us with future-round messages and exhaust memory.
                        tracing::warn!(
                            "@ round {} - dropping out-of-window/over-cap future-round message for round {} from {:?} (buffered: {})",
                            network_round,
                            round,
                            sender,
                            state.future.len()
                        );
                    }
                    continue;
                }
            }
        }
    }

    /// Increase the round counter
    ///
    /// __NOTE__: We always assume this is called right before sending happens
    async fn increase_round_counter(&self) {
        // Hold the round-counter write lock across the whole update. It is the
        // serialization point for round transitions (readers take it in `send`,
        // `receive` and `get_current_round`), so the timeout atomics below are
        // only ever mutated while it is held.
        let mut net_round = self.round_counter.write().await;

        let current_round_timeout = self.current_network_timeout.load();
        self.max_elapsed_time.fetch_add(current_round_timeout);

        //Update next round timeout
        let next_round_timeout = self.next_network_timeout.load();
        self.current_network_timeout.store(next_round_timeout);

        //Update round counter
        *net_round += 1;
        tracing::debug!(
            "changed network round to: {:?} on party: {:?}, with timeout: {:?}",
            *net_round,
            self.owner,
            next_round_timeout
        )
    }

    ///Used to compute the timeout in network functions
    async fn get_timeout_current_round(&self) -> Instant {
        let init_time = self.init_time.get_or_init(Instant::now);
        let max_elapsed_time = self.max_elapsed_time.load();
        let network_timeout = self.current_network_timeout.load();

        *init_time + network_timeout + max_elapsed_time
    }

    async fn get_current_round(&self) -> usize {
        *self.round_counter.read().await
    }

    /// Method to set a different timeout than the one set at construction, effective for the next round.
    ///
    /// __NOTE__: If the network mode is Async, this has no effect
    async fn set_timeout_for_next_round(&self, timeout: Duration) {
        self.inner_set_timeout_for_next_round(timeout).await
    }

    /// Method to set the timeout for distributed generation of the TFHE bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    async fn set_timeout_for_bk(&self) {
        self.inner_set_timeout_for_next_round(self.conf.get_network_timeout_bk())
            .await
    }

    /// Method to set the timeout for distributed generation of the TFHE switch and squash bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    async fn set_timeout_for_bk_sns(&self) {
        self.inner_set_timeout_for_next_round(self.conf.get_network_timeout_bk_sns())
            .await
    }

    fn get_network_mode(&self) -> NetworkMode {
        self.inner_get_network_mode()
    }

    async fn get_num_byte_sent(&self) -> usize {
        self.num_byte_sent.load(Ordering::Relaxed)
    }

    async fn get_num_byte_received(&self) -> anyhow::Result<usize> {
        if let Some(num_byte_received) = NETWORK_RECEIVED_MEASUREMENT.get(&self.session_id) {
            Ok(*num_byte_received)
        } else {
            Err(anyhow_error_and_log(format!(
                "Couldn't find session {} in the NETWORK_RECEIVED_MEASUREMENT",
                self.session_id
            )))
        }
    }
}

impl NetworkSession {
    /// Build a fresh session. Collapses the two production construction sites in
    /// [`GrpcNetworkingManager::make_network_session`](crate::grpc::GrpcNetworkingManager)
    /// (the inactive→active and vacant branches), which previously duplicated this
    /// 14-field literal and had to be kept in lock-step by hand. All the
    /// round-independent fields (round counter, timers, byte counter, activity
    /// time) are initialised here; callers supply only what actually differs.
    pub(crate) fn new(
        owner: Identity,
        session_id: SessionId,
        sending_channels: HashMap<RoleKind, UnboundedSender<ArcSendValueRequest>>,
        receiving_channels: MessageQueueStore,
        completed_parties: Arc<DashSet<RoleKind>>,
        network_mode: NetworkMode,
        conf: CoreToCoreNetworkConfig,
    ) -> Self {
        let timeout = match network_mode {
            // Since we discard active sessions after some time not receiving messages, we can use this as a timeout for async networking
            NetworkMode::Async => conf.get_discard_inactive_sessions_interval(),
            NetworkMode::Sync => conf.get_network_timeout(),
        };
        NetworkSession {
            owner,
            session_id,
            sending_channels,
            receiving_channels,
            round_counter: tokio::sync::RwLock::new(0),
            completed_parties,
            num_byte_sent: AtomicUsize::new(0),
            network_mode,
            conf,
            init_time: OnceLock::new(),
            last_rec_activity_time: AtomicU64::new(now_activity_millis()),
            current_network_timeout: AtomicDuration::new(timeout),
            next_network_timeout: AtomicDuration::new(timeout),
            max_elapsed_time: AtomicDuration::new(Duration::ZERO),
        }
    }

    /// Wait for the next packet from `sender`'s channel, applying the
    /// completed-party grace period.
    ///
    /// This isolates the subtlest control flow in [`Networking::receive`] (the
    /// nested `select!`) behind a small enum. The invariants:
    /// - If a packet is available on the channel it is always returned as
    ///   [`RecvOutcome::Packet`] — even when it arrives *during* the grace
    ///   period.
    /// - A plain tick while the sender is *not* completed yields
    ///   [`RecvOutcome::Retry`] (keep waiting), never a spurious abort.
    /// - The grace period is entered only once the sender has declared the
    ///   session complete, and only then can its timeout produce
    ///   [`RecvOutcome::Aborted`].
    ///
    /// Classification of the returned packet against the current round is the
    /// caller's job; this method only decides *whether* there is a packet.
    async fn recv_next<R: RoleTrait>(
        &self,
        rx: &mut tokio::sync::mpsc::Receiver<NetworkRoundValue>,
        tick_interval: &mut tokio::time::Interval,
        sender: &R,
    ) -> RecvOutcome {
        tokio::select! {
            _ = tick_interval.tick() => {
                tracing::warn!(
                    "Still waiting to receive from party {:?} for session {:?}",
                    sender,
                    self.session_id
                );
                if self.completed_parties.contains(&sender.get_role_kind()) {
                    // The sender has said the session is complete: wait one more
                    // grace period for any lingering in-flight message, but still
                    // deliver it if it arrives before the timeout.
                    tokio::select! {
                        _ = tokio::time::sleep(self.conf.get_max_waiting_time_for_message_queue()) => RecvOutcome::Aborted,
                        local_packet = rx.recv() => RecvOutcome::from_recv(local_packet),
                    }
                } else {
                    RecvOutcome::Retry
                }
            },
            local_packet = rx.recv() => RecvOutcome::from_recv(local_packet),
        }
    }

    fn inner_get_network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    async fn inner_set_timeout_for_next_round(&self, timeout: Duration) {
        match self.inner_get_network_mode() {
            NetworkMode::Sync => {
                self.next_network_timeout.store(timeout);
            }
            NetworkMode::Async => {
                tracing::warn!(
                    "Trying to change network timeout with async network, doesn't do anything"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use dashmap::{DashMap, DashSet};
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::channel;
    use tokio::task::JoinSet;

    use crate::grpc::GrpcNetworkingManager;
    use crate::grpc::{
        ChannelPair, CoreToCoreNetworkConfig, MessageQueueStore, NetworkRoundValue, ReceiverState,
        TlsExtensionGetter,
    };
    use crate::sending_service::{AtomicDuration, NetworkSession, now_activity_millis};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use test_utils::random_free_port::get_listeners_random_free_ports;
    use threshold_types::network::{NetworkMode, Networking};
    use threshold_types::party::{Identity, RoleAssignment};
    use threshold_types::role::{Role, RoleTrait, TwoSetsRole};
    use threshold_types::session_id::SessionId;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_network_stack() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 2).await.unwrap();
        let port_1 = listeners[0].1;
        let port_2 = listeners[1].1;
        drop(listeners);

        let sid = SessionId::from(0);
        let mut role_assignment = RoleAssignment::default();
        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new(format!("{ip_addr}"), port_1, None);
        let role_2 = Role::indexed_from_one(2);
        let id_2 = Identity::new(format!("{ip_addr}"), port_2, None);
        role_assignment.insert(role_1, id_1.clone());
        role_assignment.insert(role_2, id_2.clone());

        // Helper function to create and run a server
        async fn create_server(
            networking: &GrpcNetworkingManager,
            ip_addr: IpAddr,
            port: u16,
        ) -> (
            tokio::sync::oneshot::Sender<()>,
            tokio::task::JoinHandle<()>,
        ) {
            let (server_terminate_tx, server_terminate_rx) = tokio::sync::oneshot::channel::<()>();
            let networking_server = networking.new_server(TlsExtensionGetter::default());
            let core_grpc_layer = tower::ServiceBuilder::new().timeout(Duration::from_secs(300));
            let core_router = tonic::transport::Server::builder()
                .timeout(Duration::from_secs(300))
                .layer(core_grpc_layer)
                .add_service(networking_server);

            let core_future = core_router.serve_with_shutdown(
                format!("{ip_addr}:{port}").parse().unwrap(),
                async move {
                    let _ = server_terminate_rx.await;
                },
            );

            (
                server_terminate_tx,
                tokio::spawn(async move {
                    tracing::info!("Starting server on port {port}");
                    core_future.await.unwrap();
                    tracing::info!("Server on port {port} shut down");
                }),
            )
        }

        // Create channels for coordination
        let (terminate_sender_1, mut terminate_receiver_1) = tokio::sync::mpsc::channel::<()>(100);

        // Spawn sender (role_1)
        let sender_handle = {
            let role_assignment = role_assignment.clone();
            tokio::spawn(async move {
                let networking =
                    GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap();
                let network_session = networking
                    .make_network_session(sid, &role_assignment, role_1, NetworkMode::Sync)
                    .await
                    .unwrap();

                let msg = vec![1u8; 10];
                let arc_msg = Arc::new(msg.clone());

                // First send
                tracing::info!("Sending ONCE");
                network_session
                    .send(arc_msg.clone(), &role_2)
                    .await
                    .unwrap();

                // Wait for signal to send second message
                terminate_receiver_1.recv().await.unwrap();
                network_session.increase_round_counter().await;

                // Second send
                tracing::info!("Sending TWICE");
                network_session
                    .send(arc_msg.clone(), &role_2)
                    .await
                    .unwrap();

                // Wait for final termination signal
                terminate_receiver_1.recv().await.unwrap();
                (role_1, msg)
            })
        };

        // First receiver (role_2) - starts after delay, receives first message, then shuts down
        let first_receiver_handle = {
            let networking =
                GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap();
            let role_assignment = role_assignment.clone();
            let id_2 = id_2.clone();
            tokio::spawn(async move {
                // Wait before starting server to make sure sender retries
                tokio::time::sleep(Duration::from_secs(3)).await;

                let network_session = networking
                    .make_network_session(sid, &role_assignment, role_2, NetworkMode::Sync)
                    .await
                    .unwrap();

                let (server_terminate_tx, server_handle) =
                    create_server(&networking, ip_addr, id_2.port()).await;

                tracing::info!("Trying to receive");
                let msg = network_session.receive(&role_1).await.unwrap();
                tracing::info!("Received ONCE {msg:?}");

                // Signal server to shutdown
                server_terminate_tx.send(()).unwrap();
                server_handle.await.unwrap();

                // Return networking to avoid blocking drop inside the spawned task
                (role_2, msg, networking)
            })
        };

        // Wait for first receiver to complete
        let (role, msg, _networking_1) =
            tokio::time::timeout(Duration::from_secs(300), first_receiver_handle)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(role, role_2);
        assert_eq!(msg, vec![1u8; 10]);

        // Signal sender to send second message
        terminate_sender_1.send(()).await.unwrap();

        // Second receiver (role_2) - starts after longer delay, receives second message
        let second_receiver_handle = {
            let networking =
                GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap();
            let role_assignment = role_assignment.clone();
            tokio::spawn(async move {
                // Wait before starting server to make sure sender retries
                tokio::time::sleep(Duration::from_secs(3)).await;

                let network_session = networking
                    .make_network_session(sid, &role_assignment, role_2, NetworkMode::Sync)
                    .await
                    .unwrap();

                let (server_terminate_tx, server_handle) =
                    create_server(&networking, ip_addr, id_2.port()).await;

                // Increase round counter to receive second message
                network_session.increase_round_counter().await;

                tracing::info!("Trying to receive");
                let msg = network_session.receive(&role_1).await.unwrap();
                tracing::info!("Received TWICE {msg:?}");

                // Signal server to shutdown
                server_terminate_tx.send(()).unwrap();
                server_handle.await.unwrap();

                // Return networking to avoid blocking drop inside the spawned task
                (role_2, msg, networking)
            })
        };

        // Wait for second receiver to complete
        let (role, msg, _networking_2) =
            tokio::time::timeout(Duration::from_secs(150), second_receiver_handle)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(role, role_2);
        assert_eq!(msg, vec![1u8; 10]);

        // Signal sender to terminate
        terminate_sender_1.send(()).await.unwrap();

        // Wait for sender to complete
        let (role, msg) = tokio::time::timeout(Duration::from_secs(300), sender_handle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(role, role_1);
        assert_eq!(msg, vec![1u8; 10]);
    }

    #[tokio::test()]
    async fn test_network_session() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 2).await.unwrap();
        let port_1 = listeners[0].1;
        let port_2 = listeners[1].1;
        drop(listeners);

        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new(format!("{ip_addr}"), port_1, None);
        let role_2 = Role::indexed_from_one(2);
        let id_2 = Identity::new(format!("{ip_addr}"), port_2, None);

        let role_assignment = {
            let mut role_assignment = RoleAssignment::default();
            role_assignment.insert(role_1, id_1.clone());
            role_assignment.insert(role_2, id_2.clone());
            role_assignment
        };

        let channel_size_limit = 1000;

        // we manually initialize the message store instead of calling
        // [MessageQueueStore::new_initialized] because we want set the uninitialized channel
        // to test the session tracker
        let dummy_session_tracker = Arc::new(DashMap::new());
        let message_store = {
            let channel_maps = DashMap::new();
            let (tx, rx) = channel::<NetworkRoundValue>(channel_size_limit);
            let tx = Arc::new(tx);
            channel_maps.insert(
                id_2.mpc_identity(),
                ChannelPair {
                    tx: Arc::clone(&tx),
                    rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
                },
            );
            let mut out = MessageQueueStore::new_uninitialized(channel_maps);

            let mut others = role_assignment.clone();
            others.remove(&role_1);
            out.init(
                channel_size_limit,
                &others,
                Arc::clone(&dummy_session_tracker),
            );
            out
        };

        // session tracker should have one entry for party 2 since it was in the uninitialized variant
        assert_eq!(1, dummy_session_tracker.len());
        assert_eq!(
            0,
            *dummy_session_tracker
                .get(&id_2.mpc_identity())
                .unwrap()
                .value(),
        );

        let tx_2 = message_store.get_tx(&id_2.mpc_identity()).unwrap().unwrap();

        let session = NetworkSession {
            owner: id_1,
            session_id: SessionId::from(0),
            // no need to fill this channel because we're not forwading
            // messages to the networking service in this test
            sending_channels: HashMap::new(),
            receiving_channels: message_store,
            completed_parties: Arc::new(DashSet::new()),
            round_counter: tokio::sync::RwLock::new(0),
            num_byte_sent: AtomicUsize::new(0),
            network_mode: NetworkMode::Async,
            conf: CoreToCoreNetworkConfig::default(),
            init_time: OnceLock::new(),
            last_rec_activity_time: AtomicU64::new(now_activity_millis()),
            current_network_timeout: AtomicDuration::new(Duration::from_secs(10)),
            next_network_timeout: AtomicDuration::new(Duration::from_secs(10)),
            max_elapsed_time: AtomicDuration::new(Duration::ZERO),
        };

        // the test is role 2, the session is role 1
        // so we let role 2 send a message and role 1 should receive it
        {
            let expected = vec![1, 2, 3, 4, 5];
            let expected_clone = expected.clone();
            let tx_2 = tx_2.clone();
            tokio::spawn(async move {
                tx_2.send(NetworkRoundValue {
                    round_counter: 0,
                    value: expected_clone,
                })
                .await
                .unwrap();
            });

            let actual = session.receive(&role_2).await.unwrap();
            assert_eq!(actual, expected);
        }

        // try to send to a role that is not in the role assignment should fail
        {
            let e = session
                .send(Arc::new(vec![1, 2, 3]), &Role::indexed_from_one(3))
                .await
                .unwrap_err();
            assert!(e.to_string().contains("Missing local channel for"));
        }

        // set the round to be 5 and send messages with lower round counters
        // only the final message at round 5 should be received
        {
            for _ in 0..5 {
                <NetworkSession as Networking<Role>>::increase_round_counter(&session).await;
            }
            let tx_2 = tx_2.clone();

            let expected = vec![1, 2, 3, 4, 5];
            let expected_clone = expected.clone();
            tokio::spawn(async move {
                tx_2.send(NetworkRoundValue {
                    round_counter: 3,
                    value: vec![],
                })
                .await
                .unwrap();
                tx_2.send(NetworkRoundValue {
                    round_counter: 4,
                    value: vec![],
                })
                .await
                .unwrap();
                tx_2.send(NetworkRoundValue {
                    round_counter: 5,
                    value: expected_clone,
                })
                .await
                .unwrap();
            });

            let actual = session.receive(&role_2).await.unwrap();
            assert_eq!(actual, expected);
        }
    }

    /// Build a [`NetworkSession`] wired to a single sender channel, returning the
    /// session and a `Sender` on which a (possibly malicious) peer's messages can
    /// be enqueued directly, bypassing the gRPC layer. `channel_size_limit` bounds
    /// the mpsc so buffer-flooding tests can be exercised deterministically.
    fn make_test_session(
        channel_size_limit: usize,
    ) -> (
        NetworkSession,
        Role,
        Role,
        Arc<tokio::sync::mpsc::Sender<NetworkRoundValue>>,
    ) {
        make_test_session_with_conf(channel_size_limit, CoreToCoreNetworkConfig::default())
    }

    /// Like [`make_test_session`] but with an explicit config, so tests can
    /// exercise configurable knobs (e.g. `max_future_rounds` /
    /// `max_buffered_future_msgs`) rather than only their defaults.
    fn make_test_session_with_conf(
        channel_size_limit: usize,
        conf: CoreToCoreNetworkConfig,
    ) -> (
        NetworkSession,
        Role,
        Role,
        Arc<tokio::sync::mpsc::Sender<NetworkRoundValue>>,
    ) {
        let ip_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new(format!("{ip_addr}"), 1, None);
        let role_2 = Role::indexed_from_one(2);
        let id_2 = Identity::new(format!("{ip_addr}"), 2, None);

        let role_assignment = {
            let mut role_assignment = RoleAssignment::default();
            role_assignment.insert(role_1, id_1.clone());
            role_assignment.insert(role_2, id_2.clone());
            role_assignment
        };

        let dummy_session_tracker = Arc::new(DashMap::new());
        let message_store = {
            let channel_maps = DashMap::new();
            let (tx, rx) = channel::<NetworkRoundValue>(channel_size_limit);
            let tx = Arc::new(tx);
            channel_maps.insert(
                id_2.mpc_identity(),
                ChannelPair {
                    tx: Arc::clone(&tx),
                    rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
                },
            );
            let mut out = MessageQueueStore::new_uninitialized(channel_maps);
            let mut others = role_assignment.clone();
            others.remove(&role_1);
            out.init(
                channel_size_limit,
                &others,
                Arc::clone(&dummy_session_tracker),
            );
            out
        };

        let tx_2 = message_store.get_tx(&id_2.mpc_identity()).unwrap().unwrap();

        let session = NetworkSession {
            owner: id_1,
            session_id: SessionId::from(0),
            sending_channels: HashMap::new(),
            receiving_channels: message_store,
            completed_parties: Arc::new(DashSet::new()),
            round_counter: tokio::sync::RwLock::new(0),
            num_byte_sent: AtomicUsize::new(0),
            network_mode: NetworkMode::Async,
            conf,
            init_time: OnceLock::new(),
            last_rec_activity_time: AtomicU64::new(now_activity_millis()),
            current_network_timeout: AtomicDuration::new(Duration::from_secs(10)),
            next_network_timeout: AtomicDuration::new(Duration::from_secs(10)),
            max_elapsed_time: AtomicDuration::new(Duration::ZERO),
        };

        (session, role_1, role_2, tx_2)
    }

    /// A malicious authenticated peer controls the ordering of its own channel
    /// and the (unauthenticated) round counter of each packet. It places a
    /// round-5 packet at the head of the queue while the victim is still in
    /// round 0. `receive` must NOT deliver that future-round packet as the
    /// round-0 message: it must skip/buffer it and deliver the genuine round-0
    /// payload instead. Once the session advances to round 5, the buffered
    /// packet must then be delivered.
    #[tokio::test()]
    async fn test_future_round_not_delivered_early() {
        let (session, _role_1, role_2, tx_2) = make_test_session(1000);

        let future_payload = vec![5, 5, 5, 5, 5];
        let current_payload = vec![0, 0, 0, 0, 0];

        // Malicious ordering: future-round packet first, then the legitimate
        // current-round packet.
        tx_2.send(NetworkRoundValue {
            round_counter: 5,
            value: future_payload.clone(),
        })
        .await
        .unwrap();
        tx_2.send(NetworkRoundValue {
            round_counter: 0,
            value: current_payload.clone(),
        })
        .await
        .unwrap();

        // At round 0, we must get the round-0 payload, not the injected round-5 one.
        let actual = session.receive(&role_2).await.unwrap();
        assert_eq!(
            actual, current_payload,
            "receive at round 0 must return the round-0 payload, not the injected future-round one"
        );

        // Advance to round 5; the buffered round-5 payload must now be delivered
        // straight from the reordering buffer, without any new send.
        for _ in 0..5 {
            <NetworkSession as Networking<Role>>::increase_round_counter(&session).await;
        }
        let actual = session.receive(&role_2).await.unwrap();
        assert_eq!(
            actual, future_payload,
            "after advancing to round 5, the previously buffered round-5 payload must be delivered"
        );
    }

    /// A peer flooding many distinct future rounds must not grow the per-sender
    /// buffer without bound, and the legitimate current-round message must still
    /// be delivered.
    #[tokio::test()]
    async fn test_future_round_buffer_bounded() {
        use crate::constants::MAX_BUFFERED_FUTURE_MSGS;

        // Make sure the channel can hold the whole flood plus the current-round
        // message, so enqueue never blocks and the flood reaches `receive`.
        let flood = MAX_BUFFERED_FUTURE_MSGS + 50;
        let (session, _role_1, role_2, tx_2) = make_test_session(flood + 10);

        // Flood the channel with distinct future rounds (all >= 1, current is 0).
        for r in 1..=flood {
            tx_2.send(NetworkRoundValue {
                round_counter: r,
                value: vec![r as u8],
            })
            .await
            .unwrap();
        }

        // The genuine current-round (0) message arrives last.
        let current_payload = vec![42u8; 8];
        tx_2.send(NetworkRoundValue {
            round_counter: 0,
            value: current_payload.clone(),
        })
        .await
        .unwrap();

        // Despite the flood, the current-round message is delivered.
        let actual = session.receive(&role_2).await.unwrap();
        assert_eq!(actual, current_payload);

        // And the buffer stayed bounded.
        {
            let receiver_state = session
                .receiving_channels
                .get_receiver_state(&role_2)
                .unwrap()
                .unwrap();
            let state = receiver_state.lock().await;
            assert!(
                state.future.len() <= MAX_BUFFERED_FUTURE_MSGS,
                "future buffer must stay within MAX_BUFFERED_FUTURE_MSGS, got {}",
                state.future.len()
            );
        }
    }

    /// The reordering-buffer bounds come from the network config, not the
    /// compile-time constants. A session configured with a smaller window / cap
    /// must enforce the *configured* values — dropping messages the default
    /// bounds would have accepted.
    #[tokio::test()]
    async fn test_future_round_bounds_are_configurable() {
        // --- Configured look-ahead window (max_future_rounds = 2) ---
        {
            let conf = CoreToCoreNetworkConfig {
                max_future_rounds: Some(2),
                ..Default::default()
            };
            let (session, _role_1, role_2, tx_2) = make_test_session_with_conf(1000, conf);

            // Round 2 is within the configured window; round 5 is outside it
            // (yet inside the default window of 16, so this pins the config path).
            tx_2.send(NetworkRoundValue {
                round_counter: 2,
                value: vec![2],
            })
            .await
            .unwrap();
            tx_2.send(NetworkRoundValue {
                round_counter: 5,
                value: vec![5],
            })
            .await
            .unwrap();
            let current = vec![0u8; 4];
            tx_2.send(NetworkRoundValue {
                round_counter: 0,
                value: current.clone(),
            })
            .await
            .unwrap();

            assert_eq!(session.receive(&role_2).await.unwrap(), current);

            let rx = session
                .receiving_channels
                .get_receiver_state(&role_2)
                .unwrap()
                .unwrap();
            let state = rx.lock().await;

            // Keep the round 2 message, but drop round 5's: it is outside the configured window.
            assert!(
                state.future.contains_key(&2),
                "round 2 is within the configured window and must be buffered"
            );
            assert!(
                !state.future.contains_key(&5),
                "round 5 is outside the configured window of 2 and must be dropped"
            );
        }

        // --- Configured per-sender cap (max_buffered_future_msgs = 2) ---
        {
            let conf = CoreToCoreNetworkConfig {
                // Wide window so the cap, not the window, is what bites.
                max_future_rounds: Some(1000),
                max_buffered_future_msgs: Some(2),
                ..Default::default()
            };
            let (session, _role_1, role_2, tx_2) = make_test_session_with_conf(1000, conf);

            for r in 1..=5 {
                tx_2.send(NetworkRoundValue {
                    round_counter: r,
                    value: vec![r as u8],
                })
                .await
                .unwrap();
            }
            let current = vec![9u8; 4];
            tx_2.send(NetworkRoundValue {
                round_counter: 0,
                value: current.clone(),
            })
            .await
            .unwrap();

            assert_eq!(session.receive(&role_2).await.unwrap(), current);

            let rx = session
                .receiving_channels
                .get_receiver_state(&role_2)
                .unwrap()
                .unwrap();
            let state = rx.lock().await;
            assert_eq!(
                state.future.len(),
                2,
                "buffer must be capped at the configured max_buffered_future_msgs (2), not the default"
            );
        }
    }

    /// Two payloads tagged with the same future round must not overwrite each
    /// other: the first-buffered value wins and delivery is deterministic.
    #[tokio::test()]
    async fn test_future_round_duplicate_does_not_overwrite() {
        let (session, _role_1, role_2, tx_2) = make_test_session(1000);

        let first = vec![1u8; 4];
        let second = vec![2u8; 4];

        // Two packets for the same future round 2, plus the current-round packet.
        tx_2.send(NetworkRoundValue {
            round_counter: 2,
            value: first.clone(),
        })
        .await
        .unwrap();
        tx_2.send(NetworkRoundValue {
            round_counter: 2,
            value: second.clone(),
        })
        .await
        .unwrap();
        let current_payload = vec![9u8; 4];
        tx_2.send(NetworkRoundValue {
            round_counter: 0,
            value: current_payload.clone(),
        })
        .await
        .unwrap();

        // Round 0 delivers the current-round payload.
        let actual = session.receive(&role_2).await.unwrap();
        assert_eq!(actual, current_payload);

        // Advance to round 2: the first buffered value wins (or_insert), the
        // duplicate is discarded — no panic, deterministic result.
        for _ in 0..2 {
            <NetworkSession as Networking<Role>>::increase_round_counter(&session).await;
        }
        let actual = session.receive(&role_2).await.unwrap();
        assert_eq!(
            actual, first,
            "the first value buffered for a round must win over a later duplicate"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_set_network() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 4).await.unwrap();
        let ports: Vec<u16> = listeners.iter().map(|(_, p)| *p).collect();
        drop(listeners);

        let sid = SessionId::from(0);
        let mut role_assignment = RoleAssignment::default();
        // Create the roles from Set 1
        let role_1_set_1 = TwoSetsRole::OnlySet1(Role::indexed_from_one(1));
        let id_1_set_1 = Identity::new(format!("{ip_addr}"), ports[0], None);
        let role_2_set_1 = TwoSetsRole::OnlySet1(Role::indexed_from_one(2));
        let id_2_set_1 = Identity::new(format!("{ip_addr}"), ports[1], None);

        // Create the roles from Set 2
        let role_1_set_2 = TwoSetsRole::OnlySet2(Role::indexed_from_one(1));
        let id_1_set_2 = Identity::new(format!("{ip_addr}"), ports[2], None);
        let role_2_set_2 = TwoSetsRole::OnlySet2(Role::indexed_from_one(2));
        let id_2_set_2 = Identity::new(format!("{ip_addr}"), ports[3], None);

        role_assignment.insert(role_1_set_1, id_1_set_1.clone());
        role_assignment.insert(role_2_set_1, id_2_set_1.clone());
        role_assignment.insert(role_1_set_2, id_1_set_2.clone());
        role_assignment.insert(role_2_set_2, id_2_set_2.clone());

        let expected_message = Arc::new(HashMap::from([
            (role_1_set_1, vec![1; 10]),
            (role_2_set_1, vec![2; 10]),
            (role_1_set_2, vec![3; 10]),
            (role_2_set_2, vec![4; 10]),
        ]));

        // Keep a Vec for collecting results
        let mut server_handles = JoinSet::new();
        let mut client_handles = JoinSet::new();
        for (role, id) in role_assignment.iter() {
            let role = *role;
            let my_port = id.port();

            let mut others = role_assignment.clone();
            others.remove(&role);

            // Spin up gRPC server for current Role
            let networking =
                GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap();
            let networking_server = networking.new_server(TlsExtensionGetter::default());
            let core_grpc_layer = tower::ServiceBuilder::new().timeout(Duration::from_secs(300));
            let core_router = tonic::transport::Server::builder()
                .timeout(Duration::from_secs(300))
                .layer(core_grpc_layer)
                .add_service(networking_server);
            let core_future = core_router.serve(format!("{ip_addr}:{my_port}").parse().unwrap());

            // Spawn server
            let my_role = role;
            server_handles.spawn(async move {
                println!("Starting server on {my_role:?}");
                core_future.await.unwrap();
                println!("Server on {my_role:?} shut down");
            });

            // Spawn client, sending my expected message to all,
            // receiving all others' expected messages
            let expected_message = Arc::clone(&expected_message);
            let role_assignment = role_assignment.clone();
            client_handles.spawn(async move {
                // Create network session for current Role
                let network_session = networking
                    .make_network_session(sid, &role_assignment, role, NetworkMode::Sync)
                    .await
                    .unwrap();
                let msg = Arc::new(expected_message.get(&role).unwrap().clone());
                for other in others.keys() {
                    network_session.send(msg.clone(), other).await.unwrap();
                }

                let mut results = HashMap::new();
                for other in others.keys() {
                    let received_msg = network_session.receive(other).await.unwrap();
                    assert_eq!(
                        received_msg,
                        *expected_message.get(other).unwrap(),
                        "Error receiving message from {} in {}",
                        other,
                        role
                    );
                    results.insert(*other, received_msg);
                }
                (role, results)
            });
        }

        while let Some(res) = client_handles.join_next().await {
            let (role, results) = res.unwrap();
            for (other_role, received_msg) in results.iter() {
                assert_eq!(
                    received_msg,
                    expected_message.get(other_role).unwrap(),
                    "Error in final check for {} in {}",
                    other_role,
                    role
                );
            }
        }
    }

    /// Build a [`CoreToCoreNetworkConfig`] identical to the defaults, except for a configurable
    /// `max_waiting_time_for_message_queue` so that tests don't have to wait the default 60s.
    fn test_config(max_waiting_time_secs: u64) -> CoreToCoreNetworkConfig {
        CoreToCoreNetworkConfig {
            message_limit: Some(70),
            multiplier: Some(1.1),
            max_interval: Some(60),
            max_elapsed_time: Some(60),
            initial_interval_ms: Some(100),
            network_timeout: Some(120),
            network_timeout_bk: Some(300),
            network_timeout_bk_sns: Some(1200),
            max_en_decode_message_size: Some(2 * 1024 * 1024 * 1024),
            session_update_interval_secs: Some(60),
            session_cleanup_interval_secs: Some(86400),
            discard_inactive_sessions_interval: Some(15 * 60),
            max_waiting_time_for_message_queue: Some(max_waiting_time_secs),
            max_opened_inactive_sessions_per_party: Some(2000),
            max_future_rounds: Some(16),
            max_buffered_future_msgs: Some(32),
        }
    }

    /// Regression test for the bug fixed in PR #624.
    ///
    /// Scenario (2 parties, role 1 is receiver, role 2 is sender):
    /// 1. Role 2 is marked as a `completed_parties`.
    /// 2. Role 1 calls `receive` for role 2. No message is in the queue yet, so the `tick_interval`
    ///    fires and we enter the "grace period".
    /// 3. While we are inside that grace-period, Role 2 sends a message
    ///
    /// Before the fix, that message was received from the channel but the branch evaluated to
    /// `None`, so the packet was silently discarded and the loop kept spinning until the
    /// session was aborted. After the fix, the in-flight message is
    /// returned.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_message_not_dropped_during_completed_grace_period() {
        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 2).await.unwrap();
        let port_1 = listeners[0].1;
        let port_2 = listeners[1].1;
        drop(listeners);

        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new(format!("{ip_addr}"), port_1, None);
        let role_2 = Role::indexed_from_one(2);
        let id_2 = Identity::new(format!("{ip_addr}"), port_2, None);

        let role_assignment = {
            let mut role_assignment = RoleAssignment::default();
            role_assignment.insert(role_1, id_1.clone());
            role_assignment.insert(role_2, id_2.clone());
            role_assignment
        };

        let channel_size_limit = 1000;
        let dummy_session_tracker = Arc::new(DashMap::new());
        let message_store = {
            let channel_maps = DashMap::new();
            let (tx, rx) = channel::<NetworkRoundValue>(channel_size_limit);
            let tx = Arc::new(tx);
            channel_maps.insert(
                id_2.mpc_identity(),
                ChannelPair {
                    tx: Arc::clone(&tx),
                    rx: Arc::new(Mutex::new(ReceiverState::new(rx))),
                },
            );
            let mut out = MessageQueueStore::new_uninitialized(channel_maps);

            let mut others = role_assignment.clone();
            others.remove(&role_1);
            out.init(
                channel_size_limit,
                &others,
                Arc::clone(&dummy_session_tracker),
            );
            out
        };

        // Get handle on the mpsc Sender channel to send the message on behalf of Role 2
        // (don't go through the gRPC API for simplicity)
        let tx_2 = message_store.get_tx(&id_2.mpc_identity()).unwrap().unwrap();

        // Mark role 2 as a completed party: this is the precondition that activates the buggy
        // grace-period branch in `receive`.
        let completed_parties = Arc::new(DashSet::new());
        completed_parties.insert(role_2.get_role_kind());

        // Use a 1s waiting time.
        let wait = Duration::from_secs(1);
        let session = NetworkSession {
            owner: id_1,
            session_id: SessionId::from(0),
            sending_channels: HashMap::new(),
            receiving_channels: message_store,
            completed_parties,
            round_counter: tokio::sync::RwLock::new(0),
            num_byte_sent: AtomicUsize::new(0),
            network_mode: NetworkMode::Async,
            conf: test_config(1),
            init_time: OnceLock::new(),
            last_rec_activity_time: AtomicU64::new(now_activity_millis()),
            current_network_timeout: AtomicDuration::new(wait),
            next_network_timeout: AtomicDuration::new(wait),
            max_elapsed_time: AtomicDuration::new(Duration::ZERO),
        };

        let expected = vec![42u8; 8];
        let expected_clone = expected.clone();
        // Send the message *after* the first tick has fired (1s) but before the grace-period
        // sleep (another 1s) elapses,
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            tx_2.send(NetworkRoundValue {
                round_counter: 0,
                value: expected_clone,
            })
            .await
            .unwrap();
        });

        // Bound the whole receive so a regression times out.
        let actual = tokio::time::timeout(Duration::from_secs(10), session.receive(&role_2))
            .await
            .expect("receive should not time out; a timeout means the message was dropped")
            .expect("receive should return the in-flight message, not an abort error");

        assert_eq!(
            actual, expected,
            "the message that arrived during the completed-party grace period must be delivered"
        );
    }
}
