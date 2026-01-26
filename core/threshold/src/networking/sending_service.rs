use std::{
    collections::{hash_map::Entry, HashMap},
    net::IpAddr,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use super::gen::gnetworking_client::GnetworkingClient;
use backoff::exponential::ExponentialBackoff;
use backoff::future::retry_notify;
use backoff::SystemClock;
use hyper_rustls_ring::{FixedServerNameResolver, HttpsConnectorBuilder};
use observability::telemetry::ContextPropagator;
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        RwLock,
    },
    time::{Duration, Instant},
};
use tokio_rustls::rustls::{client::ClientConfig, pki_types::ServerName};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Uri;
use tonic::{async_trait, transport::Channel};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::runtime::party::{Identity, RoleKind, RoleTrait},
    networking::constants::NETWORKING_INTERVAL_LOGS_WAITING_SENDER,
    networking::r#gen::Status,
};
use crate::{execution::runtime::party::RoleAssignment, session_id::SessionId};

use super::gen::SendValueRequest;
#[cfg(feature = "choreographer")]
use super::grpc::NETWORK_RECEIVED_MEASUREMENT;
use super::grpc::{MessageQueueStore, OptionConfigWrapper, Tag};
use super::{NetworkMode, Networking};
use crate::thread_handles::ThreadHandleGroup;

pub struct ArcSendValueRequest {
    tag: Arc<Vec<u8>>,
    value: Arc<Vec<u8>>,
}

impl ArcSendValueRequest {
    fn deep_clone(&self) -> SendValueRequest {
        SendValueRequest {
            tag: self.tag.as_ref().clone(),
            value: self.value.as_ref().clone(),
        }
    }
}

#[async_trait]
pub trait SendingService: Send + Sync {
    /// Init and start the sending service
    fn new(
        tls_certs: Option<ClientConfig>,
        conf: OptionConfigWrapper,
        peer_tcp_proxy: bool,
    ) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized;

    /// Adds one connection and outputs the mpsc Sender channel other processes will use to communicate to other
    async fn add_connection(
        &self,
        other: &Identity,
        abort_sender: UnboundedSender<()>,
    ) -> anyhow::Result<UnboundedSender<ArcSendValueRequest>>;

    ///Adds multiple connections at once
    async fn add_connections<R: RoleTrait>(
        &self,
        others: &RoleAssignment<R>,
    ) -> anyhow::Result<
        HashMap<RoleKind, (UnboundedSender<ArcSendValueRequest>, UnboundedReceiver<()>)>,
    >;
}

type ChannelMap =
    HashMap<Identity, GnetworkingClient<InterceptedService<Channel, ContextPropagator>>>;

#[derive(Debug, Clone)]
pub struct GrpcSendingService {
    /// Contains all the information needed by the sync network
    pub(crate) config: OptionConfigWrapper,
    /// A ready-made TLS identity (certificate, keypair and CA roots)
    pub(crate) tls_config: Option<ClientConfig>,
    /// Whether to use TCP proxies on localhost to access peers
    peer_tcp_proxy: bool,
    /// Keep in memory channels we already have available
    channel_map: Arc<RwLock<ChannelMap>>,
    /// Network task threads
    thread_handles: Arc<RwLock<ThreadHandleGroup>>,
}

impl GrpcSendingService {
    /// Create the network channel between self and the grpc server of the other party
    /// or retrieve it if one already exists
    pub(crate) async fn connect_to_party(
        &self,
        receiver: &Identity,
    ) -> anyhow::Result<GnetworkingClient<InterceptedService<Channel, ContextPropagator>>> {
        if let Some(channel) = self.channel_map.read().await.get(receiver) {
            tracing::debug!("Channel to {:?} already existed, retrieving it.", receiver);
            return Ok(channel.clone());
        }

        // Hold a write lock on the entry to avoid duplicate connections
        let mut channel_map_write_lock = self.channel_map.write().await;
        let entry = channel_map_write_lock.entry(receiver.clone());

        // First thing we do is re-check whether connection has been established while waiting for the lock
        if let Entry::Occupied(channel) = entry {
            tracing::debug!(
                "Channel to {:?} was created while waiting for the lock, retrieving it.",
                receiver
            );
            return Ok(channel.get().clone());
        }

        let proto = match self.tls_config {
            Some(_) => "https",
            None => "http",
        };
        tracing::debug!("Creating {} channel to '{}'", proto, receiver);
        // When running within the AWS Nitro enclave, we have to go through
        // vsock proxies to make TCP connections to peers.
        let endpoint: Uri = if self.peer_tcp_proxy {
            format!("{proto}://localhost:{}", receiver.port())
                .parse::<Uri>()
                .map_err(|_e| {
                    anyhow_error_and_log(format!(
                        "failed to parse peer proxy address with port: {}",
                        receiver.port()
                    ))
                })?
        } else {
            format!("{proto}://{receiver}").parse().map_err(|_e| {
                anyhow_error_and_log(format!(
                    "failed to parse peer network address as endpoint: {receiver}"
                ))
            })?
        };

        let channel = match &self.tls_config {
            Some(client_config) => {
                // If the host is an IP address then we abort
                // domain names are needed for TLS.
                //
                // This is because we could run the parties with the
                // same IP address for all parties but using different ports,
                // but we cannot map the port number to certificates.
                if IpAddr::from_str(receiver.hostname()).is_ok() {
                    return Err(anyhow_error_and_log(format!(
                        "{} is an IP address, which is not supported for TLS",
                        receiver.hostname()
                    )));
                }
                let domain_name = ServerName::try_from(receiver.hostname().to_string())
                    .map_err(|_e| {
                        anyhow_error_and_log(format!(
                            "The MPC party hostname {} is not a valid DNS name",
                            receiver.hostname()
                        ))
                    })?
                    .to_owned();

                tracing::debug!(
                    "Attempting TLS connection to address {:?} with MPC identity {:?}",
                    endpoint,
                    domain_name
                );

                // Use the TLS_NODELAY mode to ensure everything gets sent immediately by disabling Nagle's algorithm.
                // Note that this decreases latency but increases network bandwidth usage. If bandwidth is a concern,
                // then this should be changed
                let endpoint = Channel::builder(endpoint)
                    .http2_adaptive_window(true)
                    .tcp_nodelay(true);
                // we have to pass a custom TLS connector to
                // tonic::transport::Channel to be able to use a custom rustls
                // ClientConfig that overrides the certificate verifier for AWS
                // Nitro attestation
                let https_connector = HttpsConnectorBuilder::new()
                    .with_tls_config(client_config.clone())
                    .https_only()
                    .with_server_name_resolver(FixedServerNameResolver::new(domain_name))
                    .enable_http2()
                    .build();
                Channel::new(https_connector, endpoint)
            }
            None => {
                tracing::warn!("Building channel to {:?} without TLS", endpoint);
                // Use the TLS_NODELAY mode to ensure everything gets sent immediately by disabling Nagle's algorithm.
                // Note that this decreases latency but increases network bandwidth usage. If bandwidth is a concern,
                // then this should be changed
                Channel::builder(endpoint)
                    .http2_adaptive_window(true)
                    .tcp_nodelay(true)
                    .connect_lazy()
            }
        };
        let client = GnetworkingClient::with_interceptor(channel, ContextPropagator)
            .max_decoding_message_size(self.config.get_max_en_decode_message_size())
            .max_encoding_message_size(self.config.get_max_en_decode_message_size());
        entry.insert_entry(client.clone());
        Ok(client)
    }

    async fn run_network_task(
        mut receiver: UnboundedReceiver<ArcSendValueRequest>,
        network_channel: GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        exponential_backoff: ExponentialBackoff<SystemClock>,
        other: &Identity,
        abort_sender: UnboundedSender<()>,
    ) {
        let mut received_request = 0;
        let mut incorrectly_sent = 0;

        while let Some(value) = receiver.recv().await {
            received_request += 1;
            let send_fn = || async {
                let value = value.deep_clone();
                network_channel
                    .clone()
                    .send_value(value)
                    .await
                    .map(|inner| inner.into_inner())
                    .map_err(|status| {
                        // All errors are transient and retryable
                        backoff::Error::Transient {
                            err: status,
                            retry_after: None,
                        }
                    })
            };

            let on_network_fail = |e, duration: Duration| {
                tracing::debug!(
                    "Network retry for message: {e:?} - Duration {:?} secs. Talking to {other}.",
                    duration.as_secs()
                );
            };

            // Single unified retry strategy
            let res: Result<_, _> =
                retry_notify(exponential_backoff.clone(), send_fn, on_network_fail).await;
            match res {
                Ok(send_response) => {
                    if send_response.status() == Status::Completed {
                        // Failed to have receiver accept the message
                        // Send abort signal and break since we can only send once
                        if abort_sender.send(()).is_err() {
                            tracing::warn!(
                                "Failed to send abort signal to network task for {other}"
                            );
                        }
                        // TODO should we actually break or instead increase error count and continue ?
                        break;
                    }
                }
                Err(status) => {
                    incorrectly_sent += 1;
                    tracing::warn!(
                    "Failed to send message to {other} after {incorrectly_sent} retries: {} - {}",
                    status.code(),
                    status.message()
                );
                }
            };
        }

        if received_request == 0 {
            // This is not necessarily an error since we may use the network to only receive in certain protocols
            tracing::debug!(
                "No more listeners on {other}, nothing happened, shutting down network task without errors."
            );
        } else if incorrectly_sent == received_request {
            tracing::error!("No more listeners on {other}, everything failed, {incorrectly_sent} errors, shutting down network task");
        } else if incorrectly_sent > 0 {
            tracing::warn!(
                "Network task with {other} finished with: {incorrectly_sent}/{received_request} errors"
            );
        } else {
            tracing::debug!(
                "Network task with {other} succeeded and transmitted {received_request} values"
            );
        }
    }

    /// Shut down the sending service.
    pub fn shutdown(&mut self) {
        match Arc::get_mut(&mut self.thread_handles) {
            Some(lock) => {
                let handles = std::mem::take(RwLock::get_mut(lock));
                match handles.join_all_blocking() {
                    Ok(_) => tracing::info!(
                        "Successfully cleaned up all handles in grpc sending service"
                    ),
                    Err(e) => tracing::error!("Error joining threads on drop: {}", e),
                }
            }
            None => {
                tracing::warn!("Thread handles are still referenced elsewhere, skipping cleanup")
            }
        }
        tracing::info!("dropped grpc sending service");
    }
}

#[async_trait]
impl SendingService for GrpcSendingService {
    /// Communicates with the service thread to spin up a new connection with `other`
    /// __NOTE__: This requires the service to be running already
    fn new(
        tls_config: Option<ClientConfig>,
        config: OptionConfigWrapper,
        peer_tcp_proxy: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            tls_config,
            peer_tcp_proxy,
            thread_handles: Arc::new(RwLock::new(ThreadHandleGroup::new())),
            channel_map: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Adds one connection and outputs the mpsc Sender channel other processes will use to communicate to other
    async fn add_connection(
        &self,
        other: &Identity,
        abort_sender: UnboundedSender<()>,
    ) -> anyhow::Result<UnboundedSender<ArcSendValueRequest>> {
        // 1. Create channel first (no allocation issues)
        let (sender, receiver) = unbounded_channel::<ArcSendValueRequest>();

        // 2. Connect to party (can fail, so do before any spawning)
        let network_channel = self.connect_to_party(other).await?;

        // 3. Configurable backoff with initial_interval from config
        let exponential_backoff = ExponentialBackoff::<SystemClock> {
            initial_interval: self.config.get_initial_interval(), // Configurable start
            max_elapsed_time: self.config.get_max_elapsed_time(),
            max_interval: self.config.get_max_interval(),
            multiplier: self.config.get_multiplier(),
            ..Default::default()
        };

        // 4. Single spawn with integrated error handling (eliminates double-spawn overhead)
        let other = other.clone();
        let handle = tokio::spawn(async move {
            // Run the actual network task (already logs completion status)
            Self::run_network_task(
                receiver,
                network_channel,
                exponential_backoff,
                &other,
                abort_sender,
            )
            .await;
        });

        // 5. Minimize lock scope - acquire write lock last and release immediately
        let mut handles = self.thread_handles.write().await;
        handles.add(handle);

        Ok(sender)
    }

    ///Adds multiple connections at once
    async fn add_connections<R: RoleTrait>(
        &self,
        others: &RoleAssignment<R>,
    ) -> anyhow::Result<
        HashMap<RoleKind, (UnboundedSender<ArcSendValueRequest>, UnboundedReceiver<()>)>,
    > {
        let mut result = HashMap::with_capacity(others.len());

        for (other_role, other_id) in others.iter() {
            let (abort_sender, abort_receiver) = tokio::sync::mpsc::unbounded_channel();
            match self.add_connection(other_id, abort_sender).await {
                Ok(sender) => {
                    result.insert(other_role.get_role_kind(), (sender, abort_receiver));
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to establish connection to {} with role {}: {}",
                        other_id,
                        other_role,
                        e
                    );
                    return Err(e);
                }
            }
        }
        Ok(result)
    }
}

impl Drop for GrpcSendingService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

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
    /// MPSC channels that are filled by parties and dealt with by the [`SendingService`]
    /// Sending channels for this session
    pub(crate) sending_channels:
        HashMap<RoleKind, (UnboundedSender<ArcSendValueRequest>, UnboundedReceiver<()>)>,
    /// Channels which are filled by the grpc server receiving messages from the other parties
    /// owned by the session and thus automatically cleaned up on drop
    pub(crate) receiving_channels: MessageQueueStore,
    // Round counter for the current session, behind a lock to be able to update it without a mut ref to self
    // Observe tokio lock is needed since it must be held across an await point
    pub(crate) round_counter: tokio::sync::RwLock<usize>,
    // Measure the number of bytes sent by this session
    #[cfg(feature = "choreographer")]
    pub(crate) num_byte_sent: RwLock<usize>,
    // Network mode is either async or sync
    pub(crate) network_mode: NetworkMode,
    // If Network mode is sync, we need to keep track of the values below to make sure
    // we are within time bound
    pub(crate) conf: OptionConfigWrapper,
    pub(crate) init_time: OnceLock<Instant>,
    pub(crate) current_network_timeout: RwLock<Duration>,
    pub(crate) next_network_timeout: RwLock<Duration>,
    pub(crate) max_elapsed_time: RwLock<Duration>,
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
        // Lock the counter to ensure no modifications happens while sending
        // This may cause an error if someone tries to increase the round counter at the same time
        // however, this would imply incorrect use of the networking API and thus we want to fail fast.
        let round_counter = *self.round_counter.read().await;
        let tagged_value = Tag {
            session_id: self.session_id,
            sender: self.owner.mpc_identity(),
            round_counter,
        };

        let tag = Arc::new(
            bc2wrap::serialize(&tagged_value)
                .map_err(|e| anyhow_error_and_log(format!("networking error: {e:?}")))?,
        );

        #[cfg(feature = "choreographer")]
        {
            let mut sent = self.num_byte_sent.write().await;
            *sent += tag.len() + value.len();
        }
        let request = ArcSendValueRequest { tag, value };

        //Retrieve the local channel that corresponds to the party we want to send to and push into it
        match self.sending_channels.get(&receiver.get_role_kind()) {
            Some((sending_channel, _abort_receiver)) => Ok(sending_channel.send(request)?),
            None => Err(anyhow_error_and_log(format!(
                "Missing local channel for {receiver:?}"
            ))),
        }?;
        Ok(())
    }

    /// Receives messages from other parties, assuming the grpc server filled the [`MessageQueueStores`] correctly
    ///
    /// WARNING: A call to [`receive`] cannot be interleaved between a counter increase and a send.
    /// Thus sending and receiving MUST not be interleaved.
    async fn receive(&self, sender: &R) -> anyhow::Result<Vec<u8>> {
        // Lock the counter to ensure no modifications happens while receiving
        // This may cause an error if someone tries to increase the round counter at the same time
        // however, this would imply incorrect use of the networking API and thus we want to fail fast.
        let counter_lock = self.round_counter.read().await;
        let rx = self.receiving_channels.get_rx(sender)?.ok_or_else(|| {
            anyhow_error_and_log(format!(
                "couldn't retrieve receiving channel for P:{sender:?}"
            ))
        })?;
        let mut rx = rx.lock().await;

        tracing::debug!("Waiting to receive from {:?}", sender);

        let mut log_interval = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(NETWORKING_INTERVAL_LOGS_WAITING_SENDER),
            Duration::from_secs(NETWORKING_INTERVAL_LOGS_WAITING_SENDER),
        );
        let mut local_packet = loop {
            let packet = tokio::select! {
                    _ = log_interval.tick() => {
                        tracing::warn!("Still waiting to receive from party {:?} for session {:?}", sender, self.session_id);
                        None
                    },
                    local_packet = rx.recv() => Some(local_packet)
            };
            if let Some(local_packet) = packet {
                break local_packet;
            }
        }
        .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel."))?;

        // drop old messages
        let network_round = *counter_lock;
        while local_packet.round_counter < network_round {
            let val_len = local_packet.value.len();
            tracing::debug!(
                "@ round {} - dropped value {:?} from round {}",
                network_round,
                local_packet.value[..if val_len < 16 { val_len } else { 16 }].to_vec(),
                local_packet.round_counter
            );
            local_packet = rx
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel."))?;
        }

        Ok(local_packet.value)
    }

    /// Increase the round counter
    ///
    /// __NOTE__: We always assume this is called right before sending happens
    async fn increase_round_counter(&self) {
        let (mut max_elapsed_time, mut current_round_timeout, next_round_timeout, mut net_round) = (
            self.max_elapsed_time.write().await,
            self.current_network_timeout.write().await,
            self.next_network_timeout.read().await,
            self.round_counter.write().await,
        );

        *max_elapsed_time += *current_round_timeout;

        //Update next round timeout
        *current_round_timeout = *next_round_timeout;

        //Update round counter
        *net_round += 1;
        tracing::debug!(
            "changed network round to: {:?} on party: {:?}, with timeout: {:?}",
            *net_round,
            self.owner,
            *current_round_timeout
        )
    }

    ///Used to compute the timeout in network functions
    async fn get_timeout_current_round(&self) -> Instant {
        let init_time = self.init_time.get_or_init(Instant::now);
        let (max_elapsed_time, network_timeout) = (
            self.max_elapsed_time.read().await,
            self.current_network_timeout.read().await,
        );
        *init_time + *network_timeout + *max_elapsed_time
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

    #[cfg(feature = "choreographer")]
    async fn get_num_byte_sent(&self) -> usize {
        *self.num_byte_sent.read().await
    }

    #[cfg(feature = "choreographer")]
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
    fn inner_get_network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    async fn inner_set_timeout_for_next_round(&self, timeout: Duration) {
        match self.inner_get_network_mode() {
            NetworkMode::Sync => {
                let mut next_network_timeout = self.next_network_timeout.write().await;
                *next_network_timeout = timeout;
            }
            NetworkMode::Async => {
                tracing::warn!(
                    "Trying to change network timeout with async network, doesn't do anything"
                );
            }
        }
    }

    // Check if the session has been aborted by a quorum of other parties refusing the connection
    pub fn is_aborted(&self) -> bool {
        let mut abort_ctr = 0;
        let keys: Vec<_> = self.sending_channels.keys().cloned().collect();
        for cur_id in keys {
            let abort_received = self
                .sending_channels
                .get(&cur_id)
                .map(|(_, abort_receiver)| {
                    // Check if we have received an abort signal
                    !abort_receiver.is_empty()
                })
                .unwrap_or(false);
            if abort_received {
                abort_ctr += 1;
            }
        }
        if abort_ctr >= 4 {
            // TODO threshold!!!
            tracing::warn!(
                "Session {} aborted due to quorum of parties refusing connection",
                self.session_id
            );
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use dashmap::DashMap;
    use tokio::sync::mpsc::channel;
    use tokio::sync::{Mutex, RwLock};
    use tokio::task::JoinSet;

    use crate::execution::runtime::party::TwoSetsRole;
    use crate::networking::grpc::{
        MessageQueueStore, NetworkRoundValue, OptionConfigWrapper, TlsExtensionGetter,
    };
    use crate::networking::sending_service::NetworkSession;
    use crate::networking::NetworkMode;
    use crate::{
        execution::runtime::party::{Identity, Role, RoleAssignment},
        networking::{grpc::GrpcNetworkingManager, Networking},
        session_id::SessionId,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread")]
    #[tracing_test::traced_test]
    async fn test_network_stack() {
        let sid = SessionId::from(0);
        let mut role_assignment = RoleAssignment::default();
        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new("127.0.0.1".to_string(), 6001, None);
        let role_2 = Role::indexed_from_one(2);
        let id_2 = Identity::new("127.0.0.1".to_string(), 6002, None);
        role_assignment.insert(role_1, id_1.clone());
        role_assignment.insert(role_2, id_2.clone());

        // Helper function to create and run a server
        async fn create_server(
            networking: &GrpcNetworkingManager,
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
                format!("127.0.0.1:{port}").parse().unwrap(),
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
                let networking = GrpcNetworkingManager::new(None, None, false).unwrap();
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
            let networking = GrpcNetworkingManager::new(None, None, false).unwrap();
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
                    create_server(&networking, id_2.port()).await;

                tracing::info!("Trying to receive");
                let msg = network_session.receive(&role_1).await.unwrap();
                tracing::info!("Received ONCE {msg:?}");

                // Signal server to shutdown
                server_terminate_tx.send(()).unwrap();
                server_handle.await.unwrap();

                (role_2, msg)
            })
        };

        // Wait for first receiver to complete
        let (role, msg) = tokio::time::timeout(Duration::from_secs(300), first_receiver_handle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(role, role_2);
        assert_eq!(msg, vec![1u8; 10]);

        // Signal sender to send second message
        terminate_sender_1.send(()).await.unwrap();

        // Second receiver (role_2) - starts after longer delay, receives second message
        let second_receiver_handle = {
            let networking = GrpcNetworkingManager::new(None, None, false).unwrap();
            let role_assignment = role_assignment.clone();
            tokio::spawn(async move {
                // Wait before starting server to make sure sender retries
                tokio::time::sleep(Duration::from_secs(3)).await;

                let network_session = networking
                    .make_network_session(sid, &role_assignment, role_2, NetworkMode::Sync)
                    .await
                    .unwrap();

                let (server_terminate_tx, server_handle) =
                    create_server(&networking, id_2.port()).await;

                // Increase round counter to receive second message
                network_session.increase_round_counter().await;

                tracing::info!("Trying to receive");
                let msg = network_session.receive(&role_1).await.unwrap();
                tracing::info!("Received TWICE {msg:?}");

                // Signal server to shutdown
                server_terminate_tx.send(()).unwrap();
                server_handle.await.unwrap();

                (role_2, msg)
            })
        };

        // Wait for second receiver to complete
        let (role, msg) = tokio::time::timeout(Duration::from_secs(300), second_receiver_handle)
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
        let role_1 = Role::indexed_from_one(1);
        let id_1 = Identity::new("127.0.0.1".to_string(), 6001, None);
        let role_2 = Role::indexed_from_one(2);
        let id_2 = Identity::new("127.0.0.1".to_string(), 6002, None);

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
                (Arc::clone(&tx), Arc::new(Mutex::new(rx))),
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
            round_counter: tokio::sync::RwLock::new(0),
            #[cfg(feature = "choreographer")]
            num_byte_sent: RwLock::new(0),
            network_mode: crate::networking::NetworkMode::Async,
            conf: OptionConfigWrapper { conf: None },
            init_time: OnceLock::new(),
            current_network_timeout: RwLock::new(Duration::from_secs(10)),
            next_network_timeout: RwLock::new(Duration::from_secs(10)),
            max_elapsed_time: RwLock::new(Duration::from_secs(0)),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_set_network() {
        let sid = SessionId::from(0);
        let mut role_assignment = RoleAssignment::default();
        // Create the roles from Set 1
        let role_1_set_1 = TwoSetsRole::Set1(Role::indexed_from_one(1));
        let id_1_set_1 = Identity::new("127.0.0.1".to_string(), 6001, None);
        let role_2_set_1 = TwoSetsRole::Set1(Role::indexed_from_one(2));
        let id_2_set_1 = Identity::new("127.0.0.1".to_string(), 6002, None);

        // Create the roles from Set 2
        let role_1_set_2 = TwoSetsRole::Set2(Role::indexed_from_one(1));
        let id_1_set_2 = Identity::new("127.0.0.1".to_string(), 6003, None);
        let role_2_set_2 = TwoSetsRole::Set2(Role::indexed_from_one(2));
        let id_2_set_2 = Identity::new("127.0.0.1".to_string(), 6004, None);

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
            let networking = GrpcNetworkingManager::new(None, None, false).unwrap();
            let networking_server = networking.new_server(TlsExtensionGetter::default());
            let core_grpc_layer = tower::ServiceBuilder::new().timeout(Duration::from_secs(300));

            let core_router = tonic::transport::Server::builder()
                .timeout(Duration::from_secs(300))
                .layer(core_grpc_layer)
                .add_service(networking_server);

            let core_future = core_router.serve(format!("127.0.0.1:{my_port}").parse().unwrap());

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
                    .make_network_session(
                        sid,
                        &role_assignment,
                        role,
                        crate::networking::NetworkMode::Sync,
                    )
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
}
