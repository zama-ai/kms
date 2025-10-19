use dashmap::DashMap;
use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

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

use crate::{error::error_handler::anyhow_error_and_log, execution::runtime::party::Identity};
use crate::{
    execution::runtime::party::{Role, RoleAssignment},
    session_id::SessionId,
};

#[cfg(feature = "choreographer")]
use super::grpc::NETWORK_RECEIVED_MEASUREMENT;
use super::grpc::{MessageQueueStore, OptionConfigWrapper, Tag};
use super::{NetworkMode, Networking};
use crate::thread_handles::ThreadHandleGroup;

use super::gen::SendValueRequest;

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
        other: Identity,
    ) -> anyhow::Result<UnboundedSender<ArcSendValueRequest>>;

    ///Adds multiple connections at once
    async fn add_connections(
        &self,
        others: &RoleAssignment,
    ) -> anyhow::Result<HashMap<Role, UnboundedSender<ArcSendValueRequest>>>;
}

#[derive(Debug, Clone)]
pub struct GrpcSendingService {
    /// Contains all the information needed by the sync network
    pub(crate) config: OptionConfigWrapper,
    /// A ready-made TLS identity (certificate, keypair and CA roots)
    pub(crate) tls_config: Option<ClientConfig>,
    /// Whether to use TCP proxies on localhost to access peers
    peer_tcp_proxy: bool,
    /// Keep in memory channels we already have available
    channel_map:
        DashMap<Identity, GnetworkingClient<InterceptedService<Channel, ContextPropagator>>>,
    /// Network task threads
    thread_handles: Arc<RwLock<ThreadHandleGroup>>,
}

impl GrpcSendingService {
    /// Create the network channel between self and the grpc server of the other party
    /// or retrieve it if one already exists
    pub(crate) async fn connect_to_party(
        &self,
        receiver: Identity,
    ) -> anyhow::Result<GnetworkingClient<InterceptedService<Channel, ContextPropagator>>> {
        if let Some(channel) = self.channel_map.get(&receiver) {
            tracing::debug!("Channel to {:?} already existed, retrieving it.", receiver);
            return Ok(channel.clone());
        }

        let proto = match self.tls_config {
            Some(_) => "https",
            None => "http",
        };
        tracing::debug!("Creating {} channel to '{}'", proto, receiver);
        
        // Determine the actual endpoint to connect to
        // If using peer_tcp_proxy (enclave mode), rewrite to localhost regardless of TLS
        let endpoint: Uri = if self.peer_tcp_proxy {
            format!("{}://localhost:{}", proto, receiver.port())
                .parse()
                .map_err(|_e| {
                    anyhow_error_and_log(format!(
                        "failed to parse proxy endpoint with port: {}",
                        receiver.port()
                    ))
                })?
        } else {
            format!("{proto}://{receiver}").parse().map_err(|_e| {
                anyhow_error_and_log(format!("failed to parse identity as endpoint: {receiver}"))
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

                let endpoint = Channel::builder(endpoint).http2_adaptive_window(true);
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
                tracing::warn!("Building channel to {:?} without TLS", endpoint.host());
                Channel::builder(endpoint)
                    .http2_adaptive_window(true)
                    .connect_lazy()
            }
        };
        let client = GnetworkingClient::with_interceptor(channel, ContextPropagator)
            .max_decoding_message_size(self.config.get_max_en_decode_message_size())
            .max_encoding_message_size(self.config.get_max_en_decode_message_size());
        self.channel_map.insert(receiver, client.clone());
        Ok(client)
    }

    async fn run_network_task(
        mut receiver: UnboundedReceiver<ArcSendValueRequest>,
        network_channel: GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        exponential_backoff: ExponentialBackoff<SystemClock>,
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
                    .map(|_| ())
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
                    "Network retry for message: {e:?} - Duration {:?} secs",
                    duration.as_secs()
                );
            };

            // Single unified retry strategy
            let res = retry_notify(exponential_backoff.clone(), send_fn, on_network_fail).await;

            if let Err(status) = res {
                incorrectly_sent += 1;
                tracing::warn!(
                    "Failed to send message after retries: {} - {}",
                    status.code(),
                    status.message()
                );
            }
        }

        if received_request == 0 {
            // This is not necessarily an error since we may use the network to only receive in certain protocols
            tracing::info!("No more listeners, nothing happened, shutting down network task");
        } else if incorrectly_sent == received_request {
            tracing::error!("No more listeners, everything failed, {incorrectly_sent} errors, shutting down network task");
        } else if incorrectly_sent > 0 {
            tracing::warn!(
                "Network task finished with: {incorrectly_sent}/{received_request} errors"
            );
        } else {
            tracing::info!("Network task succeeded and transmitted {received_request} values");
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
            channel_map: DashMap::new(),
        })
    }

    /// Adds one connection and outputs the mpsc Sender channel other processes will use to communicate to other
    async fn add_connection(
        &self,
        other: Identity,
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
        let handle = tokio::spawn(async move {
            // Run the actual network task (already logs completion status)
            Self::run_network_task(receiver, network_channel, exponential_backoff).await;
        });

        // 5. Minimize lock scope - acquire write lock last and release immediately
        let mut handles = self.thread_handles.write().await;
        handles.add(handle);

        Ok(sender)
    }

    ///Adds multiple connections at once
    async fn add_connections(
        &self,
        others: &RoleAssignment,
    ) -> anyhow::Result<HashMap<Role, UnboundedSender<ArcSendValueRequest>>> {
        let mut result = HashMap::with_capacity(others.len());

        for (other_role, other_id) in others.iter() {
            match self.add_connection(other_id.clone()).await {
                Ok(sender) => {
                    result.insert(*other_role, sender);
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
    pub(crate) context_id: SessionId,
    /// MPSC channels that are filled by parties and dealt with by the [`SendingService`]
    /// Sending channels for this session
    pub(crate) sending_channels: HashMap<Role, UnboundedSender<ArcSendValueRequest>>,
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
    pub(crate) init_time: RwLock<Option<Instant>>,
    pub(crate) current_network_timeout: RwLock<Duration>,
    pub(crate) next_network_timeout: RwLock<Duration>,
    pub(crate) max_elapsed_time: RwLock<Duration>,
}

#[async_trait]
impl Networking for NetworkSession {
    /// WARNING: [`increase_round_counter`] MUST be called right before sending.
    /// In particular a call to [`receive`] cannot be interleaved between a counter increase and a send.
    /// Thus sending and receiving MUST not be interleaved.
    ///
    //Note this need not be async, so do we want to keep the trait definition async
    //if we want to add other implems which may require async ?
    async fn send(&self, value: Arc<Vec<u8>>, receiver: &Role) -> anyhow::Result<()> {
        // Lock the counter to ensure no modifications happens while sending
        // This may cause an error if someone tries to increase the round counter at the same time
        // however, this would imply incorrect use of the networking API and thus we want to fail fast.
        let round_counter = *self.round_counter.read().await;
        let tagged_value = Tag {
            session_id: self.session_id,
            context_id: self.context_id,
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
        match self.sending_channels.get(receiver) {
            Some(channel) => Ok(channel.send(request)?),
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
    async fn receive(&self, sender: &Role) -> anyhow::Result<Vec<u8>> {
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

        let mut local_packet = rx
            .recv()
            .await
            .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel."))?;

        // check that the message has the correct context and ID
        if self.context_id != local_packet.context_id {
            return Err(anyhow_error_and_log(format!(
                "Received message with incorrect context. Expected {}, got {}",
                self.context_id, local_packet.context_id
            )));
        }

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

        // Update next round timeout
        // most of the time it might not change
        // but this is needed because next_round_timeout might've been updated
        *current_round_timeout = *next_round_timeout;

        //Update round counter
        *net_round += 1;
        tracing::debug!(
            "changed network round to: {:?} on party: {:?}, with timeout: {:?}",
            *net_round,
            self.owner,
            *current_round_timeout
        );
    }

    ///Used to compute the deadline in network functions
    async fn get_deadline_current_round(&self) -> Instant {
        let mut init_time_guard = self.init_time.write().await;
        let init_time = *(*init_time_guard).get_or_insert(Instant::now());

        let (max_elapsed_time, network_timeout) = (
            self.max_elapsed_time.read().await,
            self.current_network_timeout.read().await,
        );
        init_time + *network_timeout + *max_elapsed_time
    }

    async fn get_timeout_current_round(&self) -> Duration {
        *self.current_network_timeout.read().await
    }

    async fn reset_timeout(&self, init_time: Instant, elapsed_time: Duration) {
        let mut init_time_guard = self.init_time.write().await;
        *init_time_guard = Some(init_time);

        let mut elapsed_time_guard = self.max_elapsed_time.write().await;
        *elapsed_time_guard = elapsed_time;
    }

    async fn get_current_round(&self) -> usize {
        *self.round_counter.read().await
    }

    /// Method to set a different timeout than the one set at construction, effective for the next round.
    ///
    /// __NOTE__: If the network mode is Async, this has no effect
    async fn set_timeout_for_next_round(&self, timeout: Duration) {
        match self.get_network_mode() {
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

    /// Method to set the timeout for distributed generation of the TFHE bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    async fn set_timeout_for_bk(&self) {
        self.set_timeout_for_next_round(self.conf.get_network_timeout_bk())
            .await
    }

    /// Method to set the timeout for distributed generation of the TFHE switch and squash bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    async fn set_timeout_for_bk_sns(&self) {
        self.set_timeout_for_next_round(self.conf.get_network_timeout_bk_sns())
            .await
    }

    fn get_network_mode(&self) -> NetworkMode {
        self.network_mode
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

#[cfg(test)]
mod tests {
    use dashmap::DashMap;
    use tokio::sync::mpsc::channel;
    use tokio::sync::{Mutex, RwLock};

    use crate::networking::grpc::{
        MessageQueueStore, NetworkRoundValue, OptionConfigWrapper, TlsExtensionGetter,
    };
    use crate::networking::sending_service::NetworkSession;
    use crate::thread_handles::OsThreadGroup;
    use crate::{
        execution::runtime::party::{Identity, Role, RoleAssignment},
        networking::{grpc::GrpcNetworkingManager, Networking},
        session_id::SessionId,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
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

        let context_id = SessionId::from(42);

        // Keep a Vec for collecting results
        let mut handles = OsThreadGroup::new();
        for (role, id) in role_assignment.iter() {
            // Wait a little while to make sure retry works fine
            std::thread::sleep(Duration::from_secs(5));
            let role = *role;
            let my_port = id.port();
            let id = id.clone();

            let networking_1 = GrpcNetworkingManager::new(None, None, false).unwrap();

            let network_session_1 = networking_1
                .make_network_session(
                    sid,
                    context_id,
                    &role_assignment,
                    role,
                    crate::networking::NetworkMode::Sync,
                )
                .await
                .unwrap();

            handles.add(std::thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let _guard = runtime.enter();

                let (send, recv) = tokio::sync::oneshot::channel();
                if role.one_based() == 1 {
                    tokio::spawn(async move {
                        let msg = Arc::new(vec![1u8; 10]);
                        println!("Sending ONCE");
                        network_session_1.send(msg.clone(), &role_2).await.unwrap();
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        println!("Sending TWICE");
                        network_session_1.send(msg.clone(), &role_2).await.unwrap();
                        send.send(msg).unwrap();
                    });
                    //Keep this std thread alive for a while
                    std::thread::sleep(Duration::from_secs(20));
                } else {
                    let networking_server_1 =
                        networking_1.new_server(TlsExtensionGetter::default());
                    let core_grpc_layer =
                        tower::ServiceBuilder::new().timeout(Duration::from_secs(3));

                    let core_router = tonic::transport::Server::builder()
                        .timeout(Duration::from_secs(3))
                        .layer(core_grpc_layer)
                        .add_service(networking_server_1);

                    let core_future =
                        core_router.serve(format!("127.0.0.1:{my_port}").parse().unwrap());
                    tokio::spawn(async move {
                        println!("Spinning up server on {id:?}");
                        let _res = futures::join!(core_future);
                    });
                    tokio::spawn(async move {
                        println!("Trying to receive");
                        let msg = Arc::new(network_session_1.receive(&role_1).await.unwrap());
                        println!("Received ONCE {msg:?}");
                        send.send(msg).unwrap();
                    });
                }
                recv.blocking_recv().unwrap();
                println!("Thread for {role} exiting");
            }));
        }

        let networking_2 = GrpcNetworkingManager::new(None, None, false).unwrap();
        let networking_server_2 = networking_2.new_server(TlsExtensionGetter::default());
        let network_session_2 = networking_2
            .make_network_session(
                sid,
                context_id,
                &role_assignment,
                role_2,
                crate::networking::NetworkMode::Sync,
            )
            .await
            .unwrap();

        let port_p2 = id_2.port();
        handles.add(std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _guard = runtime.enter();

            let core_grpc_layer = tower::ServiceBuilder::new().timeout(Duration::from_secs(3));

            let core_router = tonic::transport::Server::builder()
                .timeout(Duration::from_secs(3))
                .layer(core_grpc_layer)
                .add_service(networking_server_2);

            let core_future = core_router.serve(format!("127.0.0.1:{port_p2}").parse().unwrap());

            tokio::spawn(async move {
                println!("Spinning up second server");
                let _res = futures::join!(core_future);
            });

            let (send, recv) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                println!("Ready to receive");
                let msg = network_session_2.receive(&role_1).await.unwrap();
                println!("Received TWICE {msg:?}");
                send.send(Arc::new(msg)).unwrap();
            });
            recv.blocking_recv().unwrap();
            println!("Second thread exiting");
        }));

        // Join all threads and collect results
        let results = handles.join_all_with_results().unwrap();

        // Check results
        let ref_res = results.first().unwrap();
        for res in results.iter() {
            assert_eq!(res, ref_res);
        }
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
        let context_id = SessionId::from(42);

        let session = NetworkSession {
            owner: id_1,
            session_id: SessionId::from(0),
            context_id,
            // no need to fill this channel because we're not forwading
            // messages to the networking service in this test
            sending_channels: HashMap::new(),
            receiving_channels: message_store,
            round_counter: tokio::sync::RwLock::new(0),
            #[cfg(feature = "choreographer")]
            num_byte_sent: RwLock::new(0),
            network_mode: crate::networking::NetworkMode::Async,
            conf: OptionConfigWrapper { conf: None },
            init_time: RwLock::new(None),
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
                    context_id,
                    round_counter: 0,
                    value: expected_clone,
                })
                .await
                .unwrap();
            });

            let actual = session.receive(&role_2).await.unwrap();
            assert_eq!(actual, expected);
        }

        // try to send again but use the wrong context ID
        // it should be rejected
        {
            let tx_2 = tx_2.clone();
            tokio::spawn(async move {
                tx_2.send(NetworkRoundValue {
                    context_id: SessionId::from(123),
                    round_counter: 1,
                    value: vec![],
                })
                .await
                .unwrap();
            });

            let _ = session.receive(&role_2).await.unwrap_err();
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
                session.increase_round_counter().await;
            }
            let tx_2 = tx_2.clone();

            let expected = vec![1, 2, 3, 4, 5];
            let expected_clone = expected.clone();
            tokio::spawn(async move {
                tx_2.send(NetworkRoundValue {
                    context_id,
                    round_counter: 3,
                    value: vec![],
                })
                .await
                .unwrap();
                tx_2.send(NetworkRoundValue {
                    context_id,
                    round_counter: 4,
                    value: vec![],
                })
                .await
                .unwrap();
                tx_2.send(NetworkRoundValue {
                    context_id,
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
}
