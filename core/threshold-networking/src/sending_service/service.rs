//! The outbound transport: [`GrpcSendingService`] connects to peers and runs the
//! per-peer retry/backoff task that pushes messages out over gRPC.

use std::collections::{HashMap, hash_map::Entry};
use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::ggen::SendValueRequest;
use crate::ggen::Status;
use crate::ggen::gnetworking_client::GnetworkingClient;
use crate::grpc::CoreToCoreNetworkConfig;
use backoff::SystemClock;
use backoff::exponential::ExponentialBackoff;
use backoff::future::retry_notify;
use dashmap::DashSet;
use error_utils::anyhow_error_and_log;
use hyper_rustls_ring::{FixedServerNameResolver, HttpsConnectorBuilder};
use observability::telemetry::ContextPropagator;
use threshold_types::party::{Identity, RoleAssignment};
use threshold_types::role::{RoleKind, RoleTrait};
use tokio::sync::{
    RwLock,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_rustls::rustls::{client::ClientConfig, pki_types::ServerName};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Uri;
use tonic::{async_trait, transport::Channel};

pub struct ArcSendValueRequest {
    tag: Arc<Vec<u8>>,
    value: Arc<Vec<u8>>,
}

impl ArcSendValueRequest {
    /// Build a request from an already-serialized tag and value. Used by
    /// [`NetworkSession::send`](super::NetworkSession) (a sibling module), which
    /// cannot name the private fields directly.
    pub(crate) fn new(tag: Arc<Vec<u8>>, value: Arc<Vec<u8>>) -> Self {
        Self { tag, value }
    }

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
    fn new(tls_certs: Option<ClientConfig>, conf: CoreToCoreNetworkConfig) -> anyhow::Result<Self>
    where
        Self: std::marker::Sized;

    /// Adds one connection and outputs the mpsc Sender channel other processes will use to communicate to other
    async fn add_connection(
        &self,
        other_identity: &Identity,
        other_role_kind: RoleKind,
        aborted: Arc<DashSet<RoleKind>>,
    ) -> anyhow::Result<UnboundedSender<ArcSendValueRequest>>;

    ///Adds multiple connections at once
    async fn add_connections<R: RoleTrait>(
        &self,
        others: &RoleAssignment<R>,
    ) -> anyhow::Result<(
        HashMap<RoleKind, UnboundedSender<ArcSendValueRequest>>,
        Arc<DashSet<RoleKind>>,
    )>;
}

type ChannelMap =
    HashMap<Identity, GnetworkingClient<InterceptedService<Channel, ContextPropagator>>>;

#[derive(Debug, Clone)]
pub struct GrpcSendingService {
    /// Contains all the information needed by the sync network
    pub(crate) config: CoreToCoreNetworkConfig,
    /// A ready-made TLS identity (certificate, keypair and CA roots)
    pub(crate) tls_config: Option<ClientConfig>,
    /// Keep in memory channels we already have available
    channel_map: Arc<RwLock<ChannelMap>>,
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
        let endpoint: Uri = format!("{proto}://{receiver}").parse().map_err(|_e| {
            anyhow_error_and_log(format!(
                "failed to parse peer network address as endpoint: {receiver}"
            ))
        })?;

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

                // Use the TCP_NODELAY mode to ensure everything gets sent immediately by disabling Nagle's algorithm.
                // Note that this decreases latency but increases network bandwidth usage. If bandwidth is a concern,
                // then this should be changed
                let endpoint = Channel::builder(endpoint)
                    .http2_adaptive_window(true)
                    // Large HTTP/2 flow-control windows so per-stream throughput
                    // is not capped at 64KiB/RTT over the added-latency vsock
                    // tunnel (tonic default is 65535B stream + connection).
                    // adaptive_window can still grow beyond this floor.
                    .initial_stream_window_size(4u32 * 1024 * 1024)
                    .initial_connection_window_size(32u32 * 1024 * 1024)
                    // Keep idle P2P connections alive so the tunnel/NAT does not
                    // silently drop them (a drop = full TCP+TLS re-handshake mid-DKG).
                    .http2_keep_alive_interval(Duration::from_secs(20))
                    .keep_alive_timeout(Duration::from_secs(10))
                    .keep_alive_while_idle(true)
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
                // Use the TCP_NODELAY mode to ensure everything gets sent immediately by disabling Nagle's algorithm.
                // Note that this decreases latency but increases network bandwidth usage. If bandwidth is a concern,
                // then this should be changed
                Channel::builder(endpoint)
                    .http2_adaptive_window(true)
                    // See TLS branch above: large windows + keepalive to tolerate
                    // the added-latency tunnel.
                    .initial_stream_window_size(4u32 * 1024 * 1024)
                    .initial_connection_window_size(32u32 * 1024 * 1024)
                    .http2_keep_alive_interval(Duration::from_secs(20))
                    .keep_alive_timeout(Duration::from_secs(10))
                    .keep_alive_while_idle(true)
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
        other_role_kind: RoleKind,
        completed_parties: Arc<DashSet<RoleKind>>,
    ) {
        let mut received_request = 0;
        let mut incorrectly_sent = 0;
        let mut skipped = 0;
        let mut receiver_completed = false;

        while let Some(value) = receiver.recv().await {
            received_request += 1;

            if receiver_completed {
                skipped += 1;
                continue;
            }

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
                    "Network retry for message: {e:?} - Duration {:?} secs. Talking to {other_role_kind}.",
                    duration.as_secs()
                );
            };

            // Single unified retry strategy
            let res: Result<_, _> =
                retry_notify(exponential_backoff.clone(), send_fn, on_network_fail).await;
            match res {
                Ok(send_response) => {
                    match send_response.status() {
                        Status::Active => {
                            // All good, nothing to do
                        }
                        Status::Inactive => {
                            // The receiver is inactive
                            tracing::warn!("Receiver {other_role_kind} is inactive.");
                        }
                        Status::Completed => {
                            // The receiver already completed this session.
                            // Do not break — that would drop the receiver and cause
                            // "channel closed" errors on subsequent sends.
                            // Instead, mark as completed and drain remaining messages.
                            completed_parties.insert(other_role_kind);
                            tracing::warn!(
                                "Failed to send message to {other_role_kind} party since it claims the session is already completed"
                            );
                            incorrectly_sent += 1;
                            receiver_completed = true;
                        }
                    };
                }
                Err(status) => {
                    incorrectly_sent += 1;
                    tracing::warn!(
                        "Failed to send message to {other_role_kind} after {incorrectly_sent} retries: {} - {} (source: {:?})",
                        status.code(),
                        status.message(),
                        status.source()
                    );
                }
            };
        }

        if received_request == 0 {
            // This is not necessarily an error since we may use the network to only receive in certain protocols
            tracing::debug!(
                "No more listeners on {other_role_kind}, nothing happened, shutting down network task without errors."
            );
        } else if incorrectly_sent == received_request {
            tracing::error!(
                "No more listeners on {other_role_kind}, everything failed, {incorrectly_sent} errors, shutting down network task"
            );
        } else if incorrectly_sent > 0 {
            tracing::warn!(
                "Network task with {other_role_kind} finished with: {incorrectly_sent} errors, {skipped} skipped, {received_request} total requests"
            );
        } else {
            tracing::debug!(
                "Network task with {other_role_kind} succeeded and transmitted {received_request} values"
            );
        }
    }
}

#[async_trait]
impl SendingService for GrpcSendingService {
    /// Communicates with the service thread to spin up a new connection with `other`
    /// __NOTE__: This requires the service to be running already
    fn new(
        tls_config: Option<ClientConfig>,
        config: CoreToCoreNetworkConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            tls_config,
            channel_map: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Adds one connection and outputs the mpsc Sender channel other processes will use to communicate to other
    async fn add_connection(
        &self,
        other_identity: &Identity,
        other_role_kind: RoleKind,
        aborted: Arc<DashSet<RoleKind>>,
    ) -> anyhow::Result<UnboundedSender<ArcSendValueRequest>> {
        // 1. Create channel first (no allocation issues)
        let (sender, receiver) = unbounded_channel::<ArcSendValueRequest>();

        // 2. Connect to party (can fail, so do before any spawning)
        let network_channel = self.connect_to_party(other_identity).await?;

        // 3. Configurable backoff with initial_interval from config
        let exponential_backoff = ExponentialBackoff::<SystemClock> {
            initial_interval: self.config.get_initial_interval(), // Configurable start
            max_elapsed_time: self.config.get_max_elapsed_time(),
            max_interval: self.config.get_max_interval(),
            multiplier: self.config.get_multiplier(),
            ..Default::default()
        };

        // 4. Spawns the sender in its own task and discard the handle
        tokio::spawn(Self::run_network_task(
            receiver,
            network_channel,
            exponential_backoff,
            other_role_kind,
            aborted,
        ));

        Ok(sender)
    }

    ///Adds multiple connections at once
    async fn add_connections<R: RoleTrait>(
        &self,
        others: &RoleAssignment<R>,
    ) -> anyhow::Result<(
        HashMap<RoleKind, UnboundedSender<ArcSendValueRequest>>,
        Arc<DashSet<RoleKind>>,
    )> {
        let mut result = HashMap::with_capacity(others.len());

        let aborted = Arc::new(DashSet::new());
        for (other_role, other_id) in others.iter() {
            let other_role_kind = other_role.get_role_kind();
            match self
                .add_connection(other_id, other_role_kind, Arc::clone(&aborted))
                .await
            {
                Ok(sender) => {
                    result.insert(other_role_kind, sender);
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
        Ok((result, aborted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::random_free_port::get_listeners_random_free_ports;

    /// Verify that after receiving `Status::Completed`, the `UnboundedReceiver` is NOT dropped, so
    /// subsequent sends on the `UnboundedSender` do not fail with "channel closed".
    /// See here for context: https://github.com/zama-ai/kms-internal/issues/2948
    #[tokio::test(flavor = "multi_thread")]
    async fn test_run_network_task_does_not_drop_receiver_on_completed() {
        use crate::ggen::gnetworking_server::{Gnetworking, GnetworkingServer};
        use crate::ggen::{
            HealthCheckRequest, HealthCheckResponse, SendValueRequest, SendValueResponse, Status,
        };
        use backoff::ExponentialBackoff;
        use tokio::sync::mpsc::unbounded_channel;

        // Mock gRPC server that always returns Status::Completed
        struct AlwaysCompletedServer;

        #[tonic::async_trait]
        impl Gnetworking for AlwaysCompletedServer {
            async fn send_value(
                &self,
                _request: tonic::Request<SendValueRequest>,
            ) -> Result<tonic::Response<SendValueResponse>, tonic::Status> {
                Ok(tonic::Response::new(SendValueResponse {
                    status: Status::Completed as i32,
                }))
            }

            async fn health_check(
                &self,
                _request: tonic::Request<HealthCheckRequest>,
            ) -> Result<tonic::Response<HealthCheckResponse>, tonic::Status> {
                unimplemented!()
            }
        }

        let ip_addr = "127.0.0.1".parse().unwrap();
        let listeners = get_listeners_random_free_ports(&ip_addr, 1).await.unwrap();
        let myport = listeners[0].1;
        drop(listeners);

        let (server_terminate_tx, server_terminate_rx) = tokio::sync::oneshot::channel::<()>();
        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(GnetworkingServer::new(AlwaysCompletedServer))
                .serve_with_shutdown(format!("{ip_addr}:{myport}").parse().unwrap(), async move {
                    let _ = server_terminate_rx.await;
                })
                .await
                .unwrap();
        });

        // Connect a client with the required interceptor type, retrying until the server is ready
        let endpoint = format!("http://{ip_addr}:{myport}");
        let connect_timeout = Duration::from_secs(5);
        let start = tokio::time::Instant::now();
        let channel = loop {
            match tonic::transport::Channel::from_shared(endpoint.clone())
                .unwrap()
                .connect_timeout(connect_timeout)
                .connect()
                .await
            {
                Ok(channel) => break channel,
                Err(e) => {
                    if start.elapsed() >= connect_timeout {
                        panic!(
                            "failed to connect to test server at {} within {:?}: {}",
                            endpoint, connect_timeout, e
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };

        let client = crate::ggen::gnetworking_client::GnetworkingClient::with_interceptor(
            channel,
            observability::telemetry::ContextPropagator,
        );

        // Create channel and shared state
        let (sender, receiver) = unbounded_channel::<ArcSendValueRequest>();
        let completed_parties = Arc::new(DashSet::new());
        let role_kind = threshold_types::role::Role::indexed_from_one(1).get_role_kind();

        let backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(5)),
            ..Default::default()
        };

        // Spawn the network task
        let task_handle = tokio::spawn(GrpcSendingService::run_network_task(
            receiver,
            client,
            backoff,
            role_kind,
            Arc::clone(&completed_parties),
        ));

        // Send first message — triggers Status::Completed
        let msg = ArcSendValueRequest::new(Arc::new(vec![1, 2, 3]), Arc::new(vec![4, 5, 6]));
        assert!(sender.send(msg).is_ok(), "first send should succeed");

        // Wait (with timeout) for the task to process the Completed response
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if completed_parties.contains(&role_kind) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("completed_parties should contain the role after Status::Completed");

        // Send a second message — with the old `break` bug, this would fail
        // because the receiver was dropped. With the fix, the receiver is
        // still alive (draining), so this succeeds.
        let msg2 = ArcSendValueRequest::new(Arc::new(vec![7, 8, 9]), Arc::new(vec![10, 11, 12]));
        assert!(
            sender.send(msg2).is_ok(),
            "second send should succeed — receiver must not be dropped after Completed"
        );

        // Drop sender so the task can finish
        drop(sender);
        tokio::time::timeout(Duration::from_secs(300), task_handle)
            .await
            .unwrap()
            .unwrap();

        // Shut down the server
        let _ = server_terminate_tx.send(());
        tokio::time::timeout(Duration::from_secs(300), server_handle)
            .await
            .unwrap()
            .unwrap();
    }
}
