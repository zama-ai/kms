//! The outbound transport: [`GrpcSendingService`] connects to peers and runs the
//! per-peer retry/backoff task that pushes messages out over gRPC.

use std::collections::{HashMap, hash_map::Entry};
use std::error::Error;
use std::future::Future;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::ggen::SendValueRequest;
use crate::ggen::Status;
use crate::ggen::gnetworking_client::GnetworkingClient;
use crate::grpc::CoreToCoreNetworkConfig;
use backoff::SystemClock;
use backoff::backoff::Backoff;
use backoff::exponential::ExponentialBackoff;
use dashmap::DashSet;
use error_utils::anyhow_error_and_log;
use hyper_rustls_ring::{FixedServerNameResolver, HttpsConnectorBuilder};
use observability::metrics::{self, NetworkDebugEvent};
use observability::telemetry::ContextPropagator;
use threshold_types::party::{Identity, RoleAssignment};
use threshold_types::role::{RoleKind, RoleTrait};
use tokio::sync::{
    RwLock,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio::time::{Instant, sleep, timeout_at};
use tokio_rustls::rustls::{client::ClientConfig, pki_types::ServerName};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Uri;
use tonic::{async_trait, transport::Channel};

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
    ) -> anyhow::Result<UnboundedSender<SendValueRequest>>;

    ///Adds multiple connections at once
    async fn add_connections<R: RoleTrait>(
        &self,
        others: &RoleAssignment<R>,
    ) -> anyhow::Result<(
        HashMap<RoleKind, UnboundedSender<SendValueRequest>>,
        Arc<DashSet<RoleKind>>,
    )>;
}

type ChannelMap =
    HashMap<Identity, GnetworkingClient<InterceptedService<Channel, ContextPropagator>>>;

/// Retries a message, with a backoff wait between attempts.
///
/// Before each attempt and after each failure, the sender checks whether its session has closed.
/// Once it notices closure, the message gets a limited time to finish. Retries and the waits
/// between them use the same allowance; a retry does not reset it.
/// Closing the session does not interrupt a send or a backoff wait that was already under way.
async fn send_with_retry<T, F, Fut>(
    mut send: F,
    is_closed: impl Fn() -> bool,
    mut backoff: impl Backoff,
    drain_timeout: Duration,
    peer: RoleKind,
) -> Result<T, tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, tonic::Status>>,
{
    backoff.reset();
    // Live sessions use only the backoff policy; the drain deadline starts once closure is observed.
    let mut deadline = None;
    let mut last_error = None;
    let deadline_error = |last_error: Option<&tonic::Status>| {
        let mut message = format!(
            "message delivery stopped by the {drain_timeout:?} allowance after observing session closure"
        );
        if let Some(error) = last_error {
            message.push_str(&format!("; last RPC error: {error}"));
        }
        tonic::Status::deadline_exceeded(message)
    };
    loop {
        // Start the allowance once; retries must not extend it.
        if deadline.is_none() && is_closed() {
            deadline = Some(Instant::now() + drain_timeout);
        }
        let result = if let Some(deadline) = deadline {
            // Backoff may have used up the time left for this message.
            if Instant::now() >= deadline {
                return Err(deadline_error(last_error.as_ref()));
            }
            // Give this attempt whatever remains of the allowance.
            timeout_at(deadline, send())
                .await
                .map_err(|_| deadline_error(last_error.as_ref()))?
        } else {
            // The session is open, so this send has no drain deadline.
            send().await
        };
        let error = match result {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        // The session may have closed during the failed RPC, before a drain deadline was set.
        if deadline.is_none() && is_closed() {
            deadline = Some(Instant::now() + drain_timeout);
        }
        // All gRPC errors are retryable, subject to the existing backoff policy.
        let Some(delay) = backoff.next_backoff() else {
            return Err(error);
        };
        // No retry can start within the remaining allowance if backoff consumes all of it.
        if deadline.is_some_and(|deadline| Instant::now() + delay >= deadline) {
            return Err(deadline_error(Some(&error)));
        }
        metrics::METRICS.increment_network_event(NetworkDebugEvent::SendRetry);
        tracing::debug!(
            "Network retry for message: {error:?} - Duration {:?} secs. Talking to {peer}.",
            delay.as_secs()
        );
        // Keep the cause of failure in case the next attempt runs out of time.
        last_error = Some(error);
        sleep(delay).await;
    }
}

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
                    .tcp_nodelay(true)
                    .http2_keep_alive_interval(self.config.get_keepalive_interval())
                    .keep_alive_timeout(self.config.get_keepalive_timeout())
                    .keep_alive_while_idle(true);
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
                    .tcp_nodelay(true)
                    .http2_keep_alive_interval(self.config.get_keepalive_interval())
                    .keep_alive_timeout(self.config.get_keepalive_timeout())
                    .keep_alive_while_idle(true)
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
        mut receiver: UnboundedReceiver<SendValueRequest>,
        network_channel: GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        exponential_backoff: ExponentialBackoff<SystemClock>,
        drain_timeout: Duration,
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
                metrics::METRICS
                    .increment_network_event(NetworkDebugEvent::SendSkippedAfterCompleted);
                continue;
            }

            let send_fn = || async {
                let value = value.clone();
                network_channel
                    .clone()
                    .send_value(value)
                    .await
                    .map(|inner| inner.into_inner())
            };
            let res = send_with_retry(
                send_fn,
                || receiver.is_closed(),
                exponential_backoff.clone(),
                drain_timeout,
                other_role_kind,
            )
            .await;
            match res {
                Ok(send_response) => {
                    match send_response.status() {
                        Status::Active => {
                            metrics::METRICS.increment_network_event(NetworkDebugEvent::SendActive);
                        }
                        Status::Inactive => {
                            metrics::METRICS
                                .increment_network_event(NetworkDebugEvent::SendInactive);
                        }
                        Status::Completed => {
                            // The receiver already completed this session.
                            // Do not break — that would drop the receiver and cause
                            // "channel closed" errors on subsequent sends.
                            // Instead, mark as completed and drain remaining messages.
                            completed_parties.insert(other_role_kind);
                            metrics::METRICS
                                .increment_network_event(NetworkDebugEvent::SendCompleted);
                            incorrectly_sent += 1;
                            receiver_completed = true;
                        }
                    };
                }
                Err(status) => {
                    incorrectly_sent += 1;
                    metrics::METRICS.increment_network_event(NetworkDebugEvent::SendFailed);
                    tracing::debug!(
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
            tracing::debug!(
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
    ) -> anyhow::Result<UnboundedSender<SendValueRequest>> {
        // 1. Create channel first (no allocation issues)
        let (sender, receiver) = unbounded_channel::<SendValueRequest>();

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

        // 4. Each session runs one sender task per peer. Track them to reveal tasks that accumulate
        // or fail to finish.
        let task_metrics = metrics::METRICS.track_network_sender_task();
        let drain_timeout = self.config.get_closed_session_delivery_timeout();
        tokio::spawn(async move {
            let _task_metrics = task_metrics;
            Self::run_network_task(
                receiver,
                network_channel,
                exponential_backoff,
                drain_timeout,
                other_role_kind,
                aborted,
            )
            .await;
        });

        Ok(sender)
    }

    ///Adds multiple connections at once
    async fn add_connections<R: RoleTrait>(
        &self,
        others: &RoleAssignment<R>,
    ) -> anyhow::Result<(
        HashMap<RoleKind, UnboundedSender<SendValueRequest>>,
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
    use crate::ggen::gnetworking_server::{Gnetworking, GnetworkingServer};
    use crate::ggen::{HealthCheckRequest, HealthCheckResponse, SendValueResponse};
    use backoff::backoff::{Constant, Stop, Zero};
    use bytes::Bytes;
    use futures_util::poll;
    use std::cell::Cell;
    use std::future::{pending, ready};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use test_utils::random_free_port::get_listeners_random_free_ports;
    use threshold_types::role::Role;
    use tokio::time::{sleep, timeout};

    // Closing the session leaves queued messages a chance to reach the peer.
    #[tokio::test(start_paused = true)]
    async fn closed_send_can_deliver_within_deadline() {
        let result = send_with_retry(
            || ready(Ok::<_, tonic::Status>(())),
            || true,
            Zero {},
            Duration::from_secs(10),
            Role::indexed_from_one(1).get_role_kind(),
        )
        .await;
        assert!(result.is_ok());
    }

    // The peer rejects the first send and accepts the retry. The session is open, so the zero allowance for delivery
    // after closure must not prevent that retry.
    #[tokio::test(start_paused = true)]
    async fn live_send_retries_overload_without_drain_deadline() {
        let attempts = Cell::new(0);
        let result = send_with_retry(
            || {
                attempts.set(attempts.get() + 1);
                ready(if attempts.get() == 1 {
                    Err(tonic::Status::resource_exhausted("overloaded"))
                } else {
                    Ok(())
                })
            },
            || false,
            Zero {},
            Duration::ZERO,
            Role::indexed_from_one(1).get_role_kind(),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(attempts.get(), 2);
    }

    // If the normal retry policy gives up, the caller should see the peer's error.
    #[tokio::test(start_paused = true)]
    async fn retry_policy_exhaustion_preserves_rpc_error() {
        let error = send_with_retry(
            || {
                ready(Err::<(), _>(tonic::Status::resource_exhausted(
                    "overloaded",
                )))
            },
            || false,
            Stop {},
            Duration::ZERO,
            Role::indexed_from_one(1).get_role_kind(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    // A send starts after the session has closed, but the peer never answers.
    // The sender must give up when the message's time runs out.
    #[tokio::test(start_paused = true)]
    async fn closed_send_deadline_bounds_rpc() {
        let delivery = send_with_retry(
            pending::<Result<(), tonic::Status>>,
            || true,
            Zero {},
            Duration::from_millis(20),
            Role::indexed_from_one(1).get_role_kind(),
        );
        let error = timeout(Duration::from_secs(2), delivery)
            .await
            .expect("the drain deadline must bound an unresponsive RPC")
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    }

    // The peer keeps rejecting the message. Each retry uses up part of the same drain deadline; it must not buy the
    // message more time.
    #[tokio::test(start_paused = true)]
    async fn closed_send_deadline_does_not_reset_on_retry() {
        let delivery = send_with_retry(
            || {
                ready(Err::<(), _>(tonic::Status::resource_exhausted(
                    "overloaded",
                )))
            },
            || true,
            Constant::new(Duration::from_millis(1)),
            Duration::from_millis(20),
            Role::indexed_from_one(1).get_role_kind(),
        );
        let error = timeout(Duration::from_secs(2), delivery)
            .await
            .expect("repeated rejections must not extend the drain deadline")
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert!(error.message().contains("overloaded"));
    }

    // The session closes while a send is underway. That send gets to finish, even though there would be no time left
    // for another attempt.
    #[tokio::test(start_paused = true)]
    async fn closure_during_successful_send_does_not_interrupt_it() {
        let closed = Cell::new(false);
        let result = send_with_retry(
            || async {
                closed.set(true);
                sleep(Duration::from_millis(20)).await;
                Ok(())
            },
            || closed.get(),
            Zero {},
            Duration::ZERO,
            Role::indexed_from_one(1).get_role_kind(),
        )
        .await;
        assert!(result.is_ok());
    }

    // The session closes during a failed send. The next retry would be too late, so the sender gives up immediately and
    // reports why the send failed.
    #[tokio::test(start_paused = true)]
    async fn closure_during_failed_send_skips_backoff_beyond_deadline() {
        let closed = Cell::new(false);
        let delivery = send_with_retry(
            || {
                closed.set(true);
                ready(Err::<(), _>(tonic::Status::resource_exhausted(
                    "overloaded",
                )))
            },
            || closed.get(),
            Constant::new(Duration::from_secs(3600)),
            Duration::from_secs(10),
            Role::indexed_from_one(1).get_role_kind(),
        );
        tokio::pin!(delivery);
        assert!(matches!(
            poll!(&mut delivery),
            std::task::Poll::Ready(Err(error)) if error.code() == tonic::Code::DeadlineExceeded
                && error.message().contains("overloaded")
        ));
    }

    // The session closes during backoff. Once the wait ends, the sender must notice session closure before trying
    // again. A zero allowance rules out another attempt.
    #[tokio::test(start_paused = true)]
    async fn closure_during_backoff_is_checked_before_next_attempt() {
        let closed = Cell::new(false);
        let attempts = Cell::new(0);
        let delivery = send_with_retry(
            || {
                attempts.set(attempts.get() + 1);
                ready(Err::<(), _>(tonic::Status::unavailable("offline")))
            },
            || closed.get(),
            Constant::new(Duration::from_millis(20)),
            Duration::ZERO,
            Role::indexed_from_one(1).get_role_kind(),
        );
        tokio::pin!(delivery);
        // Let the first attempt fail and enter backoff before closing the session.
        assert!(poll!(&mut delivery).is_pending());
        closed.set(true);
        let error = timeout(Duration::from_secs(2), delivery)
            .await
            .expect("closure must be checked after backoff")
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(attempts.get(), 1);
    }

    // Close the real sending channel with two messages queued. Failure to deliver the first message must not stop the
    // sender from trying the second.
    #[tokio::test]
    async fn closed_network_task_attempts_each_queued_message() {
        struct OverloadedPeer(Arc<AtomicUsize>);

        #[tonic::async_trait]
        impl Gnetworking for OverloadedPeer {
            async fn send_value(
                &self,
                _: tonic::Request<SendValueRequest>,
            ) -> Result<tonic::Response<SendValueResponse>, tonic::Status> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(tonic::Status::resource_exhausted("overloaded"))
            }

            async fn health_check(
                &self,
                _: tonic::Request<HealthCheckRequest>,
            ) -> Result<tonic::Response<HealthCheckResponse>, tonic::Status> {
                unimplemented!()
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = futures_util::stream::unfold(listener, |listener| async {
            let connection = listener.accept().await.map(|(stream, _)| stream);
            Some((connection, listener))
        });
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(GnetworkingServer::new(OverloadedPeer(Arc::clone(
                    &attempts,
                ))))
                .serve_with_incoming(incoming),
        );
        let channel = Channel::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(2))
            .connect()
            .await
            .unwrap();
        let client = GnetworkingClient::with_interceptor(channel, ContextPropagator);
        let (sender, receiver) = unbounded_channel();
        sender.send(SendValueRequest::default()).unwrap();
        sender.send(SendValueRequest::default()).unwrap();
        drop(sender);

        // A live sender would wait a minute before retrying. A closed sender abandons the
        // message instead of waiting, and gives the next queued message its own delivery attempt.
        let backoff = ExponentialBackoff {
            initial_interval: Duration::from_secs(60),
            randomization_factor: 0.0,
            max_elapsed_time: Some(Duration::from_secs(300)),
            ..Default::default()
        };
        let result = timeout(
            Duration::from_secs(5),
            GrpcSendingService::run_network_task(
                receiver,
                client,
                backoff,
                CoreToCoreNetworkConfig::default().get_closed_session_delivery_timeout(),
                Role::indexed_from_one(1).get_role_kind(),
                Arc::new(DashSet::new()),
            ),
        )
        .await;
        server.abort();
        let _ = server.await;
        result.expect("session closure must prevent the minute-long backoff");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

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
        let (sender, receiver) = unbounded_channel::<SendValueRequest>();
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
            CoreToCoreNetworkConfig::default().get_closed_session_delivery_timeout(),
            role_kind,
            Arc::clone(&completed_parties),
        ));

        // Send first message — triggers Status::Completed
        let msg = SendValueRequest {
            tag: Bytes::from_static(&[1, 2, 3]),
            value: Bytes::from_static(&[4, 5, 6]),
        };
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
        let msg2 = SendValueRequest {
            tag: Bytes::from_static(&[7, 8, 9]),
            value: Bytes::from_static(&[10, 11, 12]),
        };
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
