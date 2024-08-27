use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use backoff::exponential::ExponentialBackoff;
use backoff::future::retry_notify;
use backoff::SystemClock;
use conf_trace::telemetry::ContextPropagator;
use gen::gnetworking_client::GnetworkingClient;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{ClientTlsConfig, Uri};
use tonic::{async_trait, transport::Channel};

use crate::conf::party::CertificatePaths;
use crate::error::error_handler::{anyhow_error_and_log, anyhow_error_and_warn_log};
use crate::{execution::runtime::party::Identity, session_id::SessionId};

use super::grpc::{CoreToCoreNetworkConfig, MessageQueueStore, OptionConfigWrapper};
use super::{NetworkMode, Networking};

mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}
use self::gen::SendValueRequest;

//Note if this struct was defined inside the protobuf we wouldnt have
//to (de)serialize it at every network call
#[derive(Serialize, Deserialize, Debug)]
struct Tag {
    session_id: SessionId,
    sender: Identity,
    round_counter: usize,
}

#[async_trait]
pub trait SendingService: Send + Sync {
    /// Init and start the sending service
    fn new(cert_bundle: Option<CertificatePaths>, conf: Option<CoreToCoreNetworkConfig>) -> Self
    where
        Self: std::marker::Sized;

    /// Adds one connection and outputs the mpsc Sender channel other processes will use to communicate to other
    fn add_connection(&self, other: Identity) -> anyhow::Result<UnboundedSender<SendValueRequest>>;

    ///Adds multiple connections at once
    fn add_connections(
        &self,
        others: Vec<Identity>,
    ) -> anyhow::Result<HashMap<Identity, UnboundedSender<SendValueRequest>>>;
}

/// NOTE: This sending service spawns one channel per session per party,
/// If we fear we may even exhaust the total number of ports available,
/// this behaviour should be changed to spawning a fixed number of channels
/// and load balance the sessions accross these.
#[derive(Debug, Clone)]
pub struct GrpcSendingService {
    /// Contains all the information needed by the sync network
    config: OptionConfigWrapper,
    /// Contains the certificate bundles
    certificate_bundle: Option<CertificatePaths>,
}

impl GrpcSendingService {
    /// Create the network channel between self and the grpc server of the other party
    fn connect_to_party(
        &self,
        receiver: Identity,
    ) -> anyhow::Result<GnetworkingClient<InterceptedService<Channel, ContextPropagator>>> {
        let proto = match self.certificate_bundle {
            Some(_) => "https",
            None => "http",
        };
        tracing::debug!("Creating {} channel to '{}'", proto, receiver);
        let endpoint: Uri = format!("{}://{}", proto, receiver).parse().map_err(|_e| {
            anyhow_error_and_log(format!(
                "failed to parse identity as endpoint: {:?}",
                receiver
            ))
        })?;
        let channel = match self.certificate_bundle {
            Some(ref cert_bundle) => {
                let host_port: Vec<_> = receiver.0.split(':').collect();
                if host_port.len() != 2 {
                    return Err(anyhow_error_and_log(format!(
                        "wrong receiver format: {:?}",
                        receiver
                    )));
                }
                let tls_config = ClientTlsConfig::new()
                    // TODO when we run our network in production the correct
                    // domain_name needs to be selected somehow
                    // .domain_name(host_port[0])
                    .domain_name("localhost")
                    .ca_certificate(cert_bundle.get_flattened_ca_list()?)
                    .identity(cert_bundle.get_identity()?);
                Channel::builder(endpoint).tls_config(tls_config)?
            }
            None => Channel::builder(endpoint),
        };
        let channel = channel.connect_lazy();
        let client = GnetworkingClient::with_interceptor(channel, ContextPropagator)
            .max_decoding_message_size(self.config.get_max_en_decode_message_size())
            .max_encoding_message_size(self.config.get_max_en_decode_message_size());
        Ok(client)
    }

    async fn run_network_task(
        mut receiver: UnboundedReceiver<SendValueRequest>,
        network_channel: GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        exponential_backoff: ExponentialBackoff<SystemClock>,
    ) {
        while let Some(value) = receiver.recv().await {
            let send_fn = || async {
                match network_channel.clone().send_value(value.clone()).await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow_error_and_log(format!("networking error: {:?}", e)))
                        .map_err(|e| e.into()),
                }
            };
            let notify = |e, duration: Duration| {
                tracing::warn!(
                                    "RETRY ERROR: Failed to send message: {:?} - Receiver {:?} - Duration {:?} secs",
                                    e,
                                    receiver,
                                    duration.as_secs()
                                );
            };

            let res = retry_notify(exponential_backoff.clone(), send_fn, notify).await;
            if res.is_err() {
                tracing::error!("Error sending");
            }
        }
        anyhow_error_and_warn_log("No more listeners, shutting down network task".to_string());
    }
}

#[async_trait]
impl SendingService for GrpcSendingService {
    /// Communicates with the service thread to spin up a new connection with `other`
    /// __NOTE__: This requires the service to be running already
    fn add_connection(&self, other: Identity) -> anyhow::Result<UnboundedSender<SendValueRequest>> {
        let (sender, receiver) = unbounded_channel::<SendValueRequest>();
        let network_channel = self.connect_to_party(other.clone())?;
        let exponential_backoff = ExponentialBackoff::<SystemClock> {
            max_elapsed_time: self.config.get_max_elapsed_time(),
            max_interval: self.config.get_max_interval(),
            multiplier: self.config.get_multiplier(),
            ..Default::default()
        };
        tokio::spawn(Self::run_network_task(
            receiver,
            network_channel,
            exponential_backoff,
        ));
        Ok(sender)
    }

    /// Does the same as [`SyncSendingService::add_connection`] but for multiple others
    /// __NOTE__: This requires the service to be running already
    fn add_connections(
        &self,
        others: Vec<Identity>,
    ) -> anyhow::Result<HashMap<Identity, UnboundedSender<SendValueRequest>>> {
        let mut map = HashMap::new();
        for other in others {
            let connection = self.add_connection(other.clone())?;
            map.insert(other.clone(), connection);
        }
        Ok(map)
    }

    fn new(
        certificate_bundle: Option<CertificatePaths>,
        config: Option<CoreToCoreNetworkConfig>,
    ) -> Self {
        Self {
            config: OptionConfigWrapper { conf: config },
            certificate_bundle,
        }
    }
}

///This acts as an interface with the real networking processes.
///It communicates with the SendingService via the mpsc Sender channel (sending_channels)
///And retrieves messages via the Grpc Server mpsc Receiver channel (receiving_channels)
///It also deals with the network round and timeouts
pub struct NetworkSession {
    pub owner: Identity,
    // Sessoin id of this Network session
    pub session_id: SessionId,
    /// MPSC channels that are filled by parties and dealt with by the [`SendingService`]
    /// Sending channels for this session
    pub sending_channels: HashMap<Identity, UnboundedSender<SendValueRequest>>,
    /// Channels which are filled by the grpc server receiving messages from the other parties
    pub receiving_channels: Arc<MessageQueueStore>,
    //Round counter for the current session, behind a lock to be able to update it without a mut ref to self
    pub round_counter: RwLock<usize>,
    //Network mode is either async or sync
    pub network_mode: NetworkMode,
    //If Network mode is sync, we need to keep track of the values below to make sure
    //we are within time bound
    pub conf: OptionConfigWrapper,
    pub init_time: OnceLock<Instant>,
    pub current_network_timeout: RwLock<Duration>,
    pub next_network_timeout: RwLock<Duration>,
    pub max_elapsed_time: RwLock<Duration>,
}
#[async_trait]
impl Networking for NetworkSession {
    //Note this need not be async, so do we want to keep the trait definition async
    //if we want to add other implems which may require async ?
    async fn send(&self, value: Vec<u8>, receiver: &Identity) -> anyhow::Result<()> {
        let round_counter = *self
            .round_counter
            .read()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;
        let tagged_value = Tag {
            sender: self.owner.clone(),
            session_id: self.session_id,
            round_counter,
        };

        let tag = bincode::serialize(&tagged_value)
            .map_err(|e| anyhow_error_and_log(format!("networking error: {:?}", e)))?;
        let request = SendValueRequest {
            tag,
            value: value.clone(),
        };

        //Retrieve the local channel that corresponds to the party we want to send to and push into it
        match self.sending_channels.get(receiver) {
            Some(channel) => Ok(channel.send(request)?),
            None => Err(anyhow_error_and_log(format!(
                "Missing local channel for P{:?}",
                receiver
            ))),
        }?;
        Ok(())
    }

    /// Receives messages from other parties, assuming the grpc server filled the [`MessageQueueStores`] correctly
    async fn receive(&self, sender: &Identity) -> anyhow::Result<Vec<u8>> {
        let network_round = *self
            .round_counter
            .read()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;

        let rx = self.receiving_channels.get(sender).ok_or_else(|| {
            anyhow_error_and_log(format!(
                "couldn't retrieve receiving channel for P:{:?}",
                sender
            ))
        })?;
        let mut rx = rx.value().1.lock().await;

        tracing::debug!("Waiting to receive from {:?}", sender);

        let mut local_packet = rx
            .recv()
            .await
            .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel."))?;

        // drop old messages
        while local_packet.round_counter < network_round {
            tracing::debug!(
                "@ round {} - dropped value {:?} from round {}",
                network_round,
                local_packet.value[..16].to_vec(),
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
    fn increase_round_counter(&self) -> anyhow::Result<()> {
        if let (
            Ok(mut max_elapsed_time),
            Ok(mut current_round_timeout),
            Ok(next_round_timeout),
            Ok(mut net_round),
        ) = (
            self.max_elapsed_time.write(),
            self.current_network_timeout.write(),
            self.next_network_timeout.read(),
            self.round_counter.write(),
        ) {
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
            );
        } else {
            return Err(anyhow_error_and_log("Couldn't lock some RwLock"));
        }

        Ok(())
    }

    ///Used to compute the timeout in network functions
    fn get_timeout_current_round(&self) -> anyhow::Result<Instant> {
        let init_time = self.init_time.get_or_init(Instant::now);
        if let (Ok(max_elapsed_time), Ok(network_timeout)) = (
            self.max_elapsed_time.read(),
            self.current_network_timeout.read(),
        ) {
            Ok(*init_time + *network_timeout + *max_elapsed_time)
        } else {
            Err(anyhow_error_and_log("Couldn't lock some RwLock"))
        }
    }

    fn get_current_round(&self) -> anyhow::Result<usize> {
        if let Ok(round_counter) = self.round_counter.read() {
            Ok(*round_counter)
        } else {
            Err(anyhow_error_and_log("Couldn't lock round_counter RwLock"))
        }
    }

    /// Method to set a different timeout than the one set at construction, effective for the next round.
    ///
    /// __NOTE__: If the network mode is Async, this has no effect
    fn set_timeout_for_next_round(&self, timeout: Duration) -> anyhow::Result<()> {
        match self.get_network_mode() {
            NetworkMode::Sync => {
                if let Ok(mut next_network_timeout) = self.next_network_timeout.write() {
                    *next_network_timeout = timeout;
                } else {
                    return Err(anyhow_error_and_log("Couldn't lock mutex"));
                }
            }
            NetworkMode::Async => {
                tracing::warn!(
                    "Trying to change network timeout with async network, doesn't do anything"
                );
            }
        }
        Ok(())
    }

    /// Method to set the timeout for distributed generation of the TFHE bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    fn set_timeout_for_bk(&self) -> anyhow::Result<()> {
        self.set_timeout_for_next_round(self.conf.get_network_timeout_bk())
    }

    /// Method to set the timeout for distributed generation of the TFHE switch and squash bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    fn set_timeout_for_bk_sns(&self) -> anyhow::Result<()> {
        self.set_timeout_for_next_round(self.conf.get_network_timeout_bk_sns())
    }

    fn get_network_mode(&self) -> NetworkMode {
        self.network_mode
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        execution::runtime::party::{Identity, Role, RoleAssignment},
        networking::{grpc::GrpcNetworkingManager, Networking},
        session_id::SessionId,
    };

    #[test]
    fn test_network_stack() {
        let sid = SessionId(0);
        let mut role_assignment = RoleAssignment::new();
        let role_1 = Role::indexed_by_one(1);
        let id_1 = Identity("localhost:6000".to_owned());
        let role_2 = Role::indexed_by_one(2);
        let id_2 = Identity("localhost:6001".to_owned());
        role_assignment.insert(role_1, id_1.clone());
        role_assignment.insert(role_2, id_2.clone());

        let mut handles = Vec::new();
        for (role, id) in role_assignment.iter() {
            //Wait a little while to make sure retry works fine
            std::thread::sleep(Duration::from_secs(5));
            let id = id.clone();
            let role = *role;
            let id_1 = id_1.clone();
            let id_2 = id_2.clone();
            let port_digit = role.zero_based();
            let role_assignment = role_assignment.clone();
            handles.push(std::thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let _guard = runtime.enter();
                let networking = GrpcNetworkingManager::new(id.clone(), None, None);
                let networking_server = networking.new_server();

                let core_grpc_layer = tower::ServiceBuilder::new().timeout(Duration::from_secs(3));

                let core_router = tonic::transport::Server::builder()
                    .timeout(Duration::from_secs(3))
                    .layer(core_grpc_layer)
                    .add_service(networking_server);

                let core_future =
                    core_router.serve(format!("0.0.0.0:600{}", port_digit).parse().unwrap());

                tokio::spawn(async move {
                    let _res = futures::join!(core_future);
                });

                let network_stack = networking.make_session(
                    sid,
                    role_assignment.clone(),
                    crate::networking::NetworkMode::Sync,
                );

                let (send, recv) = tokio::sync::oneshot::channel();
                if role.zero_based() == 0 {
                    tokio::spawn(async move {
                        let msg = vec![1u8; 10];
                        tracing::info!("Sending ONCE");
                        network_stack.send(msg.clone(), &id_2).await.unwrap();
                        tokio::time::sleep(Duration::from_secs(4)).await;
                        tracing::info!("Sending TWICE");
                        network_stack.send(msg.clone(), &id_2).await.unwrap();
                        send.send(msg).unwrap();
                    });
                    //Keep this std thread alive for a while
                    std::thread::sleep(Duration::from_secs(15));
                } else {
                    tokio::spawn(async move {
                        let msg = network_stack.receive(&id_1).await.unwrap();
                        tracing::info!("Received ONCE {:?}", msg);
                        send.send(msg).unwrap();
                    });
                }
                recv.blocking_recv()
            }));
        }

        let id = id_2;
        let port_digit = 1;
        handles.push(std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _guard = runtime.enter();
            let networking = GrpcNetworkingManager::new(id.clone(), None, None);
            let networking_server = networking.new_server();

            let core_grpc_layer = tower::ServiceBuilder::new().timeout(Duration::from_secs(3));

            let core_router = tonic::transport::Server::builder()
                .timeout(Duration::from_secs(3))
                .layer(core_grpc_layer)
                .add_service(networking_server);

            let core_future =
                core_router.serve(format!("0.0.0.0:600{}", port_digit).parse().unwrap());

            tokio::spawn(async move {
                tracing::info!("Spinning up second server");
                let _res = futures::join!(core_future);
            });

            let network_stack = networking.make_session(
                sid,
                role_assignment.clone(),
                crate::networking::NetworkMode::Sync,
            );

            let (send, recv) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                tracing::info!("Ready to receive");
                let msg = network_stack.receive(&id_1).await.unwrap();
                tracing::info!("Received TWICE {:?}", msg);
                send.send(msg).unwrap();
            });
            recv.blocking_recv()
        }));

        let mut res = Vec::new();
        for handle in handles {
            res.push(handle.join().unwrap().unwrap());
        }
        let ref_res = res.first().unwrap();
        for res in res.iter() {
            assert_eq!(res, ref_res);
        }
    }
}
