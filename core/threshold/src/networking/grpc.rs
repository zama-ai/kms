//! gRPC-based networking.

mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

use self::gen::gnetworking_client::GnetworkingClient;
use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use super::constants::{MESSAGE_LIMIT, NETWORK_TIMEOUT_LONG};
use crate::conf::party::CertificatePaths;
use crate::conf::telemetry::ContextPropagator;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::{Identity, RoleAssignment};
use crate::networking::constants::{self, MAX_EN_DECODE_MESSAGE_SIZE};
use crate::networking::Networking;
use crate::session_id::SessionId;
use async_trait::async_trait;
use backoff::future::retry_notify;
use backoff::ExponentialBackoff;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::time::Instant;
use tonic::codegen::http::Uri;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

/// GrpcNetworkingManager is responsible for managing
/// channels and message queues between MPC parties.
#[derive(Debug, Clone)]
pub struct GrpcNetworkingManager {
    channels: Arc<Channels>,
    message_queues: Arc<MessageQueueStores>,
    owner: Identity,
    cert_bundle: Arc<Option<CertificatePaths>>,
}

pub type GrpcServer = GnetworkingServer<NetworkingImpl>;

impl GrpcNetworkingManager {
    /// Create a new server from the networking manager.
    /// The server can be used as a tower Service.
    pub fn new_server(&self) -> GnetworkingServer<impl Gnetworking> {
        GnetworkingServer::new(NetworkingImpl {
            message_queues: Arc::clone(&self.message_queues),
        })
        .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
        .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
    }

    /// Owner should be the external address
    pub fn new(owner: Identity, cert_bundle: Option<CertificatePaths>) -> Self {
        GrpcNetworkingManager {
            channels: Default::default(),
            message_queues: Default::default(),
            owner,
            cert_bundle: Arc::new(cert_bundle),
        }
    }

    /// Create a new session from the network manager.
    ///
    /// All the communication are performed using sessions.
    /// There may be multiple session in parallel,
    /// identified by different session IDs.
    pub fn make_session(
        &self,
        session_id: SessionId,
        roles: RoleAssignment,
    ) -> Arc<impl Networking> {
        let message_store = DashMap::new();
        for (_role, identity) in roles {
            let (tx, rx) = async_channel::bounded(MESSAGE_LIMIT);
            message_store.insert(identity, (Arc::new(tx), Arc::new(rx)));
        }
        self.message_queues
            .insert(session_id, Arc::new(message_store));
        Arc::new(GrpcNetworking {
            session_id,
            channels: Arc::clone(&self.channels),
            message_queues: Arc::clone(&self.message_queues),
            network_round: Arc::new(Mutex::new(0)),
            owner: self.owner.clone(),
            init_time: OnceLock::new(),
            cert_bundle: self.cert_bundle.clone(),
        })
    }
}

pub struct GrpcNetworking {
    session_id: SessionId,
    channels: Arc<Channels>,
    message_queues: Arc<MessageQueueStores>,
    network_round: Arc<Mutex<usize>>,
    owner: Identity,
    init_time: OnceLock<Instant>,
    cert_bundle: Arc<Option<CertificatePaths>>,
}

impl GrpcNetworking {
    fn channel(&self, receiver: &Identity) -> anyhow::Result<Channel> {
        let channel: Channel = self
            .channels
            .entry(receiver.clone())
            .or_try_insert_with(|| {
                let proto = match *self.cert_bundle {
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
                let channel = match *self.cert_bundle {
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
                        Channel::builder(endpoint)
                            .tls_config(tls_config)?
                            .timeout(*NETWORK_TIMEOUT_LONG)
                    }
                    None => Channel::builder(endpoint).timeout(*NETWORK_TIMEOUT_LONG),
                };
                Ok::<Channel, anyhow::Error>(channel.connect_lazy())
            })?
            .clone(); // cloning channels is cheap per tonic documentation
        Ok(channel)
    }

    fn new_client(
        &self,
        identity: &Identity,
    ) -> anyhow::Result<GnetworkingClient<InterceptedService<Channel, ContextPropagator>>> {
        let channel = self.channel(identity)?;
        let client = GnetworkingClient::with_interceptor(channel, ContextPropagator)
            .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
            .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE);
        Ok(client)
    }
}

#[async_trait]
impl Networking for GrpcNetworking {
    async fn send(
        &self,
        value: Vec<u8>,
        receiver: &Identity,
        _session_id: &SessionId,
    ) -> anyhow::Result<(), anyhow::Error> {
        let ctr: usize = *self
            .network_round
            .lock()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;

        let send_fn = || async {
            let tagged_value = Tag {
                sender: self.owner.clone(),
                session_id: self.session_id,
                round_counter: ctr,
            };

            let tag = bincode::serialize(&tagged_value)
                .map_err(|e| anyhow_error_and_log(format!("networking error: {:?}", e)))?;
            let request = SendValueRequest {
                tag,
                value: value.clone(),
            };
            let mut client = self.new_client(receiver)?;
            tracing::debug!(
                "Sending '{:?} bytes' to {:?}, session_id {:?}",
                value.len(),
                receiver,
                self.session_id
            );

            match client.send_value(request).await {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow_error_and_log(format!("networking error: {:?}", e)))
                    .map_err(|e| e.into()),
            }
        };

        let exponential_backoff = ExponentialBackoff {
            max_elapsed_time: *constants::MAX_ELAPSED_TIME,
            max_interval: *constants::MAX_INTERVAL,
            multiplier: constants::MULTIPLIER,
            ..Default::default()
        };

        let notify = |e, duration: Duration| {
            tracing::warn!(
                "RETRY ERROR: Failed to send message: {:?} - Receiver {:?} - Duration {:?} secs",
                e,
                receiver,
                duration.as_secs()
            );
        };

        retry_notify(exponential_backoff, send_fn, notify).await
    }

    async fn receive(&self, sender: &Identity, _session_id: &SessionId) -> anyhow::Result<Vec<u8>> {
        if !self.message_queues.contains_key(&self.session_id) {
            return Err(anyhow_error_and_log(
                "Did not have session id key for message storage inside receive call",
            ));
        }

        let rx = self
            .message_queues
            .get(&self.session_id)
            .ok_or_else(|| anyhow_error_and_log("couldn't retrieve channels from store"))
            .map(|s| {
                s.get(sender)
                    .ok_or_else(|| {
                        anyhow_error_and_log("couldn't retrieve session store from message stores")
                    })
                    .map(|s| s.value().1.clone())
            })??;

        tracing::debug!("Waiting to receive from {:?}", sender);

        let network_round: usize = *self
            .network_round
            .lock()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;

        let mut local_packet = rx.recv().await?;

        // drop old messages
        while local_packet.round_counter < network_round {
            tracing::debug!(
                "@ round {} - dropped value {:?} from round {}",
                network_round,
                local_packet.value[..16].to_vec(),
                local_packet.round_counter
            );
            local_packet = rx.recv().await?;
        }

        Ok(local_packet.value)
    }

    fn increase_round_counter(&self) -> anyhow::Result<()> {
        if let Ok(mut net_round) = self.network_round.lock() {
            *net_round += 1;
            tracing::debug!(
                "changed network round to: {:?} on party: {:?}",
                *net_round,
                self.owner
            );
        } else {
            return Err(anyhow_error_and_log("Couldn't lock mutex"));
        }
        Ok(())
    }

    fn get_timeout_current_round(&self) -> anyhow::Result<Instant> {
        // initialize init_time on first access
        // this avoids running into timeouts when large computations happen after the test runtime is set up and before the first message is received.
        let init_time = self.init_time.get_or_init(Instant::now);

        if let Ok(net_round) = self.network_round.lock() {
            Ok(*init_time + *NETWORK_TIMEOUT_LONG * (*net_round as u32))
        } else {
            Err(anyhow_error_and_log("Couldn't lock mutex"))
        }
    }

    fn get_current_round(&self) -> anyhow::Result<usize> {
        todo!("Need to implement get_current_round for grpc")
    }
}

// we need a counter for each value sent over the local queues
// so that messages that haven't been pickup up using receive() calls will get dropped
#[derive(Debug)]
struct NetworkRoundValue {
    pub value: Vec<u8>,
    pub round_counter: usize,
}

type Channels = DashMap<Identity, Channel>;
type MessageQueueStore = DashMap<
    Identity,
    (
        Arc<async_channel::Sender<NetworkRoundValue>>,
        Arc<async_channel::Receiver<NetworkRoundValue>>,
    ),
>;
type MessageQueueStores = DashMap<SessionId, Arc<MessageQueueStore>>;

#[derive(Default)]
pub struct NetworkingImpl {
    message_queues: Arc<MessageQueueStores>,
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
        // One of these must match the "tag" that's in the request for identity verification
        let valid_tls_senders = extract_valid_sender_sans(&request)
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e))?
            .map(|x| x.into_iter().collect::<Vec<_>>());
        tracing::info!("extract_valid_sender_sans returned {:?}", valid_tls_senders);

        let request = request.into_inner();
        let tag = bincode::deserialize::<Tag>(&request.tag).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "failed to parse value".to_string())
        })?;

        if let Some(senders) = valid_tls_senders {
            // tag.sender has the form hostname:port
            // we remove the port component since the tls_sender does not have it
            let host_and_port: Vec<_> = tag.sender.0.split(':').collect();
            if host_and_port.len() != 2 {
                return Err(tonic::Status::new(
                    tonic::Code::Unknown,
                    format!(
                        "wrong sender tag (could not split at ':'): {:?}",
                        tag.sender,
                    ),
                ));
            }
            let host = host_and_port[0].to_string();
            if !senders.contains(&host) {
                return Err(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    format!("wrong sender: expected {:?} to be in {:?}", host, senders),
                ));
            }
        }
        tracing::debug!("passed sender verification, tag is {:?}", tag);

        if self.message_queues.contains_key(&tag.session_id) {
            let tx = self
                .message_queues
                .get(&tag.session_id)
                .ok_or_else(|| {
                    anyhow_error_and_log("couldn't retrieve session store from message stores")
                })
                .map(|s| {
                    s.get(&tag.sender)
                        .ok_or_else(|| {
                            anyhow_error_and_log("couldn't retrieve channels from session store")
                        })
                        .map(|s| s.value().0.clone())
                        .map_err(|e| tonic::Status::new(tonic::Code::NotFound, e.to_string()))
                })
                .map_err(|e| tonic::Status::new(tonic::Code::NotFound, e.to_string()))??;

            let _ = tx
                .send(NetworkRoundValue {
                    value: request.value,
                    round_counter: tag.round_counter,
                })
                .await;
            Ok(tonic::Response::new(SendValueResponse::default()))
        } else {
            let msg = format!("unknown session id {:?} for party", tag.session_id);
            tracing::error!(msg);
            Err(tonic::Status::new(tonic::Code::NotFound, msg))
        }
    }
}

/// returns the list of accepted sender SANs that is contained in the request's client peer certificates
fn extract_valid_sender_sans<T>(
    request: &tonic::Request<T>,
) -> Result<Option<Vec<String>>, String> {
    match request.peer_certs() {
        None => Ok(None),
        Some(certs) => {
            let san_strings = extract_san_from_certs(&certs, false)?;
            Ok(Some(san_strings))
        }
    }
}

/// Extract all the SANs in the certificate from the request.
///
/// Each party should have its own self-signed certificate.
/// Each self-signed certificate is loaded into the trust store of all the parties.
pub fn extract_san_from_certs(certs: &[Certificate], use_pem: bool) -> Result<Vec<String>, String> {
    if certs.len() != 1 {
        return Err(format!(
            "cannot extract identity from certificate chain of length {:?}",
            certs.len()
        ));
    }

    let (pem_cert, der_cert) = if use_pem {
        let (_rem, c) = x509_parser::pem::parse_x509_pem(certs[0].as_ref())
            .map_err(|err| format!("failed to parse X509 certificate: {:?}", err.to_string()))?;
        (Some(c), None)
    } else {
        let (_rem, c) = x509_parser::parse_x509_certificate(certs[0].as_ref())
            .map_err(|err| format!("failed to parse X509 certificate: {:?}", err.to_string()))?;
        (None, Some(c))
    };

    let cert = match (&pem_cert, &der_cert) {
        (Some(pem_cert), None) => pem_cert.parse_x509().map_err(|e| e.to_string())?,
        (None, Some(der_cert)) => der_cert.clone(),
        _ => return Err("internal logic error when parsing certificates".to_string()),
    };

    let Some(sans) = cert.subject_alternative_name().map_err(|e| e.to_string())? else {
        return Err("SAN not specified".to_string());
    };
    let san_strings: Vec<_> = sans
        .value
        .general_names
        .iter()
        .filter_map(|san| match san {
            x509_parser::extensions::GeneralName::DNSName(s) => Some(s.to_string()),
            x509_parser::extensions::GeneralName::IPAddress(s) => {
                if s.len() == 16 {
                    let mut buf = [0u8; 16];
                    buf.copy_from_slice(s);
                    Some(Ipv6Addr::from(buf).to_string())
                } else if s.len() == 4 {
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(s);
                    Some(Ipv4Addr::from(buf).to_string())
                } else {
                    tracing::warn!("Ignoring IP SAN in unsupported format {:?}", san);
                    None
                }
            }
            _ => {
                tracing::warn!("Ignoring SAN in unsupported format {:?}", san);
                None
            }
        })
        .collect();

    if san_strings.is_empty() {
        return Err("No valid SAN found".to_string());
    }

    Ok(san_strings)
}

#[derive(Serialize, Deserialize, Debug)]
struct Tag {
    session_id: SessionId,
    sender: Identity,
    round_counter: usize,
}
