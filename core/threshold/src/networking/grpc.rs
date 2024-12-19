//! gRPC-based networking.

mod gen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}

use self::gen::gnetworking_server::{Gnetworking, GnetworkingServer};
use self::gen::{SendValueRequest, SendValueResponse};
use super::constants::{
    MAX_ELAPSED_TIME, MAX_EN_DECODE_MESSAGE_SIZE, MAX_INTERVAL, MESSAGE_LIMIT, MULTIPLIER,
    NETWORK_TIMEOUT_ASYNC, NETWORK_TIMEOUT_BK, NETWORK_TIMEOUT_BK_SNS, NETWORK_TIMEOUT_LONG,
};
use super::sending_service::{GrpcSendingService, NetworkSession, SendingService};
use super::NetworkMode;
use crate::conf::party::CertificatePaths;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::{Identity, RoleAssignment};
use crate::networking::Networking;
use crate::session_id::SessionId;
use async_trait::async_trait;
use dashmap::DashMap;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::Duration;
use tonic::transport::Certificate;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct CoreToCoreNetworkConfig {
    pub message_limit: u64,
    pub multiplier: f64,
    pub max_interval: u64,
    pub max_elapsed_time: Option<u64>,
    pub network_timeout: u64,
    pub network_timeout_bk: u64,
    pub network_timeout_bk_sns: u64,
    pub max_en_decode_message_size: u64,
}

#[derive(Debug, Clone)]
pub struct OptionConfigWrapper {
    pub conf: Option<CoreToCoreNetworkConfig>,
}

impl OptionConfigWrapper {
    pub fn get_message_limit(&self) -> usize {
        if let Some(conf) = self.conf {
            conf.message_limit as usize
        } else {
            MESSAGE_LIMIT
        }
    }

    pub fn get_multiplier(&self) -> f64 {
        if let Some(conf) = self.conf {
            conf.multiplier
        } else {
            MULTIPLIER
        }
    }

    pub fn get_max_interval(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.max_interval)
        } else {
            *MAX_INTERVAL
        }
    }

    pub fn get_max_elapsed_time(&self) -> Option<Duration> {
        if let Some(conf) = self.conf {
            conf.max_elapsed_time.map(Duration::from_secs)
        } else {
            *MAX_ELAPSED_TIME
        }
    }

    pub fn get_network_timeout(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.network_timeout)
        } else {
            *NETWORK_TIMEOUT_LONG
        }
    }

    pub fn get_network_timeout_bk(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.network_timeout_bk)
        } else {
            *NETWORK_TIMEOUT_BK
        }
    }

    pub fn get_network_timeout_bk_sns(&self) -> Duration {
        if let Some(conf) = self.conf {
            Duration::from_secs(conf.network_timeout_bk_sns)
        } else {
            *NETWORK_TIMEOUT_BK_SNS
        }
    }

    pub fn get_max_en_decode_message_size(&self) -> usize {
        if let Some(conf) = self.conf {
            conf.max_en_decode_message_size as usize
        } else {
            *MAX_EN_DECODE_MESSAGE_SIZE
        }
    }
}

//TODO: Most likely need this to create NetworkStack instead of GrpcNetworking
/// GrpcNetworkingManager is responsible for managing
/// channels and message queues between MPC parties.
#[derive(Debug, Clone)]
pub struct GrpcNetworkingManager {
    pub message_queues: Arc<MessageQueueStores>,
    owner: Identity,
    conf: OptionConfigWrapper,
    sending_service: GrpcSendingService,
}

pub type GrpcServer = GnetworkingServer<NetworkingImpl>;

impl GrpcNetworkingManager {
    /// Create a new server from the networking manager.
    /// The server can be used as a tower Service.
    pub fn new_server(&self) -> GnetworkingServer<impl Gnetworking> {
        GnetworkingServer::new(NetworkingImpl {
            message_queues: Arc::clone(&self.message_queues),
        })
        .max_decoding_message_size(self.conf.get_max_en_decode_message_size())
        .max_encoding_message_size(self.conf.get_max_en_decode_message_size())
    }

    /// Owner should be the external address
    pub fn new(
        owner: Identity,
        cert_bundle: Option<CertificatePaths>,
        conf: Option<CoreToCoreNetworkConfig>,
    ) -> Self {
        GrpcNetworkingManager {
            message_queues: Default::default(),
            owner,
            conf: OptionConfigWrapper { conf },
            sending_service: GrpcSendingService::new(cert_bundle, conf),
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
        network_mode: NetworkMode,
    ) -> Arc<impl Networking> {
        let others = roles
            .iter()
            .filter_map(|(_role, identity)| {
                if identity != &self.owner {
                    Some(identity.clone())
                } else {
                    None
                }
            })
            .collect_vec();

        // Tell the sending service to spawns network threads to communicate wit the others
        let connection_channel = self.sending_service.add_connections(others).unwrap();

        // Create the message queue for this session id (this queue will be written to by the grpc server and read by the NetworkSession)
        let message_store = DashMap::new();
        for (_role, identity) in roles {
            let (tx, rx) = channel::<NetworkRoundValue>(self.conf.get_message_limit());
            message_store.insert(identity, (Arc::new(tx), Arc::new(Mutex::new(rx))));
        }
        let message_store = Arc::new(message_store);
        self.message_queues
            .insert(session_id, message_store.clone());

        let timeout = match network_mode {
            NetworkMode::Async => *NETWORK_TIMEOUT_ASYNC,
            NetworkMode::Sync => self.conf.get_network_timeout(),
        };
        Arc::new(NetworkSession {
            owner: self.owner.clone(),
            session_id,
            sending_channels: connection_channel,
            receiving_channels: message_store,
            round_counter: RwLock::new(0),
            network_mode,
            conf: self.conf.clone(),
            init_time: OnceLock::new(),
            current_network_timeout: RwLock::new(timeout),
            next_network_timeout: RwLock::new(timeout),
            max_elapsed_time: RwLock::new(Duration::ZERO),
        })
    }
}

// we need a counter for each value sent over the local queues
// so that messages that haven't been pickup up using receive() calls will get dropped
#[derive(Debug)]
pub struct NetworkRoundValue {
    pub value: Vec<u8>,
    pub round_counter: usize,
}

pub(crate) type MessageQueueStore = DashMap<
    Identity,
    (
        Arc<Sender<NetworkRoundValue>>,
        Arc<Mutex<Receiver<NetworkRoundValue>>>,
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
        // The DNS component must match the "tag" that's in the request for identity verification,
        // in this case it's party1.com.
        // We also require party1.com to be the subject and the issuer CN too,
        // since we're using self-signed certificates at the moment.
        let valid_tls_senders = extract_valid_sender_sans(&request)
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e))?;
        tracing::debug!("extract_valid_sender_sans returned {:?}", valid_tls_senders);

        let request = request.into_inner();
        let tag = bincode::deserialize::<Tag>(&request.tag).map_err(|_e| {
            tonic::Status::new(tonic::Code::Aborted, "failed to parse value".to_string())
        })?;

        if let Some(sender) = valid_tls_senders {
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
            let host = host_and_port[0];
            if sender != host {
                return Err(tonic::Status::new(
                    tonic::Code::Unauthenticated,
                    format!("wrong sender: expected {:?} to be in {:?}", host, sender),
                ));
            }
        } else {
            tracing::warn!("No valid TLS senders known.");
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
            let msg = format!(
                "unknown session id {:?} for from sender {:?} (round {})",
                tag.session_id, tag.sender, tag.round_counter
            );
            tracing::error!(msg);
            Err(tonic::Status::new(tonic::Code::NotFound, msg))
        }
    }
}

/// returns the list of accepted sender SANs that is contained in the request's client peer certificates
fn extract_valid_sender_sans<T>(request: &tonic::Request<T>) -> Result<Option<String>, String> {
    match request.peer_certs() {
        None => Ok(None),
        Some(certs) => {
            // Convert CertificateDer to tonic Certificate - since Certificate is just a wrapper
            // around Vec<u8>, we can create it directly from the DER bytes
            let cert_slice: Vec<Certificate> = certs
                .iter()
                .map(|c| Certificate::from_pem(c.as_ref()))
                .collect();

            // Extract SAN from the converted certificates
            let san_strings = extract_san_from_certs(&cert_slice, false)?;
            Ok(Some(san_strings))
        }
    }
}

/// Extract the party name from the certificate.
///
/// Each party should have its own self-signed certificate.
/// Each self-signed certificate is loaded into the trust store of all the parties.
pub fn extract_san_from_certs(certs: &[Certificate], use_pem: bool) -> Result<String, String> {
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
            x509_parser::extensions::GeneralName::DNSName(s) => Some(*s),
            _ => None,
        })
        .collect();

    if san_strings.is_empty() {
        return Err("No valid SAN found".to_string());
    }

    // find the subject and issuer CN, check there's a matching name in SAN list
    let Some(subject) = cert.subject().iter_common_name().next() else {
        return Err("Bad certificate: missing subject".to_owned());
    };
    let subject_str = subject.as_str().map_err(|e| e.to_string())?;

    let Some(issuer) = cert.issuer().iter_common_name().next() else {
        return Err("Bad certificate: missing issuer".to_owned());
    };
    let issuer_str = issuer.as_str().map_err(|e| e.to_string())?;

    if subject_str != issuer_str {
        return Err("Subject CN does not match issuer CN".to_owned());
    }

    if !san_strings.contains(&subject_str) {
        return Err("Subject CN not found in SAN".to_owned());
    }

    Ok(subject_str.to_string())
}

#[derive(Serialize, Deserialize, Debug)]
struct Tag {
    session_id: SessionId,
    sender: Identity,
    round_counter: usize,
}
