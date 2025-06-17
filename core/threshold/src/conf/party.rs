//! Settings based on [`config-rs`] crate which follows 12-factor configuration model.
//! Configuration file by default is under `config` folder.
//!
use super::Party;
use crate::{
    execution::online::preprocessing::redis::RedisConf, networking::grpc::CoreToCoreNetworkConfig,
};
use itertools::Itertools;
use observability::conf::TelemetryConfig;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::{
    client::ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use x509_parser::pem::parse_x509_pem;

/// Struct for storing protocol settings
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Protocol {
    host: Party,
    peers: Option<Vec<Party>>,
}

impl Protocol {
    /// Returns the host configuration.
    pub fn host(&self) -> &Party {
        &self.host
    }

    /// Returns the peers configuration.
    pub fn peers(&self) -> &Option<Vec<Party>> {
        &self.peers
    }
}

/// Struct for storing settings.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PartyConf {
    protocol: Protocol,
    pub telemetry: Option<TelemetryConfig>,
    pub redis: Option<RedisConf>,
    /// If [certpaths] is Some(_), then TLS will be enabled
    /// for the core-to-core communication
    pub certpaths: Option<CertificatePaths>,
    pub net_conf: Option<CoreToCoreNetworkConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertificatePaths {
    /// My certificate
    pub cert: String,
    /// My signing key
    pub key: String,
    /// A list of CA paths is a string delimited by commas,
    /// like "path/to/ca1.pem,path/to/ca2.pem,path/to/ca3.pem,"
    /// this is a consequence of using the config crate
    /// when the [calist] is populated using an environment
    /// variable, namely environment variables only support
    /// the string type.
    ///
    /// Do not put an underscore in this name otherwise
    /// it will confuse the config crate.
    pub calist: String,
}

impl CertificatePaths {
    pub fn get_certificate(&self) -> anyhow::Result<tonic::transport::Certificate> {
        let cert_str = std::fs::read_to_string(&self.cert)?;
        Ok(tonic::transport::Certificate::from_pem(cert_str))
    }

    pub fn get_identity(&self) -> anyhow::Result<tonic::transport::Identity> {
        let cert = std::fs::read_to_string(&self.cert)?;
        let key = std::fs::read_to_string(&self.key)?;
        Ok(tonic::transport::Identity::from_pem(cert, key))
    }

    pub fn get_client_tls_conf(&self) -> anyhow::Result<ClientConfig> {
        // public key certificate
        let cert_bytes = std::fs::read_to_string(&self.cert)?;
        let cert = parse_x509_pem(cert_bytes.as_ref())?.1;
        let cert_chain = vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()];

        // private key
        let key_bytes = std::fs::read_to_string(&self.key)?;
        let key = parse_x509_pem(key_bytes.as_ref())?.1;
        let key_der = PrivateKeyDer::try_from(key.contents.as_slice())
            .unwrap_or_else(|e| panic!("Could not read TLS private key: {}", e))
            .clone_key();

        // trust roots
        let ca_certs_bytes = self
            .calist
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|path| {
                std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("Could not read CA certificates: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ca_certs_list = ca_certs_bytes
            .into_iter()
            .map(|cert_bytes| {
                parse_x509_pem(cert_bytes.as_ref())
                    .map_err(|e| anyhow::anyhow!("Failed to parse CA certificate: {e}"))
                    .map(|(_, cert)| cert)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs_list {
            roots.add(CertificateDer::from_slice(&cert.contents))?;
        }

        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, key_der)
            .map_err(|e| anyhow::anyhow!("Failed to build TLS client configuration: {e}"))
    }

    pub fn get_flattened_ca_list(&self) -> anyhow::Result<tonic::transport::Certificate> {
        let client_ca_cert_buf = {
            let list = self
                .calist
                .split(',')
                .filter(|s| !s.is_empty())
                .map(std::fs::read_to_string)
                .collect::<Result<Vec<_>, _>>()?;
            list.join("")
        };
        Ok(tonic::transport::Certificate::from_pem(client_ca_cert_buf))
    }

    /// Iterate over the certificates and find the one that contains
    /// Issue and subject CN that match the parameter cn.
    pub fn get_ca_by_name(&self, cn: &str) -> anyhow::Result<tonic::transport::Certificate> {
        let list = self
            .calist
            .split(',')
            .filter(|s| !s.is_empty())
            .map(std::fs::read_to_string)
            .collect::<Result<Vec<_>, _>>()?;
        for buf in list {
            let (_rem, c) = x509_parser::pem::parse_x509_pem(buf.as_ref())?;
            let x509 = c.parse_x509()?;

            // check that one of the SAN is the cn
            let Some(sans) = x509.subject_alternative_name()? else {
                tracing::error!("SAN not specified");
                continue;
            };
            if !sans
                .value
                .general_names
                .iter()
                .filter_map(|san| match san {
                    x509_parser::extensions::GeneralName::DNSName(s) => Some(s),
                    _ => None,
                })
                .contains(&cn)
            {
                continue;
            }

            let Some(subject) = x509.subject().iter_common_name().next() else {
                tracing::error!("bad certificate, missing subject");
                continue;
            };
            let Some(issuer) = x509.issuer().iter_common_name().next() else {
                tracing::error!("bad certificate, missing issuer");
                continue;
            };

            // then issuer and subject CN should match
            if subject.as_str()? == cn && issuer.as_str()? == cn {
                return Ok(tonic::transport::Certificate::from_pem(buf));
            }

            // continue otherwise
        }

        Err(anyhow::anyhow!("no name found matching {cn}"))
    }
}

/// This is an example of the configuration file using `PartyConf` struct.
///
/// ```toml
/// [protocol.host]
/// address = "p1"
/// port = 50000
/// id = 1
/// choreoport = 60000
///
/// [telemetry]
/// service_name = "moby"
/// endpoint = "http://localhost:4317"
///
/// [redis]
/// host = "redis://127.0.0.1"
///
/// [certpaths]
/// cert = "/path/to/cert"
/// key = "/path/to/key"
/// calist = "/path/one,/path/two"
///
/// [[protocol.peers]]
/// address = "p2"
/// port = 50000
/// id = 2
/// choreoport = 60000
///
/// [[protocol.peers]]
/// address = "p3"
/// port = 50000
/// id = 3
/// choreoport = 60000
///
/// [[protocol.peers]]
/// address = "p4"
/// port = 50000
/// id = 4
/// choreoport = 60000
/// ```
///
/// The `peers` field is optional.
/// If it is not present, the `peers` field will be `None`. At the moment of writing this we are
/// not using the `peers` field, but it is there for future use.
/// If it is present, the `peers` field will be `Some(Vec<Party>)`.
/// The `peers` field is a list of `Party` struct.
/// The telemetry, redis and certpaths fields are also optional.
/// Core-to-core TLS will be enabled if certpaths is not empty.
impl PartyConf {
    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }
}

#[cfg(test)]
mod tests {
    use observability::conf::Settings;
    use std::env;

    use super::*;

    #[test]
    #[serial_test::parallel]
    fn test_party_conf_with_real_file() {
        let party_conf: PartyConf = Settings::builder()
            .path("src/tests/config/ddec_test")
            .env_prefix("DDEC")
            .build()
            .init_conf()
            .unwrap();
        let protocol = party_conf.protocol();
        let host = protocol.host();
        let peers = protocol.peers();

        let certpaths = party_conf.certpaths.clone().unwrap();
        assert_eq!(certpaths.cert, "/path/to/cert");
        assert_eq!(certpaths.key, "/path/to/key");
        assert_eq!(certpaths.calist, "/path/one,/path/two");

        assert_eq!(
            host,
            &Party {
                address: "p1".to_string(),
                port: 50000,
                id: 1,
                choreoport: 60000,
            }
        );
        assert!(peers.is_some());
        let peers = peers.as_ref().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(
            *peers,
            vec![
                Party {
                    address: "p2".to_string(),
                    port: 50001,
                    id: 2,
                    choreoport: 60001,
                },
                Party {
                    address: "p3".to_string(),
                    port: 50002,
                    id: 3,
                    choreoport: 60002,
                }
            ]
        );

        let core_to_core_net_conf = party_conf.net_conf;
        assert!(core_to_core_net_conf.is_some());
        let core_to_core_net_conf = core_to_core_net_conf.unwrap();
        assert_eq!(core_to_core_net_conf.message_limit, 70);
        assert_eq!(core_to_core_net_conf.multiplier, 1.1);
        assert_eq!(core_to_core_net_conf.max_interval, 5);
        assert_eq!(core_to_core_net_conf.max_elapsed_time, Some(300));
        assert_eq!(core_to_core_net_conf.network_timeout, 10);
        assert_eq!(core_to_core_net_conf.network_timeout_bk, 300);
        assert_eq!(core_to_core_net_conf.network_timeout_bk_sns, 1200);
        assert_eq!(core_to_core_net_conf.max_en_decode_message_size, 2147483648);
    }

    #[test]
    #[serial_test::parallel]
    fn test_party_conf_no_peers() {
        let party_conf: PartyConf = Settings::builder()
            .path("src/tests/config/ddec_no_peers")
            .env_prefix("DDEC")
            .build()
            .init_conf()
            .unwrap();
        let protocol = party_conf.protocol();
        let host = protocol.host();
        let peers = protocol.peers();

        assert_eq!(
            host,
            &Party {
                address: "p1".to_string(),
                port: 50000,
                id: 1,
                choreoport: 60000,
            }
        );
        assert!(peers.is_none());
    }

    #[test]
    #[serial_test::parallel]
    fn test_party_conf_error_conf() {
        let r = Settings::builder()
            .path("src/tests/config/error_conf")
            .env_prefix("DDEC")
            .build()
            .init_conf::<PartyConf>();
        assert!(r.is_err());
    }

    //Can't run this test in parallel with others as env variable take precedence over config files
    #[test]
    #[serial_test::serial]
    fn test_party_conf_with_env() {
        env::set_var("DDEC__PROTOCOL__HOST__ADDRESS", "p3");
        env::set_var("DDEC__PROTOCOL__HOST__PORT", "50000");
        env::set_var("DDEC__PROTOCOL__HOST__ID", "3");
        env::set_var("DDEC__PROTOCOL__HOST__CHOREOPORT", "60000");
        env::set_var("DDEC__CERTPATHS__CERT", "/path/to/cert");
        env::set_var("DDEC__CERTPATHS__KEY", "/path/to/key");
        env::set_var("DDEC__CERTPATHS__CALIST", "/path/one,/path/two");
        env::set_var("DDEC__TELEMETRY__TRACING_SERVICE_NAME", "moby-p3");
        env::set_var("DDEC__TELEMETRY__TRACING_ENDPOINT", "moby-p3-endpoint");

        env::set_var("DDEC__NET_CONF__MESSAGE_LIMIT", "60");
        env::set_var("DDEC__NET_CONF__MULTIPLIER", "2.2");
        env::set_var("DDEC__NET_CONF__MAX_INTERVAL", "4");
        env::set_var("DDEC__NET_CONF__MAX_ELAPSED_TIME", "200");
        env::set_var("DDEC__NET_CONF__NETWORK_TIMEOUT", "20");
        env::set_var("DDEC__NET_CONF__NETWORK_TIMEOUT_BK", "200");
        env::set_var("DDEC__NET_CONF__NETWORK_TIMEOUT_BK_SNS", "2300");
        env::set_var("DDEC__NET_CONF__MAX_EN_DECODE_MESSAGE_SIZE", "3258");
        let party_conf: PartyConf = Settings::builder()
            .env_prefix("DDEC")
            .build()
            .init_conf()
            .unwrap();

        let core_to_core_net_conf = party_conf.net_conf;
        assert!(core_to_core_net_conf.is_some());
        let core_to_core_net_conf = core_to_core_net_conf.unwrap();
        assert_eq!(core_to_core_net_conf.message_limit, 60);
        assert_eq!(core_to_core_net_conf.multiplier, 2.2);
        assert_eq!(core_to_core_net_conf.max_interval, 4);
        assert_eq!(core_to_core_net_conf.max_elapsed_time, Some(200));
        assert_eq!(core_to_core_net_conf.network_timeout, 20);
        assert_eq!(core_to_core_net_conf.network_timeout_bk, 200);
        assert_eq!(core_to_core_net_conf.network_timeout_bk_sns, 2300);
        assert_eq!(core_to_core_net_conf.max_en_decode_message_size, 3258);

        let bundle = party_conf.certpaths.unwrap();
        assert_eq!(bundle.cert, "/path/to/cert");
        assert_eq!(bundle.key, "/path/to/key");
        assert_eq!(bundle.calist, "/path/one,/path/two");
        assert_eq!(
            party_conf.telemetry.unwrap().tracing_service_name(),
            Some("moby-p3")
        );

        env::remove_var("DDEC__PROTOCOL__HOST__ADDRESS");
        env::remove_var("DDEC__PROTOCOL__HOST__PORT");
        env::remove_var("DDEC__PROTOCOL__HOST__ID");
        env::remove_var("DDEC__PROTOCOL__HOST__CHOREOPORT");
        env::remove_var("DDEC__CERTPATHS__CERT");
        env::remove_var("DDEC__CERTPATHS__KEY");
        env::remove_var("DDEC__CERTPATHS__CALIST");
        env::remove_var("DDEC__TELEMETRY__TRACING_SERVICE_NAME");
        env::remove_var("DDEC__TELEMETRY__TRACING_ENDPOINT");

        env::remove_var("DDEC__NET_CONF__MESSAGE_LIMIT");
        env::remove_var("DDEC__NET_CONF__MULTIPLIER");
        env::remove_var("DDEC__NET_CONF__MAX_INTERVAL");
        env::remove_var("DDEC__NET_CONF__MAX_ELAPSED_TIME");
        env::remove_var("DDEC__NET_CONF__NETWORK_TIMEOUT");
        env::remove_var("DDEC__NET_CONF__NETWORK_TIMEOUT_BK");
        env::remove_var("DDEC__NET_CONF__NETWORK_TIMEOUT_BK_SNS");
        env::remove_var("DDEC__NET_CONF__MAX_EN_DECODE_MESSAGE_SIZE");
    }
}
