//! Settings based on [`config-rs`] crate which follows 12-factor configuration model.
//! Configuration file by default is under `config` folder.
//!
use serde::{Deserialize, Serialize};

use crate::execution::online::preprocessing::redis::RedisConf;

use super::{Party, Tracing};

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
    pub tracing: Option<Tracing>,
    pub redis: Option<RedisConf>,
    /// If [certpaths] is Some(_), then TLS will be enabled
    /// for the core-to-core communication
    pub certpaths: Option<CertificatePaths>,
    /// If [certpaths] is Some(_) and choreousetls is true,
    /// TLS will be enabled for the choreographer-to-core
    /// communication.
    pub choreo_use_tls: bool,
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
    /// variable
    pub calist: String,
}

impl CertificatePaths {
    pub fn get_identity(&self) -> anyhow::Result<tonic::transport::Identity> {
        let cert = std::fs::read_to_string(&self.cert)?;
        let key = std::fs::read_to_string(&self.key)?;
        Ok(tonic::transport::Identity::from_pem(cert, key))
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
}

/// This is an example of the configuration file using `PartyConf` struct.
///
/// ```toml
/// choreo_use_tls = false
///
/// [protocol.host]
/// address = "p1"
/// port = 50000
/// id = 1
/// choreoport = 60000
///
/// [tracing]
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
/// The tracing, redis and certpaths fields are also optional.
/// Core-to-core TLS will be enabled if certpaths is not empty.
/// Choreographer-to-core TLS will be enabled if `choreo_use_tls`
/// is also enabled.
impl PartyConf {
    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }
}

#[cfg(test)]
mod tests {
    use crate::conf::Settings;

    use super::*;

    #[test]
    #[serial_test::parallel]
    fn test_party_conf_with_real_file() {
        let party_conf: PartyConf = Settings::builder()
            .path("src/tests/config/ddec_test")
            .build()
            .init_conf()
            .unwrap();
        assert!(party_conf.choreo_use_tls);
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
    }

    #[test]
    #[serial_test::parallel]
    fn test_party_conf_no_peers() {
        let party_conf: PartyConf = Settings::builder()
            .path("src/tests/config/ddec_no_peers")
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
            .build()
            .init_conf::<PartyConf>();
        assert!(r.is_err());
    }

    //Can't run this test in parallel with others as env variable take precedence over config files
    #[test]
    #[serial_test::serial]
    fn test_party_conf_with_env() {
        use std::env;
        env::set_var("DDEC-PROTOCOL-HOST-ADDRESS", "p3");
        env::set_var("DDEC-PROTOCOL-HOST-PORT", "50000");
        env::set_var("DDEC-PROTOCOL-HOST-ID", "3");
        env::set_var("DDEC-PROTOCOL-HOST-CHOREOPORT", "60000");
        env::set_var("DDEC-CERTPATHS-CERT", "/path/to/cert");
        env::set_var("DDEC-CERTPATHS-KEY", "/path/to/key");
        env::set_var("DDEC-CERTPATHS-CALIST", "/path/one,/path/two");
        env::set_var("DDEC-CHOREO_USE_TLS", "true");
        env::set_var("DDEC-TRACING-SERVICE_NAME", "moby-p3");
        env::set_var("DDEC-TRACING-ENDPOINT", "moby-p3-endpoint");
        let party_conf: PartyConf = Settings::builder().build().init_conf().unwrap();

        let bundle = party_conf.certpaths.unwrap();
        assert_eq!(bundle.cert, "/path/to/cert");
        assert_eq!(bundle.key, "/path/to/key");
        assert_eq!(bundle.calist, "/path/one,/path/two");
        assert!(party_conf.choreo_use_tls);
        assert_eq!(party_conf.tracing.unwrap().service_name, "moby-p3");

        env::remove_var("DDEC-PROTOCOL-HOST-ADDRESS");
        env::remove_var("DDEC-PROTOCOL-HOST-PORT");
        env::remove_var("DDEC-PROTOCOL-HOST-ID");
        env::remove_var("DDEC-PROTOCOL-HOST-CHOREOPORT");
        env::remove_var("DDEC-CERTPATHS-CERT");
        env::remove_var("DDEC-CERTPATHS-KEY");
        env::remove_var("DDEC-CERTPATHS-CALIST");
        env::remove_var("DDEC-CHOREO_USE_TLS");
        env::remove_var("DDEC-TRACING-SERVICE_NAME");
        env::remove_var("DDEC-TRACING-ENDPOINT");
    }
}
