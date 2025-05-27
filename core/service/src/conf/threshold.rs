use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::online::preprocessing::redis::RedisConf;
use threshold_fhe::execution::runtime::party::{Identity, Role};
use threshold_fhe::networking::{grpc::CoreToCoreNetworkConfig, tls::ReleasePCRValues};
use x509_parser::pem::{parse_x509_pem, Pem};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ThresholdPartyConf {
    // network interface for MPC communication
    pub listen_address: String,
    // port for MPC communication
    pub listen_port: u16,
    // TLS identity if MPC communication should use TLS
    pub tls: Option<TlsConf>,

    pub threshold: u8,
    pub my_id: usize,
    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub preproc_redis: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
    pub peers: Vec<PeerConf>,
    pub core_to_core_net: Option<CoreToCoreNetworkConfig>,
    pub decryption_mode: DecryptionMode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TlsConf {
    // Both public key certificate and private key are provided externally. If
    // enclaves are not used, this is the ony option.
    Manual {
        cert: TlsCert,
        key: TlsKey,
    },
    // The party will generate a keypair inside of the enclave on boot and issue
    // an ephemeral self-signed TLS certificate for it that bundles the provided
    // certificate and the attestation document. The enclave image must be
    // signed with the provided certificate.
    SemiAuto {
        cert: TlsCert,
        trusted_releases: Vec<ReleasePCRValues>,
    },
    // The party will use its core signing key to sign an emphemeral TLS
    // certificate on boot that that bundles the attestation document, acting as
    // its own CA. The CA certificate must be self-signed with the core signing
    // key and included in the peer list.
    FullAuto {
        trusted_releases: Vec<ReleasePCRValues>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsCert {
    Path(PathBuf),
    Pem(String),
}

impl TlsCert {
    pub fn into_pem(&self, my_id: usize, peers: &[PeerConf]) -> anyhow::Result<Pem> {
        let cert_bytes = match self {
            TlsCert::Path(ref cert_path) => std::fs::read_to_string(cert_path).map_err(|e| {
                anyhow::anyhow!("Failed to open file {}: {}", cert_path.display(), e)
            })?,
            TlsCert::Pem(ref cert_bytes) => cert_bytes.to_string(),
        };
        let cert_pem = parse_x509_pem(cert_bytes.as_ref())?.1;
        let x509_cert = cert_pem.parse_x509()?;
        // sanity check: peerlist needs to have an entry for the
        // current party
        let my_hostname = &peers
            .iter()
            .find(|peer| peer.party_id == my_id)
            .expect("Peer list does not have an entry for my id")
            .address;
        let subject = threshold_fhe::networking::tls::extract_subject_from_cert(&x509_cert)
            .map_err(|e| anyhow::anyhow!(e))?;
        if subject != *my_hostname {
            anyhow::bail!("Certificate subject {subject} does not match hostname {my_hostname}");
        }
        Ok(cert_pem)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsKey {
    Path(PathBuf),
    Pem(String),
}

impl TlsKey {
    pub fn into_pem(&self) -> anyhow::Result<Pem> {
        let key_bytes = match self {
            TlsKey::Path(ref key_path) => std::fs::read_to_string(key_path).map_err(|e| {
                anyhow::anyhow!("Failed to open file {}: {}", key_path.display(), e)
            })?,
            TlsKey::Pem(ref key_bytes) => key_bytes.to_string(),
        };
        Ok(parse_x509_pem(key_bytes.as_ref())?.1)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PeerConf {
    pub party_id: usize,
    pub address: String,
    pub port: u16,
    pub tls_cert: Option<TlsCert>,
}

impl PeerConf {
    /// Validity of the output is not guaranteed.
    pub fn into_role_identity(&self) -> (Role, Identity) {
        (
            Role::indexed_by_one(self.party_id),
            Identity(format!("{}:{}", self.address, self.port)),
        )
    }
}
