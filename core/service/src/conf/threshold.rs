use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::online::preprocessing::redis::RedisConf;
use threshold_fhe::execution::runtime::party::{Identity, Role};
use threshold_fhe::networking::{grpc::CoreToCoreNetworkConfig, tls::ReleasePCRValues};

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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TlsConf {
    pub cert: TlsCert,
    pub key: TlsKey,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsCert {
    Path(PathBuf),
    Pem(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsKey {
    Path(PathBuf),
    Pem(String),
    // If set, the party will generate a keypair inside of the enclave and
    // issues a self-signed TLS certificate for it that bundles the certificate
    // used to sign the party enclave image and the attestation document
    Enclave(EnclaveConf),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnclaveConf {
    // If `trusted_releases` is set, the party will drop incoming messages from
    // parties that cannot provide AWS Nitro attestation documents with these
    // PCR values
    pub trusted_releases: Vec<ReleasePCRValues>,
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
