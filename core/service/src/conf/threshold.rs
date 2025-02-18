use distributed_decryption::conf::party::CertificatePaths;
use distributed_decryption::execution::online::preprocessing::redis::RedisConf;
use distributed_decryption::execution::runtime::party::{Identity, Role};
use distributed_decryption::networking::grpc::CoreToCoreNetworkConfig;
use kms_common::DecryptionMode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ThresholdPartyConf {
    // endpoint for incoming peer requests
    pub listen_address: String,
    // endpoint for the communication between the MPC servers
    pub listen_port: u16,

    pub threshold: u8,
    pub my_id: usize,
    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub preproc_redis: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub peers: Vec<PeerConf>,
    pub core_to_core_net: Option<CoreToCoreNetworkConfig>,
    pub decryption_mode: DecryptionMode,
}

impl ThresholdPartyConf {
    pub fn get_tls_cert_paths(&self) -> Option<CertificatePaths> {
        let cert_paths: Option<Vec<String>> =
            self.peers.iter().map(|c| c.tls_cert_path.clone()).collect();

        match (
            cert_paths,
            self.tls_cert_path.clone(),
            self.tls_key_path.clone(),
        ) {
            (Some(paths), Some(cert), Some(key)) => Some(CertificatePaths {
                cert,
                key,
                calist: paths.join(","),
            }),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PeerConf {
    pub party_id: usize,
    pub address: String,
    pub port: u16,
    pub tls_cert_path: Option<String>,
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
