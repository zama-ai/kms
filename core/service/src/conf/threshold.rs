use crate::conf::storage::StorageConfigWith;
use distributed_decryption::conf::party::CertificatePaths;
use distributed_decryption::execution::online::preprocessing::redis::RedisConf;
use distributed_decryption::execution::runtime::party::{Identity, Role};
use distributed_decryption::networking::grpc::CoreToCoreNetworkConfig;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThresholdConfig {
    pub listen_address_client: String,
    pub listen_port_client: u16,
    pub listen_address_core: String,
    pub listen_port_core: u16,
    pub threshold: u8,
    pub my_id: usize,
    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub timeout_secs: u64,
    pub grpc_max_message_size: usize,
    pub preproc_redis_conf: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub peer_confs: Vec<PeerConf>,
    pub core_to_core_net_conf: Option<CoreToCoreNetworkConfig>,
}

impl ThresholdConfig {
    pub fn get_tls_cert_paths(&self) -> Option<CertificatePaths> {
        let cert_paths: Option<Vec<String>> = self
            .peer_confs
            .iter()
            .map(|c| c.tls_cert_path.clone())
            .collect();

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

impl From<StorageConfigWith<ThresholdConfig>> for ThresholdConfig {
    fn from(value: StorageConfigWith<ThresholdConfig>) -> Self {
        value.rest
    }
}
