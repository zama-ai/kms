use std::collections::HashMap;
use std::path::Path;

use distributed_decryption::conf::party::CertificatePaths;
use distributed_decryption::execution::online::preprocessing::redis::RedisConf;
use distributed_decryption::execution::runtime::party::{Identity, Role};
use serde::{Deserialize, Serialize};

use super::Tracing;

#[derive(Serialize, Deserialize, Clone)]
pub struct ThresholdConfig {
    pub public_storage_path: Option<String>,
    pub private_storage_path: Option<String>,
    #[serde(flatten)]
    pub rest: ThresholdConfigNoStorage,
    pub tracing: Option<Tracing>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ThresholdConfigNoStorage {
    pub listen_address_client: String,
    pub listen_port_client: u16,
    pub listen_address_core: String,
    pub listen_port_core: u16,
    pub threshold: u8,
    pub my_id: usize,
    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub timeout_secs: u64,
    pub preproc_redis_conf: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub peer_confs: Vec<PeerConf>,
    pub param_file_map: HashMap<String, String>, // TODO parameters should be loaded once during boot
}

impl ThresholdConfigNoStorage {
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

#[derive(Serialize, Deserialize, Clone)]
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

impl From<ThresholdConfig> for ThresholdConfigNoStorage {
    fn from(value: ThresholdConfig) -> Self {
        value.rest
    }
}

impl ThresholdConfig {
    pub fn private_storage_path(&self) -> Option<&Path> {
        self.private_storage_path.as_ref().map(Path::new)
    }

    pub fn public_storage_path(&self) -> Option<&Path> {
        self.public_storage_path.as_ref().map(Path::new)
    }
}
