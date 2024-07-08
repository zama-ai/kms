use conf_trace::conf::Tracing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use url::Url;

use super::ConfigTracing;

#[derive(Serialize, Deserialize, Clone)]
pub struct CentralizedConfig {
    pub public_storage_path: Option<String>,
    pub private_storage_path: Option<String>,
    #[serde(flatten)]
    pub rest: CentralizedConfigNoStorage,
    pub tracing: Option<Tracing>,
}

impl ConfigTracing for CentralizedConfig {
    fn tracing(&self) -> Option<Tracing> {
        self.tracing.clone()
    }
}

impl CentralizedConfig {
    pub fn private_storage_path(&self) -> Option<&Path> {
        self.private_storage_path.as_ref().map(Path::new)
    }

    pub fn public_storage_path(&self) -> Option<&Path> {
        self.public_storage_path.as_ref().map(Path::new)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CentralizedConfigNoStorage {
    pub url: String,
    pub param_file_map: HashMap<String, String>,
    pub grpc_max_message_size: usize,
}

impl From<CentralizedConfig> for CentralizedConfigNoStorage {
    fn from(value: CentralizedConfig) -> Self {
        value.rest
    }
}

impl CentralizedConfigNoStorage {
    pub fn get_socket_addr(&self) -> anyhow::Result<SocketAddr> {
        let url = Url::parse(&self.url)?;
        if url.scheme() != "http" && url.scheme() != "https" && url.scheme() != "" {
            return Err(anyhow::anyhow!(
                "Invalid scheme in URL. Only http and https are supported."
            ));
        }
        let host_str: &str = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid host in URL."))?;
        let port: u16 = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("Invalid port in URL."))?;
        let socket: SocketAddr = format!("{}:{}", host_str, port).parse()?;

        Ok(socket)
    }
}
