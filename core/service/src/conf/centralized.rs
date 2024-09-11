use crate::conf::storage::StorageConfigWith;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CentralizedConfig {
    pub url: String,
    pub param_file_map: HashMap<String, String>,
    pub grpc_max_message_size: usize,
}

impl From<StorageConfigWith<CentralizedConfig>> for CentralizedConfig {
    fn from(value: StorageConfigWith<CentralizedConfig>) -> Self {
        value.rest
    }
}

impl CentralizedConfig {
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
