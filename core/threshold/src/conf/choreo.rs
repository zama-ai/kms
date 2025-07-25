//! Settings based on [`config-rs`] crate which follows 12-factor configuration model.
//! Configuration file by default is under `config` folder.
//!
use std::collections::HashMap;

use crate::choreography::choreographer::NetworkTopology;
use crate::execution::runtime::party::{Identity, Role};
use observability::conf::TelemetryConfig;
use serde::{Deserialize, Serialize};
use tonic::transport::Uri;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChoreoParty {
    pub logical_address: String,
    pub physical_address: String,
    pub logical_port: u16,
    pub physical_port: u16,
    pub choreo_logical_port: u16,
    pub choreo_physical_port: u16,
    pub id: usize,
    pub use_tls: bool,
}

impl From<&ChoreoParty> for Role {
    fn from(party: &ChoreoParty) -> Role {
        Role::indexed_from_one(party.id)
    }
}

impl From<&ChoreoParty> for Identity {
    fn from(party: &ChoreoParty) -> Identity {
        Identity::new(party.logical_address.clone(), party.logical_port, None)
    }
}

impl ChoreoParty {
    pub fn physical_addr_into_uri(&self) -> anyhow::Result<Uri> {
        let proto = if self.use_tls { "https" } else { "http" };
        let uri: Uri = format!(
            "{}://{}:{}",
            proto, self.physical_address, self.physical_port
        )
        .parse()
        .map_err(|e| anyhow::anyhow!("Error on parsing uri {}", e))?;
        Ok(uri)
    }

    pub fn choreo_physical_addr_into_uri(&self) -> anyhow::Result<Uri> {
        let uri: Uri = format!(
            "http://{}:{}",
            self.physical_address, self.choreo_physical_port
        )
        .parse()
        .map_err(|e| anyhow::anyhow!("Error on parsing uri {}", e))?;
        Ok(uri)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThresholdTopology {
    pub peers: Vec<ChoreoParty>,
    pub threshold: u32,
}

impl From<&ThresholdTopology> for HashMap<Role, Identity> {
    fn from(topology: &ThresholdTopology) -> HashMap<Role, Identity> {
        topology
            .peers
            .iter()
            .map(|party| (party.into(), party.into()))
            .collect()
    }
}

impl ThresholdTopology {
    pub fn physical_topology_into_network_topology(&self) -> anyhow::Result<NetworkTopology> {
        self.peers
            .iter()
            .map(|party| {
                let uri: Uri = party.physical_addr_into_uri()?;
                Ok((party.into(), uri))
            })
            .collect()
    }

    pub fn choreo_physical_topology_into_network_topology(
        &self,
    ) -> anyhow::Result<NetworkTopology> {
        self.peers
            .iter()
            .map(|party| {
                let uri: Uri = party.choreo_physical_addr_into_uri()?;
                Ok((party.into(), uri))
            })
            .collect()
    }
}

/// Struct for storing settings.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ChoreoConf {
    pub threshold_topology: ThresholdTopology,
    pub malicious_roles: Option<Vec<Role>>,
    pub telemetry: Option<TelemetryConfig>,

    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
}
