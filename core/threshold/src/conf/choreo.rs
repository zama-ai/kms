//! Settings based on [`config-rs`] crate which follows 12-factor configuration model.
//! Configuration file by default is under `config` folder.
//!
use serde::{Deserialize, Serialize};
use tonic::transport::Uri;

use crate::choreography::choreographer::NetworkTopology;
use crate::execution::runtime::party::{Identity, Role, RoleAssignment};
use crate::execution::runtime::session::DecryptionMode;

use super::Tracing;

#[derive(Clone, Deserialize, Serialize)]
pub struct ChoreoParty {
    pub logical_address: String,
    pub physical_address: String,
    pub logical_port: u16,
    pub physical_port: u16,
    pub id: usize,
}

impl From<&ChoreoParty> for Role {
    fn from(party: &ChoreoParty) -> Role {
        Role::indexed_by_one(party.id)
    }
}

impl From<&ChoreoParty> for Identity {
    fn from(party: &ChoreoParty) -> Identity {
        Identity::from(&format!("{}:{}", party.logical_address, party.logical_port))
    }
}

impl TryFrom<&ChoreoParty> for Uri {
    type Error = anyhow::Error;
    fn try_from(party: &ChoreoParty) -> Result<Uri, Self::Error> {
        let uri: Uri = format!("http://{}:{}", party.physical_address, party.physical_port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Error on parsing uri {}", e))?;
        Ok(uri)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ThresholdTopology {
    pub peers: Vec<ChoreoParty>,
    pub threshold: u32,
}

impl From<&ThresholdTopology> for RoleAssignment {
    fn from(topology: &ThresholdTopology) -> RoleAssignment {
        topology
            .peers
            .iter()
            .map(|party| (party.into(), party.into()))
            .collect()
    }
}

impl TryFrom<&ThresholdTopology> for NetworkTopology {
    type Error = anyhow::Error;
    fn try_from(topology: &ThresholdTopology) -> Result<NetworkTopology, Self::Error> {
        topology
            .peers
            .iter()
            .map(|party| {
                let uri: Uri = party.try_into()?;
                Ok((party.into(), uri))
            })
            .collect()
    }
}

/// Struct for storing settings.
#[derive(Deserialize, Serialize, Clone)]
pub struct ChoreoConf {
    pub threshold_topology: ThresholdTopology,
    pub number_messages: Option<usize>,
    storage_folder: String,
    session_file: String,
    pub params_file: String,
    pub decrypt_mode: DecryptionMode,
    epoch_id: Option<usize>,
    pub witness_dim: Option<u32>,
    pub tracing: Option<Tracing>,
}

impl ChoreoConf {
    pub fn epoch(&self) -> u128 {
        self.epoch_id.unwrap_or(1) as u128
    }

    pub fn pub_key_file(&self) -> String {
        format!("{}/pk.bin", self.storage_folder)
    }

    pub fn crs_file(&self) -> String {
        format!("{}/crs_{}.bin", self.storage_folder, self.epoch())
    }

    pub fn session_file_path(&self) -> String {
        format!("{}/{}", self.storage_folder, self.session_file)
    }
}
