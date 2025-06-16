use crate::execution::runtime::party::{Identity, Role};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Party {
    address: String,
    port: u16,
    id: usize,
    choreoport: u16,
}

impl Party {
    /// Returns the address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the id.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns the choreographer port.
    pub fn choreoport(&self) -> u16 {
        self.choreoport
    }
}

impl From<&Party> for Role {
    fn from(party_conf: &Party) -> Self {
        Role::indexed_from_one(party_conf.id)
    }
}

impl From<&Party> for Identity {
    fn from(party_conf: &Party) -> Self {
        Identity::from(&format!("{}:{}", party_conf.address, party_conf.port))
    }
}

#[cfg(feature = "choreographer")]
pub mod choreo;
pub mod party;
