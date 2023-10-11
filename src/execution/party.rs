use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Role/party ID of a party.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Display, Serialize, Deserialize,
)]
pub struct Role(pub u64);

impl From<u64> for Role {
    fn from(s: u64) -> Self {
        Role(s)
    }
}

impl Role {
    pub fn party_id(&self) -> usize {
        self.0 as usize
    }
    pub fn zero_index(&self) -> usize {
        self.0 as usize - 1
    }
    pub fn from_zero(s: usize) -> Self {
        Role(s as u64 + 1)
    }
}

/// Runtime identity of party.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Display, Serialize, Deserialize)]
pub struct Identity(pub String);

impl Default for Identity {
    fn default() -> Self {
        Identity("test_id".to_string())
    }
}

impl From<&str> for Identity {
    fn from(s: &str) -> Self {
        Identity(s.to_string())
    }
}

impl From<&String> for Identity {
    fn from(s: &String) -> Self {
        Identity(s.clone())
    }
}

impl From<String> for Identity {
    fn from(s: String) -> Self {
        Identity(s)
    }
}

pub type RoleAssignment = HashMap<Role, Identity>;
