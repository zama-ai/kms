use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Role/party ID of a party (1...N)
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Display, Serialize, Deserialize,
)]
pub struct Role(u64);

impl Role {
    /// Create Role from a 1..N indexing
    pub fn indexed_by_one(x: usize) -> Self {
        Role(x as u64)
    }

    /// Create Role from a 0..N-1 indexing
    pub fn indexed_by_zero(x: usize) -> Self {
        Role(x as u64 + 1_u64)
    }

    /// Retrieve index of Role considering that indexing starts from 1.
    pub fn one_based(&self) -> usize {
        self.0 as usize
    }

    /// Retrieve index of Role considering that indexing starts from 0.
    pub fn zero_based(&self) -> usize {
        self.0 as usize - 1
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
