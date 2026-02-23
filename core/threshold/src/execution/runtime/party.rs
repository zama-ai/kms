use algebra::role::RoleTrait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The identity of a MPC party.
///
/// When TLS is used, this must be the subject CN in the x509 certificate.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct MpcIdentity(pub String);

impl std::fmt::Display for MpcIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for MpcIdentity {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Runtime identity of party.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Identity {
    hostname: String,
    port: u16,
    mpc_identity: Option<MpcIdentity>,
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.hostname, self.port)
    }
}

impl Identity {
    /// Create a new Identity with the given hostname and port.
    pub fn new(hostname: String, port: u16, mpc_identity: Option<String>) -> Self {
        Identity {
            hostname,
            port,
            mpc_identity: mpc_identity.map(MpcIdentity),
        }
    }

    /// Get the hostname part of the identity.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Get the port part of the identity.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the MPC identity part of the identity, defaults to hostname if not set
    pub fn mpc_identity(&self) -> MpcIdentity {
        self.mpc_identity
            .clone()
            .unwrap_or_else(|| MpcIdentity(format!("{}:{}", &self.hostname, self.port)))
    }
}

/*
impl From<(String, u16)> for Identity {
    fn from((hostname, port): (String, u16)) -> Self {
        Identity(hostname, port)
    }
}

impl From<(&str, u16)> for Identity {
    fn from((hostname, port): (&str, u16)) -> Self {
        Identity(hostname.to_string(), port)
    }
}

impl FromStr for Identity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid identity format '{s}'. Expected 'hostname:port'"
            ));
        }

        let hostname = parts[0].to_string();
        let port = parts[1]
            .parse::<u16>()
            .map_err(|_| format!("Invalid port '{}' in identity '{}'", parts[1], s))?;

        Ok(Identity(hostname, port))
    }
}
*/

#[derive(Debug, Clone, Default)]
pub struct RoleAssignment<R: RoleTrait> {
    // NOTE: the String is the MPC identity
    pub inner: HashMap<R, Identity>,
}

impl<R: RoleTrait> From<HashMap<R, Identity>> for RoleAssignment<R> {
    fn from(map: HashMap<R, Identity>) -> Self {
        let inner = map.into_iter().collect();
        RoleAssignment { inner }
    }
}

impl<R: RoleTrait> RoleAssignment<R> {
    pub fn empty() -> Self {
        RoleAssignment {
            inner: HashMap::new(),
        }
    }

    pub fn get(&self, role: &R) -> Option<&Identity> {
        self.inner.get(role)
    }

    pub fn contains_key(&self, role: &R) -> bool {
        self.inner.contains_key(role)
    }

    pub fn keys(&self) -> impl Iterator<Item = &R> {
        self.inner.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&R, &Identity)> {
        self.inner.iter()
    }

    pub fn remove(&mut self, role: &R) -> Option<Identity> {
        self.inner.remove(role)
    }

    pub fn insert(&mut self, role: R, identity: Identity) -> Option<Identity> {
        self.inner.insert(role, identity)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
