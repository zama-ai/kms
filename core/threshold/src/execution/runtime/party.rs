use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ops::{Index, IndexMut},
    str::FromStr,
};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum RoleVersioned {
    V0(Role),
}

/// Role/party ID of a party (1...N)
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    Serialize,
    Deserialize,
    Zeroize,
    Versionize,
)]
#[versionize(RoleVersioned)]
/// This defines the role of a party in the distributed system.
/// Role are stored as 1-based indices, meaning that the first party has role 1, the second party has role 2, and so on.
/// However, when used to do direct indexing into a vector, it is converted to a 0-based index.
/// And we provide functions [`Role::get_from`] and [`Role::get_mut_from`] to retrieve elements from a vector using the role as 0-based index.
/// Roles can also be used for direct indexing into a vector using the [`Index`] and [`IndexMut`] traits, in which case the role is automatically converted to a 0-based index.
pub struct Role(u64);

impl Role {
    /// Create Role from a 1..N indexing (internally roles are _always_ stored as 1-based indices).
    pub fn indexed_from_one(x: usize) -> Self {
        assert_ne!(x, 0, "Role index must be greater than 0");
        Role(x as u64)
    }

    /// Create Role from a 0..N-1 indexing (internally roles are _always_ stored as 1-based indices).
    pub fn indexed_from_zero(x: usize) -> Self {
        Role(x as u64 + 1_u64)
    }

    // Retrieve index of Role considering that indexing starts from 1.
    pub fn one_based(&self) -> usize {
        self.0 as usize
    }

    /// Retrieve index of Role considering that indexing starts from 0.
    fn zero_based(&self) -> usize {
        self.0 as usize - 1
    }

    /// Access the given vector _safely_ using the role as a 0-based index.
    pub fn get_from<'a, T>(&self, vec: &'a [T]) -> Option<&'a T> {
        vec.get(self.zero_based())
    }

    /// Mutable access to the given vector _safely_ using the role as a 0-based index.
    pub fn get_mut_from<'a, T>(&self, vec: &'a mut [T]) -> Option<&'a mut T> {
        vec.get_mut(self.zero_based())
    }

    pub fn to_le_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl<T> Index<&Role> for [T] {
    type Output = T;

    fn index(&self, role: &Role) -> &Self::Output {
        self.get(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> IndexMut<&Role> for [T] {
    fn index_mut(&mut self, role: &Role) -> &mut Self::Output {
        self.get_mut(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> Index<&mut Role> for [T] {
    type Output = T;

    fn index(&self, role: &mut Role) -> &Self::Output {
        self.get(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> IndexMut<&mut Role> for [T] {
    fn index_mut(&mut self, role: &mut Role) -> &mut Self::Output {
        self.get_mut(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> Index<&Role> for Vec<T> {
    type Output = T;

    fn index(&self, role: &Role) -> &Self::Output {
        self.get(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> IndexMut<&Role> for Vec<T> {
    fn index_mut(&mut self, role: &Role) -> &mut Self::Output {
        self.get_mut(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> Index<&mut Role> for Vec<T> {
    type Output = T;

    fn index(&self, role: &mut Role) -> &Self::Output {
        self.get(role.zero_based())
            .expect("Role index out of bounds")
    }
}

impl<T> IndexMut<&mut Role> for Vec<T> {
    fn index_mut(&mut self, role: &mut Role) -> &mut Self::Output {
        self.get_mut(role.zero_based())
            .expect("Role index out of bounds")
    }
}

/// Runtime identity of party.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Display, Serialize, Deserialize, Default)]
#[display("{}:{}", _0, _1)]
pub struct Identity(pub String, pub u16);

impl Identity {
    /// Create a new Identity with the given hostname and port.
    pub fn new(hostname: String, port: u16) -> Self {
        Identity(hostname, port)
    }

    /// Get the hostname part of the identity.
    pub fn hostname(&self) -> &str {
        &self.0
    }

    /// Get the port part of the identity.
    pub fn port(&self) -> u16 {
        self.1
    }

    /// Convert the identity to a tuple of (hostname, port).
    pub fn to_tuple(&self) -> (&str, u16) {
        (&self.0, self.1)
    }

    /// Convert the identity to an owned tuple of (hostname, port).
    pub fn into_tuple(self) -> (String, u16) {
        (self.0, self.1)
    }
}

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

pub type RoleAssignment = HashMap<Role, Identity>;
