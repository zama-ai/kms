use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ops::{Index, IndexMut},
};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum RoleVersioned {
    V0(Role),
}

pub trait RoleTrait:
    Default
    + std::fmt::Debug
    + std::fmt::Display
    + Sync
    + Send
    + Eq
    + PartialOrd
    + Ord
    + Clone
    + Copy
    + std::hash::Hash
    + 'static
{
    type ThresholdType: std::fmt::Debug + Copy + Sync + Send;
    fn get_role_kind(&self) -> RoleKind;
    fn is_threshold_smaller_than_num_parties(
        threshold: Self::ThresholdType,
        parties: &HashSet<Self>,
    ) -> bool;
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleKind {
    SingleSet(Role),
    TwoSet(TwoSetsRole),
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[display("Set1: {}, Set2: {}", role_set_1, role_set_2)]
pub struct DualRole {
    pub role_set_1: Role,
    pub role_set_2: Role,
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TwoSetsRole {
    Set1(Role),
    Set2(Role),
    Both(DualRole),
}

impl TwoSetsRole {
    pub fn is_set1(&self) -> bool {
        matches!(self, TwoSetsRole::Set1(_) | TwoSetsRole::Both(_))
    }

    pub fn is_set2(&self) -> bool {
        matches!(self, TwoSetsRole::Set2(_) | TwoSetsRole::Both(_))
    }
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

impl RoleTrait for Role {
    type ThresholdType = u8;
    fn get_role_kind(&self) -> RoleKind {
        RoleKind::SingleSet(*self)
    }

    fn is_threshold_smaller_than_num_parties(
        threshold: Self::ThresholdType,
        parties: &HashSet<Self>,
    ) -> bool {
        parties.len() > threshold as usize
    }
}

impl Default for TwoSetsRole {
    fn default() -> Self {
        TwoSetsRole::Set1(Role::default())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TwoSetsThreshold {
    pub threshold_set_1: u8,
    pub threshold_set_2: u8,
}

impl RoleTrait for TwoSetsRole {
    type ThresholdType = TwoSetsThreshold;
    fn get_role_kind(&self) -> RoleKind {
        RoleKind::TwoSet(*self)
    }

    fn is_threshold_smaller_than_num_parties(
        threshold: Self::ThresholdType,
        parties: &HashSet<Self>,
    ) -> bool {
        let (mut num_parties_in_set_1, mut num_parties_in_set_2) = (0, 0);
        parties.iter().for_each(|role| {
            if role.is_set1() {
                num_parties_in_set_1 += 1;
            }
            if role.is_set2() {
                num_parties_in_set_2 += 1;
            }
        });
        num_parties_in_set_1 > threshold.threshold_set_1 as usize
            && num_parties_in_set_2 > threshold.threshold_set_2 as usize
    }
}

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

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn test_threshold_check() {
        // Simple Role success
        let threshold = 2;
        let parties = HashSet::from([
            Role::indexed_from_one(1),
            Role::indexed_from_one(2),
            Role::indexed_from_one(3),
        ]);
        assert!(Role::is_threshold_smaller_than_num_parties(
            threshold, &parties
        ));

        // Simple Role failure
        let threshold = 3;
        let parties = HashSet::from([
            Role::indexed_from_one(1),
            Role::indexed_from_one(2),
            Role::indexed_from_one(3),
        ]);
        assert!(!Role::is_threshold_smaller_than_num_parties(
            threshold, &parties
        ));

        // TwoSetsRole success
        let threshold = TwoSetsThreshold {
            threshold_set_1: 2,
            threshold_set_2: 1,
        };

        let parties = HashSet::from([
            TwoSetsRole::Set1(Role::indexed_from_one(1)),
            TwoSetsRole::Set1(Role::indexed_from_one(2)),
            TwoSetsRole::Both(DualRole {
                role_set_1: Role::indexed_from_one(3),
                role_set_2: Role::indexed_from_one(1),
            }),
            TwoSetsRole::Set2(Role::indexed_from_one(2)),
        ]);
        assert!(TwoSetsRole::is_threshold_smaller_than_num_parties(
            threshold, &parties
        ));

        // TwoSetsRole failure set 1
        let threshold = TwoSetsThreshold {
            threshold_set_1: 3,
            threshold_set_2: 1,
        };

        let parties = HashSet::from([
            TwoSetsRole::Set1(Role::indexed_from_one(1)),
            TwoSetsRole::Set1(Role::indexed_from_one(2)),
            TwoSetsRole::Both(DualRole {
                role_set_1: Role::indexed_from_one(3),
                role_set_2: Role::indexed_from_one(1),
            }),
            TwoSetsRole::Set2(Role::indexed_from_one(2)),
        ]);
        assert!(!TwoSetsRole::is_threshold_smaller_than_num_parties(
            threshold, &parties
        ));

        // TwoSetsRole failure set 2
        let threshold = TwoSetsThreshold {
            threshold_set_1: 2,
            threshold_set_2: 2,
        };
        let parties = HashSet::from([
            TwoSetsRole::Set1(Role::indexed_from_one(1)),
            TwoSetsRole::Set1(Role::indexed_from_one(2)),
            TwoSetsRole::Both(DualRole {
                role_set_1: Role::indexed_from_one(3),
                role_set_2: Role::indexed_from_one(1),
            }),
            TwoSetsRole::Set2(Role::indexed_from_one(2)),
        ]);
        assert!(!TwoSetsRole::is_threshold_smaller_than_num_parties(
            threshold, &parties
        ));
    }
}
