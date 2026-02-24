#! Pure-logic version of a Role and associated types.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt::Display,
    ops::{Index, IndexMut},
};
use zeroize::Zeroize;

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

#[derive(Debug, /*Display,*/ Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleKind {
    SingleSet(Role),
    TwoSet(TwoSetsRole),
}
impl Display for RoleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoleKind::SingleSet(role) => write!(f, "SingleSet({})", role),
            RoleKind::TwoSet(role) => write!(f, "TwoSet({})", role),
        }
    }
}

#[derive(Debug, /*Display,*/ Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// #[display("Set1: {}, Set2: {}", role_set_1, role_set_2)]
pub struct DualRole {
    pub role_set_1: Role,
    pub role_set_2: Role,
}

impl Display for DualRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Set1: {}, Set2: {}", self.role_set_1, self.role_set_2)
    }
}

#[derive(Debug, /*Display,*/ Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    // Display,
    Serialize,
    Deserialize,
    Zeroize,
    tfhe_versionable::Versionize,
)]
#[versionize(RoleVersioned)]
/// This defines the role of a party in the distributed system.
/// Role are stored as 1-based indices, meaning that the first party has role 1, the second party has role 2, and so on.
/// However, when used to do direct indexing into a vector, it is converted to a 0-based index.
/// And we provide functions [`Role::get_from`] and [`Role::get_mut_from`] to retrieve elements from a vector using the role as 0-based index.
/// Roles can also be used for direct indexing into a vector using the [`Index`] and [`IndexMut`] traits, in which case the role is automatically converted to a 0-based index.
pub struct Role(u64);

#[derive(Clone, Serialize, Deserialize, tfhe_versionable::VersionsDispatch)]
pub enum RoleVersioned {
    V0(Role),
}

// TODO(dp): this used `derive_more` before. Needed?
impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

impl Display for TwoSetsRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TwoSetsRole::Set1(role) => write!(f, "Set1({})", role),
            TwoSetsRole::Set2(role) => write!(f, "Set2({})", role),
            TwoSetsRole::Both(dual_role) => write!(f, "{}", dual_role),
        }
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
