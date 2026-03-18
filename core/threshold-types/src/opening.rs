use std::collections::HashMap;

use crate::role::Role;

/// Enum to state whether we want to open
/// only to some designated parties or
/// to all parties at once.
pub enum OpeningKind<Z> {
    ToSome(HashMap<Role, Vec<Z>>),
    ToAll(Vec<Z>),
}

/// Enum to state from which set
/// we are expecting to receive openings
/// as well as how many
#[derive(Clone, Copy)]
pub enum ExternalOpeningInfo {
    FromSet1(usize),
    FromSet2(usize),
}

impl ExternalOpeningInfo {
    /// Returns the expected number of openings
    pub fn expected_num_openings(&self) -> usize {
        match self {
            ExternalOpeningInfo::FromSet1(n) => *n,
            ExternalOpeningInfo::FromSet2(n) => *n,
        }
    }
}
