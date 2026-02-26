// TODO(dp): these types come from "core/threshold/execution/runtime/sharing". It sucks a bit to split things into tiny pieces like this
// but the code in `runtime` uses tokio and async-trait which I really don't want here. That said, it's a code smell.
// Maybe it should go into `threshold-types`? Or in a new `role` crate? Dunno.

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
