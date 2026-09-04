use kms_grpc::{RequestId, identifiers::EpochId};
use std::collections::HashMap;

const DSEP_STORAGE_TEST: hashing::DomainSep = *b"STOR_TST";

/// Identifies one stored item using the components of its path on disk.
///
/// Tests use these coordinates to configure fault points and describe expected storage events.
///
/// The containing storage supplies the `PUB` or `PRIV` root. The entry itself contains the remaining path parts. The
/// writes covered by these tests use:
///
/// - `PUB/PublicKey/ae0…037` maps to `StorageEntry(ae0…037, None, "PublicKey")`.
/// - `PRIV/FheKeyInfo/080…001/ae0…037` maps to `StorageEntry(ae0…037, Some(080…001), "FheKeyInfo")`.
/// - `PUB/CRS/b91…30f` maps to `StorageEntry(b91…30f, None, "CRS")`.
/// - `PRIV/CrsInfo/080…001/b91…30f` maps to `StorageEntry(b91…30f, Some(080…001), "CrsInfo")`.
///
/// In these pairs, the public half has no epoch and is shared across epochs. Each private half belongs to one epoch.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct StorageEntry {
    pub(crate) data_id: RequestId,
    pub(crate) epoch_id: Option<EpochId>,
    pub(crate) data_type: String,
}

impl StorageEntry {
    pub(crate) fn new(
        data_id: RequestId,
        epoch_id: Option<EpochId>,
        data_type: impl Into<String>,
    ) -> Self {
        Self {
            data_id,
            epoch_id,
            data_type: data_type.into(),
        }
    }
}

pub(crate) type EntryDigest = [u8; hashing::DIGEST_BYTES];

pub(crate) fn digest_entry(bytes: &[u8]) -> EntryDigest {
    hashing::hash_element(&DSEP_STORAGE_TEST, bytes)
        .try_into()
        .expect("SHAKE256 digest must have the configured length")
}

pub(crate) type StorageState = HashMap<StorageEntry, EntryDigest>;

/// The mutating operations exposed by [`super::Storage`]. Stores never overwrite existing data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum StorageOp {
    Store,
    Delete,
}

/// When an injected fault fires, relative to the mutation it guards.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultPhase {
    /// Reject the operation without touching the wrapped storage.
    BeforeMutation,
    /// Let the wrapped storage apply the change, then return an error. This models an
    /// ambiguous result from a remote backend, where the caller cannot tell whether its
    /// write or delete took effect.
    AfterMutation,
}

/// What a storage operation did to the entry it named.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum StorageOutcome {
    /// A store wrote new data.
    Created,
    /// A store found existing data and kept it.
    SkippedExisting,
    /// A delete removed data.
    Deleted,
    /// The operation returned an error without changing storage.
    FailedBeforeMutation,
    /// The operation changed storage and then returned an error.
    FailedAfterMutation,
}

#[allow(dead_code, reason = "used in the next stacked PR")]
impl StorageOutcome {
    /// Whether the operation left the stored bytes different from how it found them.
    pub(crate) fn changed_storage(&self) -> bool {
        matches!(
            self,
            Self::Created | Self::Deleted | Self::FailedAfterMutation
        )
    }

    /// Whether the operation returned an error, whatever it did to storage.
    pub(crate) fn failed(&self) -> bool {
        matches!(self, Self::FailedBeforeMutation | Self::FailedAfterMutation)
    }
}

/// A single store or delete, with the entry it named and what it did.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct StorageEvent {
    pub(crate) entry: StorageEntry,
    pub(crate) operation: StorageOp,
    pub(crate) outcome: StorageOutcome,
}

impl StorageEvent {
    pub(crate) fn new(entry: StorageEntry, operation: StorageOp, outcome: StorageOutcome) -> Self {
        Self {
            entry,
            operation,
            outcome,
        }
    }
}

/// Assert that two event slices contain the same events, including duplicates, in any order.
pub(crate) fn assert_same_events(actual: &[StorageEvent], expected: &[StorageEvent]) {
    assert_eq!(
        event_counts(actual),
        event_counts(expected),
        "actual events: {actual:#?}"
    );
}

fn event_counts(events: &[StorageEvent]) -> HashMap<StorageEvent, usize> {
    let mut counts = HashMap::new();
    for event in events {
        *counts.entry(event.clone()).or_default() += 1;
    }
    counts
}
