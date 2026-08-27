use kms_grpc::{RequestId, identifiers::EpochId};
use std::collections::HashMap;

const DSEP_STORAGE_TEST: hashing::DomainSep = *b"STOR_TST";

/// Identify a storage item by its three components: id, epoch and type
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
