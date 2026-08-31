use crate::vault::storage::{StorageProxy, ram::FailingRamStorage};
use crate::vault::{Vault, VaultDataType};
use kms_grpc::{RequestId, identifiers::EpochId, rpc_types::PrivDataType};
use std::collections::HashMap;

const DSEP_STORAGE_TEST: hashing::DomainSep = *b"STOR_TST";

/// Identifies one stored item using the components of its path on disk.
///
/// The containing storage supplies the `PUB` or `PRIV` root. The entry itself contains the
/// remaining path parts. The paired threshold writes covered by these tests use:
///
/// Examples:
/// - `testing/PUB/PublicKey/ae0…037` maps to `StorageEntry(ae0…037, None, "PublicKey")`.
/// - `testing/PRIV/FheKeyInfo/080…001/ae0…037` maps to `StorageEntry(ae0…037, Some(080…001), "FheKeyInfo")`.
/// - `testing/PUB/CRS/b91…30f` maps to `StorageEntry(b91…30f, None, "CRS")`.
/// - `testing/PRIV/CrsInfo/080…001/b91…30f` maps to `StorageEntry(b91…30f, Some(080…001), "CrsInfo")`.
///
/// Public halves have no epoch (is used for every epoch). Each private half has an epoch and contains the party's
/// material for that epoch.
///
/// Tests use these coordinates to configure fault points and describe expected storage events.
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

/// Identifies one private backup item before the vault maps it to a backend data type.
///
/// For example, `testing/BACKUP/<backup>/FheKeyInfo/<epoch>/<data>` retains each path component
/// here. [`Self::storage_entry`] maps the backup ID and private type to one backend type string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BackupEntry {
    /// Custodian context that owns the backup namespace.
    pub(crate) backup_id: RequestId,
    /// Request ID of the backed-up private item.
    pub(crate) data_id: RequestId,
    /// Epoch of the private item, when its type uses epoch storage.
    pub(crate) epoch_id: Option<EpochId>,
    /// Source private type before the vault maps it to a backup namespace.
    pub(crate) data_type: PrivDataType,
}

impl BackupEntry {
    /// Creates a structured private backup coordinate.
    pub(crate) fn new(
        backup_id: RequestId,
        data_id: RequestId,
        epoch_id: Option<EpochId>,
        data_type: PrivDataType,
    ) -> Self {
        Self {
            backup_id,
            data_id,
            epoch_id,
            data_type,
        }
    }

    /// Maps the backup coordinate to the flattened path components received by a backend.
    pub(crate) fn storage_entry(self) -> StorageEntry {
        StorageEntry::new(
            self.data_id,
            self.epoch_id,
            VaultDataType::CustodianBackupData(self.backup_id, self.data_type).to_string(),
        )
    }
}

/// Returns the fault-injecting RAM backend inside `vault`.
pub(crate) fn failing_ram_storage(vault: &Vault) -> &FailingRamStorage {
    match &vault.storage {
        StorageProxy::FailingRam(storage) => storage,
        _ => panic!("expected a fault-injecting RAM backup vault"),
    }
}

/// Returns the mutable fault-injecting RAM backend inside `vault`.
pub(crate) fn failing_ram_storage_mut(vault: &mut Vault) -> &mut FailingRamStorage {
    match &mut vault.storage {
        StorageProxy::FailingRam(storage) => storage,
        _ => panic!("expected a fault-injecting RAM backup vault"),
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

/// Assert that two event slices contain the same events, including duplicates, in any order.
pub(crate) fn assert_same_events(actual: &[StorageEvent], expected: &[StorageEvent]) {
    fn counts(events: &[StorageEvent]) -> HashMap<StorageEvent, usize> {
        let mut counts = HashMap::new();
        for event in events {
            *counts.entry(event.clone()).or_default() += 1;
        }
        counts
    }

    assert_eq!(
        counts(actual),
        counts(expected),
        "actual events: {actual:#?}"
    );
}
