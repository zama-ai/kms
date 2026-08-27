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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntryFingerprint {
    byte_length: usize,
    content_digest: [u8; hashing::DIGEST_BYTES],
}

impl EntryFingerprint {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            byte_length: bytes.len(),
            content_digest: hashing::hash_element(&DSEP_STORAGE_TEST, bytes)
                .try_into()
                .expect("SHAKE256 digest must have the configured length"),
        }
    }
}

pub(crate) type StorageState = HashMap<StorageEntry, EntryFingerprint>;

/// The mutating operations exposed by [`super::Storage`]. Stores never overwrite existing data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageOp {
    Store,
    Delete,
}

/// A write or delete that changed storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageMutation {
    pub(crate) entry: StorageEntry,
    pub(crate) operation: StorageOp,
}

impl StorageMutation {
    pub(crate) fn new(entry: StorageEntry, operation: StorageOp) -> Self {
        Self { entry, operation }
    }
}

/// A write or delete that returned an error without changing storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageFault {
    pub(crate) entry: StorageEntry,
    pub(crate) operation: StorageOp,
}

impl StorageFault {
    pub(crate) fn new(entry: StorageEntry, operation: StorageOp) -> Self {
        Self { entry, operation }
    }
}
