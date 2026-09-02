use super::RamStorage;
use crate::vault::storage::{
    Storage, StorageExt, StorageReader, StorageReaderExt, StoreWriteOutcome,
    test_support::{
        FaultPhase, StorageEntry, StorageEvent, StorageOp, StorageOutcome, StorageState,
        digest_entry,
    },
};
use kms_grpc::{RequestId, identifiers::EpochId};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashSet;
use tfhe::{Unversionize, Versionize, named::Named};

/// Test-only [`RamStorage`] wrapper with entry-specific fault injection and side-effect recording.
///
/// Each [`StorageEntry`] identifies the same data type, request ID, and optional epoch that form a
/// path in file-backed storage. The wrapper keeps those entries in RAM so tests can fail one exact
/// path and compare the complete state before and after the operation.
///
/// Store and delete fail points name the exact storage entry to reject, and choose whether the
/// error arrives before or after the wrapped storage applies the change. Both can be active at
/// the same time and remain active until replaced or cleared. Every store and delete appends a
/// [`StorageEvent`], and [`Self::state`] snapshots the stored entries. Reads pass through to the
/// wrapped storage and are not recorded.
#[derive(Default)]
pub struct FailingRamStorage {
    fail_store_at: Option<(StorageEntry, FaultPhase)>,
    fail_delete_at: Option<(StorageEntry, FaultPhase)>,
    events: Vec<StorageEvent>,
    inner: RamStorage,
}

impl FailingRamStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reject the store of `entry` without touching the wrapped storage.
    pub(crate) fn set_fail_store_at(&mut self, entry: StorageEntry) {
        self.fail_store_at = Some((entry, FaultPhase::BeforeMutation));
    }

    /// Write `entry` to the wrapped storage and then return an error.
    pub(crate) fn set_fail_store_after_mutation_at(&mut self, entry: StorageEntry) {
        self.fail_store_at = Some((entry, FaultPhase::AfterMutation));
    }

    /// Reject the delete of `entry` without touching the wrapped storage.
    pub(crate) fn set_fail_delete_at(&mut self, entry: StorageEntry) {
        self.fail_delete_at = Some((entry, FaultPhase::BeforeMutation));
    }

    /// Remove `entry` from the wrapped storage and then return an error.
    #[allow(dead_code, reason = "used in the next stacked PR")]
    pub(crate) fn set_fail_delete_after_mutation_at(&mut self, entry: StorageEntry) {
        self.fail_delete_at = Some((entry, FaultPhase::AfterMutation));
    }

    pub(crate) fn clear_fail_points(&mut self) {
        self.fail_store_at = None;
        self.fail_delete_at = None;
    }

    pub(crate) fn clear_events(&mut self) {
        self.events.clear();
    }

    /// Every recorded store and delete, in the order the wrapper saw them.
    pub(crate) fn events(&self) -> &[StorageEvent] {
        &self.events
    }

    /// The events that changed stored data, including those that mutated and then failed.
    #[allow(dead_code, reason = "used in the next stacked PR")]
    pub(crate) fn mutations(&self) -> Vec<&StorageEvent> {
        self.events
            .iter()
            .filter(|event| event.outcome.changed_storage())
            .collect()
    }

    /// The events that returned an error, whatever they did to storage.
    #[allow(dead_code, reason = "used in the next stacked PR")]
    pub(crate) fn faults(&self) -> Vec<&StorageEvent> {
        self.events
            .iter()
            .filter(|event| event.outcome.failed())
            .collect()
    }

    pub(crate) fn state(&self) -> StorageState {
        self.inner
            .internal_storage
            .iter()
            .map(|(((data_id, epoch_id), data_type), bytes)| {
                (
                    StorageEntry::new(*data_id, *epoch_id, data_type),
                    digest_entry(bytes),
                )
            })
            .collect()
    }

    fn matches_fail_point(
        &self,
        (op, phase): (StorageOp, FaultPhase),
        entry: &StorageEntry,
    ) -> bool {
        let fail_point = match op {
            StorageOp::Store => &self.fail_store_at,
            StorageOp::Delete => &self.fail_delete_at,
        };
        matches!(
            fail_point,
            Some((target, target_phase)) if target == entry && *target_phase == phase
        )
    }

    fn record_store_result(
        &mut self,
        entry: StorageEntry,
        result: anyhow::Result<StoreWriteOutcome>,
    ) -> anyhow::Result<StoreWriteOutcome> {
        use StorageOp::Store;
        match result {
            Ok(StoreWriteOutcome::Created) => {
                // An after-mutation fault point only applies once the data is in.
                if self.matches_fail_point((Store, FaultPhase::AfterMutation), &entry) {
                    self.record(entry, Store, StorageOutcome::FailedAfterMutation);
                    anyhow::bail!("storage failed after writing the data!")
                }
                self.record(entry, Store, StorageOutcome::Created);
                Ok(StoreWriteOutcome::Created)
            }
            Ok(StoreWriteOutcome::SkippedExisting) => {
                self.record(entry, Store, StorageOutcome::SkippedExisting);
                Ok(StoreWriteOutcome::SkippedExisting)
            }
            Err(error) => {
                self.record(entry, Store, StorageOutcome::FailedBeforeMutation);
                Err(error)
            }
        }
    }

    fn record_delete_result(
        &mut self,
        entry: StorageEntry,
        result: anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        use StorageOp::Delete;
        match result {
            Ok(()) => {
                if self.matches_fail_point((Delete, FaultPhase::AfterMutation), &entry) {
                    self.record(entry, Delete, StorageOutcome::FailedAfterMutation);
                    anyhow::bail!("storage delete failed after removing the data!")
                }
                self.record(entry, Delete, StorageOutcome::Deleted);
                Ok(())
            }
            Err(error) => {
                self.record(entry, Delete, StorageOutcome::FailedBeforeMutation);
                Err(error)
            }
        }
    }

    fn record(&mut self, entry: StorageEntry, operation: StorageOp, outcome: StorageOutcome) {
        self.events
            .push(StorageEvent::new(entry, operation, outcome));
    }
}

impl StorageReader for FailingRamStorage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        self.inner.data_exists(data_id, data_type).await
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        self.inner.read_data(data_id, data_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        self.inner.load_bytes(data_id, data_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids(data_type).await
    }

    fn info(&self) -> String {
        "FailingRamStorage".to_string()
    }
}

impl Storage for FailingRamStorage {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, None, data_type);
        if self.matches_fail_point((StorageOp::Store, FaultPhase::BeforeMutation), &entry) {
            self.record(
                entry,
                StorageOp::Store,
                StorageOutcome::FailedBeforeMutation,
            );
            anyhow::bail!("storage failed!")
        }
        let result = self.inner.store_data(data, data_id, data_type).await;
        self.record_store_result(entry, result)
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, None, data_type);
        if self.matches_fail_point((StorageOp::Store, FaultPhase::BeforeMutation), &entry) {
            self.record(
                entry,
                StorageOp::Store,
                StorageOutcome::FailedBeforeMutation,
            );
            anyhow::bail!("storage failed!")
        }
        let result = self.inner.store_bytes(bytes, data_id, data_type).await;
        self.record_store_result(entry, result)
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let entry = StorageEntry::new(*data_id, None, data_type);
        if self.matches_fail_point((StorageOp::Delete, FaultPhase::BeforeMutation), &entry) {
            self.record(
                entry,
                StorageOp::Delete,
                StorageOutcome::FailedBeforeMutation,
            );
            anyhow::bail!("storage delete failed!")
        }
        let result = self.inner.delete_data(data_id, data_type).await;
        self.record_delete_result(entry, result)
    }
}

impl StorageReaderExt for FailingRamStorage {
    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        self.inner
            .read_data_at_epoch(data_id, epoch_id, data_type)
            .await
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        self.inner.all_epoch_ids_for_data(data_type).await
    }

    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool> {
        self.inner
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await
    }

    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids_at_epoch(epoch_id, data_type).await
    }

    async fn all_data_ids_from_all_epochs(
        &self,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids_from_all_epochs(data_type).await
    }

    async fn load_bytes_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<Vec<u8>> {
        self.inner
            .load_bytes_at_epoch(data_id, epoch_id, data_type)
            .await
    }
}

impl StorageExt for FailingRamStorage {
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, Some(*epoch_id), data_type);
        if self.matches_fail_point((StorageOp::Store, FaultPhase::BeforeMutation), &entry) {
            self.record(
                entry,
                StorageOp::Store,
                StorageOutcome::FailedBeforeMutation,
            );
            anyhow::bail!("storage failed!")
        }
        let result = self
            .inner
            .store_data_at_epoch(data, data_id, epoch_id, data_type)
            .await;
        self.record_store_result(entry, result)
    }

    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, Some(*epoch_id), data_type);
        if self.matches_fail_point((StorageOp::Store, FaultPhase::BeforeMutation), &entry) {
            self.record(
                entry,
                StorageOp::Store,
                StorageOutcome::FailedBeforeMutation,
            );
            anyhow::bail!("storage failed!")
        }
        let result = self
            .inner
            .store_bytes_at_epoch(bytes, data_id, epoch_id, data_type)
            .await;
        self.record_store_result(entry, result)
    }

    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let entry = StorageEntry::new(*data_id, Some(*epoch_id), data_type);
        if self.matches_fail_point((StorageOp::Delete, FaultPhase::BeforeMutation), &entry) {
            self.record(
                entry,
                StorageOp::Delete,
                StorageOutcome::FailedBeforeMutation,
            );
            anyhow::bail!("storage delete failed!")
        }
        let result = self
            .inner
            .delete_data_at_epoch(data_id, epoch_id, data_type)
            .await;
        self.record_delete_result(entry, result)
    }
}
