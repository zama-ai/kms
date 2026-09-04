//! Fixtures and assertions for paired public/private storage tests.
//!
//! [`PairFixture`] selects the `PublicKey`/`FheKeyInfo` pair or the `CRS`/`CrsInfo` pair.
//! It seeds the target pair and unrelated controls in separate RAM stores. It also captures the
//! initial state, configures exact store failures, and exposes the final state and storage events.

use super::super::*;
use crate::vault::storage::test_support::{
    FaultPhase, StorageEvent, StorageOp, StorageOutcome, StorageState,
};

/// Which halves of the selected `PublicKey`/`FheKeyInfo` or `CRS`/`CrsInfo` pair exist before
/// `write_all` runs.
#[derive(Clone, Copy, Debug)]
pub(super) enum PairState {
    Empty,
    PublicOnly,
    PrivateOnly,
    Complete,
}

impl PairState {
    // Does this pair of stored items have a public part?
    pub(super) fn has_public(self) -> bool {
        match self {
            Self::Empty | Self::PrivateOnly => false,
            Self::PublicOnly | Self::Complete => true,
        }
    }

    // Does this pair of stored items have a private part?
    pub(super) fn has_private(self) -> bool {
        match self {
            Self::Empty | Self::PublicOnly => false,
            Self::PrivateOnly | Self::Complete => true,
        }
    }
}

/// Selects the FHE-key pair or CRS pair passed to [`CryptoMaterialStorage::write_all`].
#[derive(Clone, Copy, Debug)]
pub(super) enum PairKind {
    FheKey,
    Crs,
}

impl PairKind {
    fn public_type(self) -> PubDataType {
        match self {
            Self::FheKey => PubDataType::PublicKey,
            Self::Crs => PubDataType::CRS,
        }
    }

    fn private_type(self) -> PrivDataType {
        match self {
            Self::FheKey => PrivDataType::FheKeyInfo,
            Self::Crs => PrivDataType::CrsInfo,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::FheKey => Self::Crs,
            Self::Crs => Self::FheKey,
        }
    }

    fn public_entry(self, data_id: RequestId) -> StorageEntry {
        StorageEntry::new(data_id, None, self.public_type().to_string())
    }

    fn private_entry(self, data_id: RequestId, epoch_id: EpochId) -> StorageEntry {
        StorageEntry::new(data_id, Some(epoch_id), self.private_type().to_string())
    }
}

/// Holds one threshold pair, its control entries, and the values used by a `write_all` test.
pub(super) struct PairFixture {
    /// Public and private stores with fault injection and event recording.
    storage: CryptoMaterialStorage<FailingRamStorage, FailingRamStorage>,
    /// Which target entries were seeded before the write.
    pub(super) initial_state: PairState,
    /// Whether the target is the FHE key pair or the CRS pair.
    pair_kind: PairKind,
    /// Request ID shared by the target pair.
    data_id: RequestId,
    /// Epoch used by the private half of the target pair.
    epoch_id: EpochId,
    /// `PublicKey` or `CRS` target used for fault injection and event assertions.
    pub(super) public_entry: StorageEntry,
    /// `FheKeyInfo` or `CrsInfo` target used for fault injection and event assertions.
    pub(super) private_entry: StorageEntry,
    /// Full public state after target and control setup.
    pub(super) public_before: StorageState,
    /// Full private state after target and control setup.
    pub(super) private_before: StorageState,
    /// Value seeded at target paths selected by `initial_state`.
    original: TestType,
    /// Value passed to `write_all` and expected only at entries created by a successful write.
    attempted: TestType,
}

impl PairFixture {
    pub(super) async fn new(initial_state: PairState, pair_kind: PairKind) -> Self {
        let storage =
            CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
        let data_id = derive_request_id("write_all_side_effects_target").unwrap();
        let other_data_id = derive_request_id("write_all_side_effects_other").unwrap();
        let epoch_id: EpochId = derive_request_id("write_all_side_effects_epoch")
            .unwrap()
            .into();
        let other_epoch_id: EpochId = derive_request_id("write_all_side_effects_other_epoch")
            .unwrap()
            .into();
        let original = TestType { i: 1 };
        let control = TestType { i: 99 };

        let public_entry = pair_kind.public_entry(data_id);
        let private_entry = pair_kind.private_entry(data_id, epoch_id);

        // Seed public controls at another ID and at the other pair's public type.
        {
            let mut public = storage.public_storage.lock().await;
            if initial_state.has_public() {
                store_versioned_at_request_id(
                    &mut *public,
                    &data_id,
                    &original,
                    &pair_kind.public_type().to_string(),
                )
                .await
                .unwrap();
            }
            store_versioned_at_request_id(
                &mut *public,
                &other_data_id,
                &control,
                &pair_kind.public_type().to_string(),
            )
            .await
            .unwrap();
            store_versioned_at_request_id(
                &mut *public,
                &data_id,
                &control,
                &pair_kind.other().public_type().to_string(),
            )
            .await
            .unwrap();
            public.clear_events();
        }

        // Seed private controls at another ID, another type, and another epoch.
        {
            let mut private = storage.private_storage.lock().await;
            if initial_state.has_private() {
                store_private(&mut private, &data_id, &epoch_id, pair_kind, &original).await;
            }
            store_private(&mut private, &other_data_id, &epoch_id, pair_kind, &control).await;
            store_versioned_at_request_id(
                &mut *private,
                &data_id,
                &control,
                &PrivDataType::ContextInfo.to_string(),
            )
            .await
            .unwrap();
            store_private(&mut private, &data_id, &other_epoch_id, pair_kind, &control).await;
            private.clear_events();
        }

        let public_before = storage.public_storage.lock().await.state();
        let private_before = storage.private_storage.lock().await.state();

        Self {
            storage,
            initial_state,
            pair_kind,
            data_id,
            epoch_id,
            public_entry,
            private_entry,
            public_before,
            private_before,
            original,
            attempted: TestType { i: 2 },
        }
    }

    pub(super) async fn write_all(&self) -> Result<(), StorageError> {
        self.storage
            .write_all(
                &self.data_id,
                Some(&self.epoch_id),
                Some((&self.attempted, self.pair_kind.public_type())),
                Some((&self.attempted, self.pair_kind.private_type())),
                false,
                TEST_METRIC,
            )
            .await
    }

    pub(super) async fn states(&self) -> (StorageState, StorageState) {
        let public = self.storage.public_storage.lock().await.state();
        let private = self.storage.private_storage.lock().await.state();
        (public, private)
    }

    /// Return the events recorded by the separate public and private stores.
    pub(super) async fn events(&self) -> (Vec<StorageEvent>, Vec<StorageEvent>) {
        let public_events = self.storage.public_storage.lock().await.events().to_vec();
        let private_events = self.storage.private_storage.lock().await.events().to_vec();
        (public_events, private_events)
    }

    pub(super) async fn fail_public_store(&self, phase: FaultPhase) {
        let mut storage = self.storage.public_storage.lock().await;
        match phase {
            FaultPhase::BeforeMutation => storage.set_fail_store_at(self.public_entry.clone()),
            FaultPhase::AfterMutation => {
                storage.set_fail_store_after_mutation_at(self.public_entry.clone())
            }
        }
    }

    pub(super) async fn fail_private_store(&self, phase: FaultPhase) {
        let mut storage = self.storage.private_storage.lock().await;
        match phase {
            FaultPhase::BeforeMutation => storage.set_fail_store_at(self.private_entry.clone()),
            FaultPhase::AfterMutation => {
                storage.set_fail_store_after_mutation_at(self.private_entry.clone())
            }
        }
    }

    /// Assert that `write_all` preserved seeded entries and filled entries that were absent.
    pub(super) async fn assert_target_values(&self) {
        // A seeded half keeps its original value; an absent half receives the attempted value.
        let expected_public = if self.initial_state.has_public() {
            &self.original
        } else {
            &self.attempted
        };
        let expected_private = if self.initial_state.has_private() {
            &self.original
        } else {
            &self.attempted
        };

        let public: TestType = {
            let storage = self.storage.public_storage.lock().await;
            read_versioned_at_request_id(
                &*storage,
                &self.data_id,
                &self.pair_kind.public_type().to_string(),
            )
            .await
            .unwrap()
        };
        let private = {
            let storage = self.storage.private_storage.lock().await;
            read_private(&storage, &self.data_id, &self.epoch_id, self.pair_kind).await
        };

        assert_eq!(&public, expected_public);
        assert_eq!(&private, expected_private);
    }
}

async fn store_private(
    storage: &mut FailingRamStorage,
    data_id: &RequestId,
    epoch_id: &EpochId,
    pair_kind: PairKind,
    data: &TestType,
) {
    store_versioned_at_request_and_epoch_id(
        storage,
        data_id,
        epoch_id,
        data,
        &pair_kind.private_type().to_string(),
    )
    .await
    .unwrap();
}

async fn read_private(
    storage: &FailingRamStorage,
    data_id: &RequestId,
    epoch_id: &EpochId,
    pair_kind: PairKind,
) -> TestType {
    read_versioned_at_request_and_epoch_id(
        storage,
        data_id,
        epoch_id,
        &pair_kind.private_type().to_string(),
    )
    .await
    .unwrap()
}

pub(super) fn assert_preserved(pub_or_priv: &str, before: &StorageState, after: &StorageState) {
    for (entry, digest) in before {
        assert_eq!(
            after.get(entry),
            Some(digest),
            "{pub_or_priv} entry changed: {entry:?}"
        );
    }
}

pub(super) fn expected_store_event(
    entry: &StorageEntry,
    outcome: StorageOutcome,
) -> StorageEvent {
    StorageEvent::new(entry.clone(), StorageOp::Store, outcome)
}

pub(super) fn expected_delete_event(entry: &StorageEntry) -> StorageEvent {
    StorageEvent::new(entry.clone(), StorageOp::Delete, StorageOutcome::Deleted)
}

pub(super) fn failed_store_events(entry: &StorageEntry, phase: FaultPhase) -> Vec<StorageEvent> {
    match phase {
        FaultPhase::BeforeMutation => {
            vec![expected_store_event(
                entry,
                StorageOutcome::FailedBeforeMutation,
            )]
        }
        FaultPhase::AfterMutation => vec![
            expected_store_event(entry, StorageOutcome::FailedAfterMutation),
            expected_delete_event(entry),
        ],
    }
}
