#![expect(deprecated, reason = "these tests exercise legacy migration data")]

use super::super::super::*;
use super::support::*;
use crate::vault::storage::{
    Storage, StorageExt,
    ram::FailingRamStorage,
    test_support::{
        FaultPhase, StorageEntry, StorageEvent, StorageOp, StorageOutcome, assert_same_events,
    },
};

/// A non-epoched legacy FHE key survives when its replacement differs.
#[tokio::test]
async fn non_epoched_fhe_cleanup_rejects_a_mismatched_replacement() {
    let mut storage = FailingRamStorage::new();
    let key_id = request_id("mismatched_non_epoched_fhe_key");
    let data_type = PrivDataType::FheKeyInfo.to_string();
    storage
        .store_bytes(b"legacy-aa", &key_id, &data_type)
        .await
        .unwrap();
    storage
        .store_bytes_at_epoch(b"legacy-bb", &key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
        .await
        .unwrap();
    seed_controls(&mut storage).await;
    storage.clear_events();
    let before = storage.state();

    let error = migrate_fhe_keys_after_0_13_x(&mut storage, KMSType::Threshold)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("does not match"));
    assert_eq!(storage.state(), before);
    assert!(storage.events().is_empty());
}

/// An epoched legacy FHE key survives when the current-epoch copy differs.
#[tokio::test]
async fn epoched_fhe_cleanup_rejects_a_mismatched_replacement() {
    let mut storage = FailingRamStorage::new();
    let key_id = request_id("mismatched_epoched_fhe_key");
    let data_type = PrivDataType::FheKeyInfo.to_string();
    storage
        .store_bytes_at_epoch(b"legacy-aa", &key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
        .await
        .unwrap();
    storage
        .store_bytes_at_epoch(b"legacy-bb", &key_id, &DEFAULT_EPOCH_ID, &data_type)
        .await
        .unwrap();
    seed_controls(&mut storage).await;
    storage.clear_events();
    let before = storage.state();

    let error = remove_old_keys_for_0_13_20(&mut storage, KMSType::Threshold)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("does not match"));
    assert_eq!(storage.state(), before);
    assert!(storage.events().is_empty());
}

/// A pre-existing PRSS target must match before the legacy entry is removed.
#[tokio::test]
async fn combined_prss_migration_rejects_a_mismatched_target() {
    let mut storage = FailingRamStorage::new();
    let data_type = PrivDataType::PrssSetupCombined.to_string();
    store_versioned_at_request_id(
        &mut storage,
        &(*LEGACY_DEFAULT_EPOCH_ID).into(),
        &test_prss(1),
        &data_type,
    )
    .await
    .unwrap();
    store_versioned_at_request_id(
        &mut storage,
        &(*DEFAULT_EPOCH_ID).into(),
        &test_prss(2),
        &data_type,
    )
    .await
    .unwrap();
    seed_controls(&mut storage).await;
    storage.clear_events();
    let before = storage.state();

    let error = migrate_combined_prss_to_0_13_10(&mut storage)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("does not match"));
    assert_eq!(storage.state(), before);
    assert_same_events(
        storage.events(),
        &[StorageEvent::new(
            StorageEntry::new((*DEFAULT_EPOCH_ID).into(), None, data_type),
            StorageOp::Store,
            StorageOutcome::SkippedExisting,
        )],
    );
}

/// A pre-existing context target must match before the legacy context is removed.
#[tokio::test]
async fn context_migration_rejects_a_mismatched_target() {
    let mut storage = FailingRamStorage::new();
    let legacy = test_context(*LEGACY_DEFAULT_MPC_CONTEXT);
    let mut different = test_context(*DEFAULT_MPC_CONTEXT);
    different.mpc_nodes[0].mpc_identity = "different-node".to_string();
    store_versioned_at_request_id(
        &mut storage,
        &(*LEGACY_DEFAULT_MPC_CONTEXT).into(),
        &legacy,
        &PrivDataType::ContextInfo.to_string(),
    )
    .await
    .unwrap();
    store_versioned_at_request_id(
        &mut storage,
        &(*DEFAULT_MPC_CONTEXT).into(),
        &different,
        &PrivDataType::ContextInfo.to_string(),
    )
    .await
    .unwrap();
    seed_controls(&mut storage).await;
    storage.clear_events();
    let before = storage.state();

    let error = migrate_context_before_0_13_10(&mut storage)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("does not match"));
    assert_eq!(storage.state(), before);
    assert_same_events(
        storage.events(),
        &[StorageEvent::new(
            StorageEntry::new(
                (*DEFAULT_MPC_CONTEXT).into(),
                None,
                PrivDataType::ContextInfo.to_string(),
            ),
            StorageOp::Store,
            StorageOutcome::SkippedExisting,
        )],
    );
}

/// A failed PRSS replacement write keeps the legacy copy and permits a complete retry.
#[rstest::rstest]
#[case(FaultPhase::BeforeMutation)]
#[case(FaultPhase::AfterMutation)]
#[tokio::test]
async fn failed_combined_prss_write_is_retryable(#[case] fault_phase: FaultPhase) {
    let mut storage = FailingRamStorage::new();
    let data_type = PrivDataType::PrssSetupCombined.to_string();
    let legacy_entry = StorageEntry::new((*LEGACY_DEFAULT_EPOCH_ID).into(), None, &data_type);
    let target_entry = StorageEntry::new((*DEFAULT_EPOCH_ID).into(), None, &data_type);
    let original_prss = test_prss(1);
    store_versioned_at_request_id(
        &mut storage,
        &legacy_entry.data_id,
        &original_prss,
        &data_type,
    )
    .await
    .unwrap();
    let control_entries = seed_controls(&mut storage).await;
    let before = storage.state();
    storage.clear_events();
    match fault_phase {
        FaultPhase::BeforeMutation => storage.set_fail_store_at(target_entry.clone()),
        FaultPhase::AfterMutation => storage.set_fail_store_after_mutation_at(target_entry.clone()),
    }

    migrate_combined_prss_to_0_13_10(&mut storage)
        .await
        .unwrap_err();

    let after_failure = storage.state();
    assert_eq!(after_failure.get(&legacy_entry), before.get(&legacy_entry));
    for control_entry in &control_entries {
        assert_eq!(after_failure.get(control_entry), before.get(control_entry));
    }
    match fault_phase {
        FaultPhase::BeforeMutation => assert!(!after_failure.contains_key(&target_entry)),
        FaultPhase::AfterMutation => assert!(after_failure.contains_key(&target_entry)),
    }
    let failed_outcome = match fault_phase {
        FaultPhase::BeforeMutation => StorageOutcome::FailedBeforeMutation,
        FaultPhase::AfterMutation => StorageOutcome::FailedAfterMutation,
    };
    assert_same_events(
        storage.events(),
        &[StorageEvent::new(
            target_entry.clone(),
            StorageOp::Store,
            failed_outcome,
        )],
    );
    storage.clear_fail_points();
    storage.clear_events();

    migrate_combined_prss_to_0_13_10(&mut storage)
        .await
        .unwrap();

    let after_retry = storage.state();
    assert!(!after_retry.contains_key(&legacy_entry));
    let migrated_prss: PRSSSetupCombined =
        read_versioned_at_request_id(&storage, &target_entry.data_id, &data_type)
            .await
            .unwrap();
    assert_eq!(migrated_prss, original_prss);
    for control_entry in &control_entries {
        assert_eq!(after_retry.get(control_entry), before.get(control_entry));
    }
    let retry_store_outcome = match fault_phase {
        FaultPhase::BeforeMutation => StorageOutcome::Created,
        FaultPhase::AfterMutation => StorageOutcome::SkippedExisting,
    };
    assert_same_events(
        storage.events(),
        &[
            StorageEvent::new(target_entry, StorageOp::Store, retry_store_outcome),
            StorageEvent::new(legacy_entry, StorageOp::Delete, StorageOutcome::Deleted),
        ],
    );
}

/// A partially applied legacy-PRSS cleanup is limited to that type and completes on retry.
#[tokio::test]
async fn failed_old_prss_cleanup_is_retryable() {
    let mut storage = FailingRamStorage::new();
    let data_type = PrivDataType::PrssSetupCombined.to_string();
    let first_id = request_id("old_prss_cleanup_first");
    let second_id = request_id("old_prss_cleanup_second");
    for data_id in [first_id, second_id] {
        storage
            .store_bytes(b"legacy PRSS", &data_id, &data_type)
            .await
            .unwrap();
    }
    seed_controls(&mut storage).await;
    let before = storage.state();
    let failed_entry = StorageEntry::new(second_id, None, &data_type);
    storage.set_fail_delete_after_mutation_at(failed_entry.clone());
    storage.clear_events();

    remove_old_prss_data(&mut storage, KMSType::Threshold)
        .await
        .unwrap_err();

    let after_failure = storage.state();
    // Include successful deletes recorded before the failure, then add the required failure event.
    let legacy_entries =
        [first_id, second_id].map(|data_id| StorageEntry::new(data_id, None, &data_type));
    let first_delete = StorageEvent::new(
        legacy_entries[0].clone(),
        StorageOp::Delete,
        StorageOutcome::Deleted,
    );
    let mut expected_events = vec![];
    if storage.events().contains(&first_delete) {
        expected_events.push(first_delete);
    }
    expected_events.push(StorageEvent::new(
        failed_entry.clone(),
        StorageOp::Delete,
        StorageOutcome::FailedAfterMutation,
    ));
    assert_same_events(storage.events(), &expected_events);
    let mut expected_state = before.clone();
    for event in &expected_events {
        expected_state.remove(&event.entry);
    }
    assert_eq!(after_failure, expected_state);
    let mut expected_retry = vec![];
    if after_failure.contains_key(&legacy_entries[0]) {
        expected_retry.push(StorageEvent::new(
            legacy_entries[0].clone(),
            StorageOp::Delete,
            StorageOutcome::Deleted,
        ));
    }
    storage.clear_fail_points();
    storage.clear_events();

    remove_old_prss_data(&mut storage, KMSType::Threshold)
        .await
        .unwrap();

    let after_retry = storage.state();
    assert_same_events(storage.events(), &expected_retry);
    for entry in &legacy_entries {
        expected_state.remove(entry);
    }
    assert_eq!(after_retry, expected_state);
}
