#![expect(deprecated, reason = "these tests exercise legacy migration data")]

use super::super::super::*;
use super::support::*;
use crate::vault::storage::{
    Storage, StorageExt, StorageReader,
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
        .store_bytes(b"legacy", &key_id, &data_type)
        .await
        .unwrap();
    storage
        .store_bytes_at_epoch(b"different", &key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
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
        .store_bytes_at_epoch(b"legacy", &key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
        .await
        .unwrap();
    storage
        .store_bytes_at_epoch(b"different", &key_id, &DEFAULT_EPOCH_ID, &data_type)
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
    store_versioned_at_request_id(
        &mut storage,
        &legacy_entry.data_id,
        &test_prss(1),
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
    assert!(after_retry.contains_key(&target_entry));
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
    let control_entries = seed_controls(&mut storage).await;
    let before = storage.state();
    let failed_entry = StorageEntry::new(second_id, None, &data_type);
    storage.set_fail_delete_after_mutation_at(failed_entry.clone());
    storage.clear_events();

    remove_old_prss_data(&mut storage, KMSType::Threshold)
        .await
        .unwrap_err();

    assert!(!storage.state().contains_key(&failed_entry));
    let after_failure = storage.state();
    for control_entry in &control_entries {
        assert_eq!(after_failure.get(control_entry), before.get(control_entry));
    }
    // Storage does not promise an order for the two IDs, so assert the event scope and the
    // required failed delete instead of an exact sequence.
    assert!(
        storage
            .events()
            .iter()
            .all(|event| event.entry.data_type == data_type)
    );
    assert!(storage.events().contains(&StorageEvent::new(
        failed_entry,
        StorageOp::Delete,
        StorageOutcome::FailedAfterMutation,
    )));
    storage.clear_fail_points();

    remove_old_prss_data(&mut storage, KMSType::Threshold)
        .await
        .unwrap();

    assert!(storage.all_data_ids(&data_type).await.unwrap().is_empty());
    let after_retry = storage.state();
    for control_entry in &control_entries {
        assert_eq!(after_retry.get(control_entry), before.get(control_entry));
    }
}
