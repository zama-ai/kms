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

/// A conflicting epoch-scoped CRS entry halts migration without changing either copy.
#[tokio::test]
async fn crs_migration_rejects_a_mismatched_target() {
    let mut fixture =
        CrsMigrationFixture::new("mismatched_crs_target", Some(b"legacy CRS metadatb")).await;

    let error = migrate_crs_to_0_15_x(&mut fixture.storage)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("does not match"));
    assert_eq!(fixture.storage.state(), fixture.before);
    assert_same_events(
        fixture.storage.events(),
        &[StorageEvent::new(
            fixture.target_entry.clone(),
            StorageOp::Store,
            StorageOutcome::SkippedExisting,
        )],
    );
    fixture.assert_controls_unchanged();
}

/// A failure after migrating one CRS leaves partial progress that a retry can finish.
#[tokio::test]
async fn partially_completed_crs_migration_is_retryable() {
    let mut storage = FailingRamStorage::new();
    let data_type = PrivDataType::CrsInfo.to_string();
    let mut crs_ids = [
        request_id("partial_crs_migration_first"),
        request_id("partial_crs_migration_second"),
    ];
    crs_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let [first_id, second_id] = crs_ids;
    for crs_id in crs_ids {
        storage
            .store_bytes(LEGACY_CRS_DATA, &crs_id, &data_type)
            .await
            .unwrap();
    }
    let control_entries = seed_controls(&mut storage).await;
    let before = storage.state();
    let first_legacy = StorageEntry::new(first_id, None, &data_type);
    let first_target = StorageEntry::new(first_id, Some(*DEFAULT_EPOCH_ID), &data_type);
    let second_legacy = StorageEntry::new(second_id, None, &data_type);
    let second_target = StorageEntry::new(second_id, Some(*DEFAULT_EPOCH_ID), &data_type);
    storage.set_fail_store_at(second_target.clone());
    storage.clear_events();

    migrate_crs_to_0_15_x(&mut storage).await.unwrap_err();

    let after_failure = storage.state();
    assert!(!after_failure.contains_key(&first_legacy));
    assert!(after_failure.contains_key(&first_target));
    assert!(after_failure.contains_key(&second_legacy));
    assert!(!after_failure.contains_key(&second_target));
    for control_entry in &control_entries {
        assert_eq!(after_failure.get(control_entry), before.get(control_entry));
    }

    storage.clear_fail_points();
    migrate_crs_to_0_15_x(&mut storage).await.unwrap();

    let after_retry = storage.state();
    assert!(!after_retry.contains_key(&first_legacy));
    assert!(after_retry.contains_key(&first_target));
    assert!(!after_retry.contains_key(&second_legacy));
    assert!(after_retry.contains_key(&second_target));
    for control_entry in &control_entries {
        assert_eq!(after_retry.get(control_entry), before.get(control_entry));
    }
}

/// A failed CRS copy keeps the legacy entry and completes on retry.
#[rstest::rstest]
#[case(FaultPhase::BeforeMutation)]
#[case(FaultPhase::AfterMutation)]
#[tokio::test]
async fn failed_crs_copy_is_retryable(#[case] fault_phase: FaultPhase) {
    let mut fixture = CrsMigrationFixture::new("failed_crs_copy", None).await;
    match fault_phase {
        FaultPhase::BeforeMutation => fixture
            .storage
            .set_fail_store_at(fixture.target_entry.clone()),
        FaultPhase::AfterMutation => fixture
            .storage
            .set_fail_store_after_mutation_at(fixture.target_entry.clone()),
    }

    migrate_crs_to_0_15_x(&mut fixture.storage)
        .await
        .unwrap_err();

    let after_failure = fixture.storage.state();
    assert!(after_failure.contains_key(&fixture.legacy_entry));
    match fault_phase {
        FaultPhase::BeforeMutation => assert!(!after_failure.contains_key(&fixture.target_entry)),
        FaultPhase::AfterMutation => assert!(after_failure.contains_key(&fixture.target_entry)),
    }
    fixture.assert_controls_unchanged();
    let failed_outcome = match fault_phase {
        FaultPhase::BeforeMutation => StorageOutcome::FailedBeforeMutation,
        FaultPhase::AfterMutation => StorageOutcome::FailedAfterMutation,
    };
    assert_same_events(
        fixture.storage.events(),
        &[StorageEvent::new(
            fixture.target_entry.clone(),
            StorageOp::Store,
            failed_outcome,
        )],
    );

    fixture.storage.clear_fail_points();
    fixture.storage.clear_events();
    migrate_crs_to_0_15_x(&mut fixture.storage).await.unwrap();

    let after_retry = fixture.storage.state();
    assert!(!after_retry.contains_key(&fixture.legacy_entry));
    assert!(after_retry.contains_key(&fixture.target_entry));
    fixture.assert_controls_unchanged();
    let retry_store_outcome = match fault_phase {
        FaultPhase::BeforeMutation => StorageOutcome::Created,
        FaultPhase::AfterMutation => StorageOutcome::SkippedExisting,
    };
    assert_same_events(
        fixture.storage.events(),
        &[
            StorageEvent::new(fixture.target_entry, StorageOp::Store, retry_store_outcome),
            StorageEvent::new(
                fixture.legacy_entry,
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ),
        ],
    );
}

/// A failed legacy CRS delete leaves a state that a later startup can finish.
#[rstest::rstest]
#[case(FaultPhase::BeforeMutation)]
#[case(FaultPhase::AfterMutation)]
#[tokio::test]
async fn failed_legacy_crs_delete_is_retryable(#[case] fault_phase: FaultPhase) {
    let mut fixture =
        CrsMigrationFixture::new("failed_legacy_crs_delete", Some(LEGACY_CRS_DATA)).await;
    match fault_phase {
        FaultPhase::BeforeMutation => fixture
            .storage
            .set_fail_delete_at(fixture.legacy_entry.clone()),
        FaultPhase::AfterMutation => fixture
            .storage
            .set_fail_delete_after_mutation_at(fixture.legacy_entry.clone()),
    }

    migrate_crs_to_0_15_x(&mut fixture.storage)
        .await
        .unwrap_err();

    let after_failure = fixture.storage.state();
    assert!(after_failure.contains_key(&fixture.target_entry));
    match fault_phase {
        FaultPhase::BeforeMutation => assert!(after_failure.contains_key(&fixture.legacy_entry)),
        FaultPhase::AfterMutation => assert!(!after_failure.contains_key(&fixture.legacy_entry)),
    }
    fixture.assert_controls_unchanged();
    let failed_outcome = match fault_phase {
        FaultPhase::BeforeMutation => StorageOutcome::FailedBeforeMutation,
        FaultPhase::AfterMutation => StorageOutcome::FailedAfterMutation,
    };
    assert_same_events(
        fixture.storage.events(),
        &[
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Store,
                StorageOutcome::SkippedExisting,
            ),
            StorageEvent::new(
                fixture.legacy_entry.clone(),
                StorageOp::Delete,
                failed_outcome,
            ),
        ],
    );

    fixture.storage.clear_fail_points();
    fixture.storage.clear_events();
    migrate_crs_to_0_15_x(&mut fixture.storage).await.unwrap();

    assert!(!fixture.storage.state().contains_key(&fixture.legacy_entry));
    assert!(fixture.storage.state().contains_key(&fixture.target_entry));
    fixture.assert_controls_unchanged();
    let expected_retry_events = match fault_phase {
        FaultPhase::BeforeMutation => vec![
            StorageEvent::new(
                fixture.target_entry,
                StorageOp::Store,
                StorageOutcome::SkippedExisting,
            ),
            StorageEvent::new(
                fixture.legacy_entry,
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ),
        ],
        FaultPhase::AfterMutation => vec![],
    };
    assert_same_events(fixture.storage.events(), &expected_retry_events);
}

/// Migration rejects a successful delete response when the legacy CRS entry remains.
#[tokio::test]
async fn crs_migration_rejects_a_delete_that_did_not_happen() {
    let mut fixture =
        CrsMigrationFixture::new("ignored_legacy_crs_delete", Some(LEGACY_CRS_DATA)).await;
    fixture
        .storage
        .set_noop_delete_at(fixture.legacy_entry.clone());

    let error = migrate_crs_to_0_15_x(&mut fixture.storage)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("remains after deletion"));
    assert_eq!(fixture.storage.state(), fixture.before);
    fixture.assert_controls_unchanged();
    assert_same_events(
        fixture.storage.events(),
        &[
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Store,
                StorageOutcome::SkippedExisting,
            ),
            StorageEvent::new(
                fixture.legacy_entry.clone(),
                StorageOp::Delete,
                StorageOutcome::SucceededWithoutMutation,
            ),
        ],
    );

    fixture.storage.clear_fail_points();
    fixture.storage.clear_events();
    migrate_crs_to_0_15_x(&mut fixture.storage).await.unwrap();

    assert!(!fixture.storage.state().contains_key(&fixture.legacy_entry));
    assert!(fixture.storage.state().contains_key(&fixture.target_entry));
    fixture.assert_controls_unchanged();
}
