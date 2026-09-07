use super::super::*;
use super::support::*;
use crate::vault::storage::test_support::{FaultPhase, StorageOutcome, assert_same_events};

/// Existing pair halves keep their bytes, missing halves are written, and complete pairs are rejected.
#[rstest::rstest]
#[case::empty_fhe_key(PairState::Empty, PairKind::FheKey)]
#[case::public_only_fhe_key(PairState::PublicOnly, PairKind::FheKey)]
#[case::private_only_fhe_key(PairState::PrivateOnly, PairKind::FheKey)]
#[case::complete_fhe_key(PairState::Complete, PairKind::FheKey)]
#[case::empty_crs(PairState::Empty, PairKind::Crs)]
#[case::public_only_crs(PairState::PublicOnly, PairKind::Crs)]
#[case::private_only_crs(PairState::PrivateOnly, PairKind::Crs)]
#[case::complete_crs(PairState::Complete, PairKind::Crs)]
#[tokio::test]
async fn write_all_does_not_overwrite_existing_halves(
    #[case] initial_state: PairState,
    #[case] pair_kind: PairKind,
) {
    let fixture = PairFixture::new(initial_state, pair_kind).await;

    let result = fixture.write_all().await;

    match fixture.initial_state {
        PairState::Complete => assert_eq!(result, Err(StorageError::Duplicate)),
        PairState::Empty | PairState::PublicOnly | PairState::PrivateOnly => {
            assert_eq!(result, Ok(()));
        }
    }

    let (public_after, private_after) = fixture.states().await;
    assert_preserved("public", &fixture.public_before, &public_after);
    assert_preserved("private", &fixture.private_before, &private_after);
    assert_eq!(
        public_after.len(),
        fixture.public_before.len() + usize::from(!fixture.initial_state.has_public())
    );
    assert_eq!(
        private_after.len(),
        fixture.private_before.len() + usize::from(!fixture.initial_state.has_private())
    );
    fixture.assert_target_values().await;

    let expected_public = match fixture.initial_state {
        PairState::Complete => vec![],
        PairState::Empty => vec![expected_store_event(
            &fixture.public_entry,
            StorageOutcome::Created,
        )],
        PairState::PublicOnly => vec![expected_store_event(
            &fixture.public_entry,
            StorageOutcome::SkippedExisting,
        )],
        PairState::PrivateOnly => vec![expected_store_event(
            &fixture.public_entry,
            StorageOutcome::Created,
        )],
    };
    let expected_private = match fixture.initial_state {
        PairState::Complete => vec![],
        PairState::Empty => vec![expected_store_event(
            &fixture.private_entry,
            StorageOutcome::Created,
        )],
        PairState::PublicOnly => vec![expected_store_event(
            &fixture.private_entry,
            StorageOutcome::Created,
        )],
        PairState::PrivateOnly => vec![expected_store_event(
            &fixture.private_entry,
            StorageOutcome::SkippedExisting,
        )],
    };
    let (public_events, private_events) = fixture.events().await;
    assert_same_events(&public_events, &expected_public);
    assert_same_events(&private_events, &expected_private);
}

/// With no existing material, a failed public-half write also rolls back the private half created
/// concurrently.
#[rstest::rstest]
#[case::fhe_key_before(PairKind::FheKey, FaultPhase::BeforeMutation)]
#[case::fhe_key_after(PairKind::FheKey, FaultPhase::AfterMutation)]
#[case::crs_before(PairKind::Crs, FaultPhase::BeforeMutation)]
#[case::crs_after(PairKind::Crs, FaultPhase::AfterMutation)]
#[tokio::test]
async fn empty_pair_remains_empty_when_public_store_fails(
    #[case] pair_kind: PairKind,
    #[case] fault_phase: FaultPhase,
) {
    let fixture = PairFixture::new(PairState::Empty, pair_kind).await;
    fixture.fail_public_store(fault_phase).await;

    assert_eq!(fixture.write_all().await, Err(StorageError::Writing));
    let (public_after, private_after) = fixture.states().await;
    assert_eq!(public_after, fixture.public_before);
    assert_eq!(private_after, fixture.private_before);

    let (public_events, private_events) = fixture.events().await;
    assert_same_events(
        &public_events,
        &failed_store_events(&fixture.public_entry, fault_phase),
    );
    assert_same_events(
        &private_events,
        &[
            expected_store_event(&fixture.private_entry, StorageOutcome::Created),
            expected_delete_event(&fixture.private_entry),
        ],
    );
}

/// With no existing material, a failed private-half write also rolls back the public half created
/// concurrently.
#[rstest::rstest]
#[case::fhe_key_before(PairKind::FheKey, FaultPhase::BeforeMutation)]
#[case::fhe_key_after(PairKind::FheKey, FaultPhase::AfterMutation)]
#[case::crs_before(PairKind::Crs, FaultPhase::BeforeMutation)]
#[case::crs_after(PairKind::Crs, FaultPhase::AfterMutation)]
#[tokio::test]
async fn empty_pair_remains_empty_when_private_store_fails(
    #[case] pair_kind: PairKind,
    #[case] fault_phase: FaultPhase,
) {
    let fixture = PairFixture::new(PairState::Empty, pair_kind).await;
    fixture.fail_private_store(fault_phase).await;

    assert_eq!(fixture.write_all().await, Err(StorageError::Writing));
    let (public_after, private_after) = fixture.states().await;
    assert_eq!(public_after, fixture.public_before);
    assert_eq!(private_after, fixture.private_before);

    let (public_events, private_events) = fixture.events().await;
    assert_same_events(
        &public_events,
        &[
            expected_store_event(&fixture.public_entry, StorageOutcome::Created),
            expected_delete_event(&fixture.public_entry),
        ],
    );
    assert_same_events(
        &private_events,
        &failed_store_events(&fixture.private_entry, fault_phase),
    );
}

/// With only the public half present, a failed private-half write leaves the existing public
/// material untouched.
#[rstest::rstest]
#[case::fhe_key_before(PairKind::FheKey, FaultPhase::BeforeMutation)]
#[case::fhe_key_after(PairKind::FheKey, FaultPhase::AfterMutation)]
#[case::crs_before(PairKind::Crs, FaultPhase::BeforeMutation)]
#[case::crs_after(PairKind::Crs, FaultPhase::AfterMutation)]
#[tokio::test]
async fn existing_public_half_survives_private_store_failure(
    #[case] pair_kind: PairKind,
    #[case] fault_phase: FaultPhase,
) {
    let fixture = PairFixture::new(PairState::PublicOnly, pair_kind).await;
    fixture.fail_private_store(fault_phase).await;

    assert_eq!(fixture.write_all().await, Err(StorageError::Writing));
    let (public_after, private_after) = fixture.states().await;
    assert_eq!(public_after, fixture.public_before);
    assert_eq!(private_after, fixture.private_before);

    let (public_events, private_events) = fixture.events().await;
    assert_same_events(
        &public_events,
        &[expected_store_event(
            &fixture.public_entry,
            StorageOutcome::SkippedExisting,
        )],
    );
    assert_same_events(
        &private_events,
        &failed_store_events(&fixture.private_entry, fault_phase),
    );
}

/// With only the private half present, a failed public-half write leaves the existing private
/// material untouched.
#[rstest::rstest]
#[case::fhe_key_before(PairKind::FheKey, FaultPhase::BeforeMutation)]
#[case::fhe_key_after(PairKind::FheKey, FaultPhase::AfterMutation)]
#[case::crs_before(PairKind::Crs, FaultPhase::BeforeMutation)]
#[case::crs_after(PairKind::Crs, FaultPhase::AfterMutation)]
#[tokio::test]
async fn existing_private_half_survives_public_store_failure(
    #[case] pair_kind: PairKind,
    #[case] fault_phase: FaultPhase,
) {
    let fixture = PairFixture::new(PairState::PrivateOnly, pair_kind).await;
    fixture.fail_public_store(fault_phase).await;

    assert_eq!(fixture.write_all().await, Err(StorageError::Writing));
    let (public_after, private_after) = fixture.states().await;
    assert_eq!(public_after, fixture.public_before);
    assert_eq!(private_after, fixture.private_before);

    let (public_events, private_events) = fixture.events().await;
    assert_same_events(
        &public_events,
        &failed_store_events(&fixture.public_entry, fault_phase),
    );
    assert_same_events(
        &private_events,
        &[expected_store_event(
            &fixture.private_entry,
            StorageOutcome::SkippedExisting,
        )],
    );
}

/// A rejected store of the existing public half rolls back the private half created during the
/// same `write_all` call.
#[rstest::rstest]
#[case::fhe_key(PairKind::FheKey)]
#[case::crs(PairKind::Crs)]
#[tokio::test]
async fn new_private_half_is_removed_when_existing_public_store_fails(#[case] pair_kind: PairKind) {
    let fixture = PairFixture::new(PairState::PublicOnly, pair_kind).await;
    fixture.fail_public_store(FaultPhase::BeforeMutation).await;

    assert_eq!(fixture.write_all().await, Err(StorageError::Writing));
    let (public_after, private_after) = fixture.states().await;
    assert_eq!(public_after, fixture.public_before);
    assert_eq!(private_after, fixture.private_before);

    let (public_events, private_events) = fixture.events().await;
    assert_same_events(
        &public_events,
        &[expected_store_event(
            &fixture.public_entry,
            StorageOutcome::FailedBeforeMutation,
        )],
    );
    assert_same_events(
        &private_events,
        &[
            expected_store_event(&fixture.private_entry, StorageOutcome::Created),
            expected_delete_event(&fixture.private_entry),
        ],
    );
}

/// A rejected store of the existing private half rolls back the public half created during the
/// same `write_all` call.
#[rstest::rstest]
#[case::fhe_key(PairKind::FheKey)]
#[case::crs(PairKind::Crs)]
#[tokio::test]
async fn new_public_half_is_removed_when_existing_private_store_fails(#[case] pair_kind: PairKind) {
    let fixture = PairFixture::new(PairState::PrivateOnly, pair_kind).await;
    fixture.fail_private_store(FaultPhase::BeforeMutation).await;

    assert_eq!(fixture.write_all().await, Err(StorageError::Writing));
    let (public_after, private_after) = fixture.states().await;
    assert_eq!(public_after, fixture.public_before);
    assert_eq!(private_after, fixture.private_before);

    let (public_events, private_events) = fixture.events().await;
    assert_same_events(
        &public_events,
        &[
            expected_store_event(&fixture.public_entry, StorageOutcome::Created),
            expected_delete_event(&fixture.public_entry),
        ],
    );
    assert_same_events(
        &private_events,
        &[expected_store_event(
            &fixture.private_entry,
            StorageOutcome::FailedBeforeMutation,
        )],
    );
}

/// A failed one-sided `ContextInfo` write leaves no request-scoped private entry behind.
#[rstest::rstest]
#[case::before_mutation(FaultPhase::BeforeMutation)]
#[case::after_mutation(FaultPhase::AfterMutation)]
#[tokio::test]
async fn failed_context_info_store_restores_private_storage(#[case] fault_phase: FaultPhase) {
    let data_id = derive_request_id("context_info_side_effects").unwrap();
    let control_id = derive_request_id("context_info_side_effects_control").unwrap();
    let context_entry = StorageEntry::new(data_id, None, PrivDataType::ContextInfo.to_string());
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);

    let private_before = {
        let mut private = storage.private_storage.lock().await;
        store_versioned_at_request_id(
            &mut *private,
            &control_id,
            &TestType { i: 99 },
            &PrivDataType::ContextInfo.to_string(),
        )
        .await
        .unwrap();
        private.clear_events();
        match fault_phase {
            FaultPhase::BeforeMutation => private.set_fail_store_at(context_entry.clone()),
            FaultPhase::AfterMutation => {
                private.set_fail_store_after_mutation_at(context_entry.clone());
            }
        }
        private.state()
    };

    let attempted = TestType { i: 2 };
    let result = storage
        .write_all::<TestType, TestType>(
            &data_id,
            None,
            None,
            Some((&attempted, PrivDataType::ContextInfo)),
            false,
            TEST_METRIC,
        )
        .await;

    assert_eq!(result, Err(StorageError::Writing));
    assert!(storage.public_storage.lock().await.events().is_empty());
    let private = storage.private_storage.lock().await;
    assert_eq!(private.state(), private_before);
    assert_same_events(
        private.events(),
        &failed_store_events(&context_entry, fault_phase),
    );
}

/// Legacy flat CRS metadata does not block writing metadata for a new epoch.
#[tokio::test]
async fn legacy_crs_info_does_not_block_an_epoch_write() {
    let data_id = derive_request_id("legacy_crs_info_epoch_write").unwrap();
    let epoch_id: EpochId = derive_request_id("legacy_crs_info_epoch").unwrap().into();
    let data_type = PrivDataType::CrsInfo.to_string();
    let legacy = TestType { i: 1 };
    let attempted = TestType { i: 2 };
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
    {
        let mut private = storage.private_storage.lock().await;
        store_versioned_at_request_id(&mut *private, &data_id, &legacy, &data_type)
            .await
            .unwrap();
        private.clear_events();
    }

    let result = storage
        .write_all::<TestType, TestType>(
            &data_id,
            Some(&epoch_id),
            None,
            Some((&attempted, PrivDataType::CrsInfo)),
            false,
            TEST_METRIC,
        )
        .await;

    assert_eq!(result, Ok(()));
    let private = storage.private_storage.lock().await;
    let stored_legacy: TestType = read_versioned_at_request_id(&*private, &data_id, &data_type)
        .await
        .unwrap();
    let stored_at_epoch: TestType =
        read_versioned_at_request_and_epoch_id(&*private, &data_id, &epoch_id, &data_type)
            .await
            .unwrap();
    assert_eq!(stored_legacy, legacy);
    assert_eq!(stored_at_epoch, attempted);
    assert_same_events(
        private.events(),
        &[expected_store_event(
            &StorageEntry::new(data_id, Some(epoch_id), data_type),
            StorageOutcome::Created,
        )],
    );
}

/// A flat CRS metadata write still rejects an entry already stored at that path.
#[tokio::test]
async fn flat_crs_info_write_rejects_a_duplicate() {
    let data_id = derive_request_id("duplicate_flat_crs_info").unwrap();
    let data_type = PrivDataType::CrsInfo.to_string();
    let existing = TestType { i: 1 };
    let storage =
        CryptoMaterialStorage::from(FailingRamStorage::new(), FailingRamStorage::new(), None);
    {
        let mut private = storage.private_storage.lock().await;
        store_versioned_at_request_id(&mut *private, &data_id, &existing, &data_type)
            .await
            .unwrap();
        private.clear_events();
    }

    let result = storage
        .write_all::<TestType, TestType>(
            &data_id,
            None,
            None,
            Some((&TestType { i: 2 }, PrivDataType::CrsInfo)),
            false,
            TEST_METRIC,
        )
        .await;

    assert_eq!(result, Err(StorageError::Duplicate));
    let private = storage.private_storage.lock().await;
    let stored: TestType = read_versioned_at_request_id(&*private, &data_id, &data_type)
        .await
        .unwrap();
    assert_eq!(stored, existing);
    assert!(private.events().is_empty());
}
