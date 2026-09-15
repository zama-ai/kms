use super::super::DUMMY_SIGNING_KEY_REQ_ID;
use super::support::*;
use crate::consts::DEFAULT_MPC_CONTEXT;
use crate::engine::traits::ContextManager;
use crate::vault::storage::test_support::{
    BackupEntry, FaultPhase, StorageEntry, StorageEvent, StorageOp, StorageOutcome,
    assert_same_events,
};
use kms_grpc::{
    RequestId,
    rpc_types::{PrivDataType, PubDataType},
};

/// A failed backup erasure keeps lifecycle state and permits a complete retry.
#[rstest::rstest]
#[case(FaultPhase::BeforeMutation, StorageOutcome::FailedBeforeMutation)]
#[case(FaultPhase::AfterMutation, StorageOutcome::FailedAfterMutation)]
#[tokio::test]
async fn failed_backup_erasure_is_retryable(
    #[case] fault_phase: FaultPhase,
    #[case] expected_outcome: StorageOutcome,
) {
    let fixture = CustodianFixture::new().await;
    fixture.fail_backup_delete(fault_phase).await;
    let permitted_deletes = fixture.expected_backup_deletes(fixture.retired_id).await;
    let mut expected_final_state = fixture.backup_state().await;
    for event in &permitted_deletes {
        expected_final_state.remove(&event.entry);
    }

    let error = fixture.destroy(fixture.retired_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(fixture.recovery_exists(fixture.retired_id).await);
    assert!(fixture.context_is_complete(fixture.retired_id).await);
    assert!(fixture.public_events().await.is_empty());
    let backup_events = fixture.backup_events().await;
    // Select permitted successful deletes that actually occurred, then add the one required failure event.
    let mut expected_events: Vec<_> = permitted_deletes
        .into_iter()
        .filter(|event| {
            event.entry != fixture.retired_backup_entry && backup_events.contains(event)
        })
        .collect();
    expected_events.push(StorageEvent::new(
        fixture.retired_backup_entry.clone(),
        StorageOp::Delete,
        expected_outcome,
    ));
    assert_same_events(&backup_events, &expected_events);

    let expected_retry = fixture.expected_backup_deletes(fixture.retired_id).await;
    fixture.clear_faults_and_events().await;
    fixture.destroy(fixture.retired_id).await.unwrap();
    assert_same_events(&fixture.backup_events().await, &expected_retry);
    assert_same_events(
        &fixture.public_events().await,
        &[StorageEvent::new(
            fixture.retired_recovery_entry.clone(),
            StorageOp::Delete,
            StorageOutcome::Deleted,
        )],
    );

    assert!(fixture.backup_is_empty(fixture.retired_id).await);
    assert_eq!(fixture.backup_state().await, expected_final_state);
    assert!(!fixture.recovery_exists(fixture.retired_id).await);
    assert!(!fixture.context_is_complete(fixture.retired_id).await);
    assert!(fixture.recovery_exists(fixture.current_id).await);
    assert!(fixture.context_is_complete(fixture.current_id).await);
}

/// A recovery-material delete failure leaves no backup entries and permits a retry.
#[rstest::rstest]
#[case::before_mutation(FaultPhase::BeforeMutation, StorageOutcome::FailedBeforeMutation)]
#[case::after_mutation(FaultPhase::AfterMutation, StorageOutcome::FailedAfterMutation)]
#[tokio::test]
async fn failed_recovery_material_deletion_is_retryable(
    #[case] fault_phase: FaultPhase,
    #[case] expected_outcome: StorageOutcome,
) {
    let fixture = CustodianFixture::new().await;
    fixture.fail_recovery_delete(fault_phase).await;
    let expected_backups = fixture.expected_backup_deletes(fixture.retired_id).await;
    let mut expected_final_state = fixture.backup_state().await;
    for event in &expected_backups {
        expected_final_state.remove(&event.entry);
    }

    let error = fixture.destroy(fixture.retired_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert_same_events(&fixture.backup_events().await, &expected_backups);
    assert_eq!(fixture.backup_state().await, expected_final_state);
    assert!(fixture.backup_is_empty(fixture.retired_id).await);
    match fault_phase {
        FaultPhase::BeforeMutation => assert!(fixture.recovery_exists(fixture.retired_id).await),
        FaultPhase::AfterMutation => assert!(!fixture.recovery_exists(fixture.retired_id).await),
    }
    assert!(fixture.context_is_complete(fixture.retired_id).await);
    assert_same_events(
        &fixture.public_events().await,
        &[StorageEvent::new(
            fixture.retired_recovery_entry.clone(),
            StorageOp::Delete,
            expected_outcome,
        )],
    );

    fixture.clear_faults_and_events().await;
    fixture.destroy(fixture.retired_id).await.unwrap();

    assert!(fixture.backup_events().await.is_empty());
    assert_eq!(fixture.backup_state().await, expected_final_state);
    let expected_retry = match fault_phase {
        FaultPhase::BeforeMutation => vec![StorageEvent::new(
            fixture.retired_recovery_entry.clone(),
            StorageOp::Delete,
            StorageOutcome::Deleted,
        )],
        // The first delete took effect, so only the meta-store entry remains to remove.
        FaultPhase::AfterMutation => vec![],
    };
    assert_same_events(&fixture.public_events().await, &expected_retry);
    assert!(fixture.backup_is_empty(fixture.retired_id).await);
    assert!(!fixture.recovery_exists(fixture.retired_id).await);
    assert!(!fixture.context_is_complete(fixture.retired_id).await);
}

/// Destruction of the only successful context is rejected without a storage operation.
#[tokio::test]
async fn last_custodian_context_destruction_has_no_side_effects() {
    let fixture = CustodianFixture::new().await;
    // Destroy the retired context so the current context is the only successful context left.
    fixture.destroy(fixture.retired_id).await.unwrap();
    fixture.clear_faults_and_events().await;

    let error = fixture.destroy(fixture.current_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());
    assert!(fixture.recovery_exists(fixture.current_id).await);
    assert!(fixture.context_is_complete(fixture.current_id).await);
}

/// Custodian setup waits for the context update lock before it changes storage.
#[tokio::test]
async fn custodian_setup_waits_for_the_context_update_lock() {
    let fixture = CustodianFixture::new().await;
    let setup_guard = fixture
        .manager
        .inner
        .custodian_context_update_lock
        .lock()
        .await;
    let context_id = RequestId::from_bytes([SETUP_CONTEXT_BYTE; 32]);
    let setup = fixture
        .manager
        .new_custodian_context(custodian_request(context_id, u64::from(SETUP_CONTEXT_BYTE)));
    tokio::pin!(setup);

    assert_pending(setup.as_mut()).await;
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());

    drop(setup_guard);
    setup.await.unwrap();
    assert!(fixture.recovery_exists(context_id).await);
    assert!(fixture.context_is_complete(context_id).await);
}

/// Destruction waits for failed setup to restore the previous context, then refuses to delete it.
#[tokio::test]
async fn custodian_destruction_waits_for_setup_rollback() {
    let fixture = CustodianFixture::new().await;
    let storage = &fixture.manager.inner.crypto_storage;
    let public_before = storage.public_storage.lock().await.state();
    let backup_before = fixture.backup_state().await;
    let new_id = RequestId::from_bytes([SETUP_CONTEXT_BYTE; 32]);
    let new_recovery_entry =
        StorageEntry::new(new_id, None, PubDataType::RecoveryMaterial.to_string());
    storage
        .public_storage
        .lock()
        .await
        .set_fail_store_at(new_recovery_entry.clone());

    // Let request validation finish, then pause setup before it changes the keychain.
    let context_guard = fixture
        .manager
        .inner
        .custodian_context_update_lock
        .lock()
        .await;
    let setup = fixture
        .manager
        .new_custodian_context(custodian_request(new_id, u64::from(SETUP_CONTEXT_BYTE)));
    tokio::pin!(setup);
    assert_pending(setup.as_mut()).await;
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());

    // Setup releases the vault lock after switching contexts, then needs private storage for the backup.
    let private_guard = storage.private_storage.lock().await;
    drop(context_guard);
    assert_pending(setup.as_mut()).await;
    assert_eq!(fixture.active_backup_context_id().await, new_id);

    let destruction = fixture.destroy(fixture.current_id);
    tokio::pin!(destruction);
    assert_pending(destruction.as_mut()).await;
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());
    assert!(
        fixture
            .manager
            .inner
            .custodian_meta_store
            .try_write()
            .is_ok(),
        "destruction must wait before taking the metadata lock"
    );

    drop(private_guard);
    assert_eq!(setup.await.unwrap_err().code(), tonic::Code::Internal);
    assert_eq!(fixture.active_backup_context_id().await, fixture.current_id);
    assert_eq!(storage.public_storage.lock().await.state(), public_before);
    assert_eq!(fixture.backup_state().await, backup_before);
    for context_id in [fixture.retired_id, fixture.current_id] {
        assert!(fixture.context_is_complete(context_id).await);
    }
    assert!(!fixture.context_is_complete(new_id).await);
    assert_same_events(
        &fixture.public_events().await,
        &[StorageEvent::new(
            new_recovery_entry,
            StorageOp::Store,
            StorageOutcome::FailedBeforeMutation,
        )],
    );
    let new_backup_entries = [
        BackupEntry::new(
            new_id,
            RequestId::from_bytes(DUMMY_SIGNING_KEY_REQ_ID),
            None,
            PrivDataType::SigningKey,
        ),
        BackupEntry::new(
            new_id,
            (*DEFAULT_MPC_CONTEXT).into(),
            None,
            PrivDataType::ContextInfo,
        ),
    ];
    let mut expected_backup_events = vec![];
    for entry in new_backup_entries {
        expected_backup_events.push(StorageEvent::new(
            entry.storage_entry(),
            StorageOp::Store,
            StorageOutcome::Created,
        ));
        expected_backup_events.push(StorageEvent::new(
            entry.storage_entry(),
            StorageOp::Delete,
            StorageOutcome::Deleted,
        ));
    }
    assert_same_events(&fixture.backup_events().await, &expected_backup_events);

    fixture.clear_faults_and_events().await;
    // Two successful contexts remain, so this rejection comes from the current-backup guard, not the last-context guard.
    let error = destruction.await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.to_string().contains("current backup id"));
    assert_eq!(storage.public_storage.lock().await.state(), public_before);
    assert_eq!(fixture.backup_state().await, backup_before);
    assert!(fixture.context_is_complete(fixture.current_id).await);
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());
}
