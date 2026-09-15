use super::support::*;
use crate::engine::traits::ContextManager;
use crate::vault::storage::test_support::{
    FaultPhase, StorageEvent, StorageOp, StorageOutcome, assert_same_events,
};
use kms_grpc::RequestId;

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
    expected_final_state.remove(&fixture.retired_recovery_entry);

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

    let mut expected_retry = fixture.expected_backup_deletes(fixture.retired_id).await;
    expected_retry.push(StorageEvent::new(
        fixture.retired_recovery_entry.clone(),
        StorageOp::Delete,
        StorageOutcome::Deleted,
    ));
    fixture.clear_faults_and_events().await;
    fixture.destroy(fixture.retired_id).await.unwrap();
    assert_same_events(&fixture.backup_events().await, &expected_retry);
    assert!(fixture.public_events().await.is_empty());

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
    let mut expected_backups = fixture.expected_backup_deletes(fixture.retired_id).await;
    let mut expected_final_state = fixture.backup_state().await;
    for event in &expected_backups {
        expected_final_state.remove(&event.entry);
    }

    let error = fixture.destroy(fixture.retired_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    expected_backups.push(StorageEvent::new(
        fixture.retired_recovery_entry.clone(),
        StorageOp::Delete,
        expected_outcome,
    ));
    assert_same_events(&fixture.backup_events().await, &expected_backups);
    assert!(fixture.backup_is_empty(fixture.retired_id).await);
    match fault_phase {
        FaultPhase::BeforeMutation => assert!(fixture.recovery_exists(fixture.retired_id).await),
        FaultPhase::AfterMutation => {
            assert!(!fixture.recovery_exists(fixture.retired_id).await);
            expected_final_state.remove(&fixture.retired_recovery_entry);
        }
    }
    assert_eq!(fixture.backup_state().await, expected_final_state);
    assert!(fixture.context_is_complete(fixture.retired_id).await);
    assert!(fixture.public_events().await.is_empty());

    fixture.clear_faults_and_events().await;
    fixture.destroy(fixture.retired_id).await.unwrap();

    expected_final_state.remove(&fixture.retired_recovery_entry);
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
    assert_same_events(&fixture.backup_events().await, &expected_retry);
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_is_empty(fixture.retired_id).await);
    assert!(!fixture.recovery_exists(fixture.retired_id).await);
    assert!(!fixture.context_is_complete(fixture.retired_id).await);
}

/// Destruction of the only successful context is rejected without a storage operation: by the
/// anchor guard while the anchor names it, and by the meta-store guard once no anchor does.
#[tokio::test]
async fn last_custodian_context_destruction_has_no_side_effects() {
    let fixture = CustodianFixture::new().await;
    // Destroy the retired context so the current context is the only successful context left.
    fixture.destroy(fixture.retired_id).await.unwrap();
    fixture.clear_faults_and_events().await;

    let anchored = fixture.destroy(fixture.current_id).await.unwrap_err();
    fixture.delete_anchor().await;
    let last = fixture.destroy(fixture.current_id).await.unwrap_err();

    for (error, reason) in [
        (anchored, "the one this node backs up under"),
        (last, "the only one left"),
    ] {
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.internal_err().to_string().contains(reason));
    }
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());
    assert!(fixture.recovery_exists(fixture.current_id).await);
    assert!(fixture.context_is_complete(fixture.current_id).await);
}

/// Custodian setup waits for the context lock before it changes storage.
///
/// The setup runs on a spawned task. The clock is paused, so the sleep below resumes only once
/// that task is idle.
#[tokio::test(start_paused = true)]
async fn custodian_setup_waits_for_the_context_lock() {
    let fixture = CustodianFixture::new().await;
    let context_guard = fixture
        .manager
        .inner
        .crypto_storage
        .custodian_context_lock
        .lock()
        .await;
    let context_id = RequestId::from_bytes([SETUP_CONTEXT_BYTE; 32]);
    let setup = fixture
        .manager
        .new_custodian_context(custodian_request(context_id, u64::from(SETUP_CONTEXT_BYTE)));
    tokio::pin!(setup);

    assert_pending(setup.as_mut()).await;
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());

    drop(context_guard);
    setup.await.unwrap();
    assert!(fixture.recovery_exists(context_id).await);
    assert!(fixture.context_is_complete(context_id).await);
}
