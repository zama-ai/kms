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

    let error = fixture.destroy(fixture.target_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(fixture.recovery_exists(fixture.target_id).await);
    assert!(fixture.context_is_complete(fixture.target_id).await);
    assert!(fixture.public_events().await.is_empty());
    let backup_events = fixture.backup_events().await;
    let faults: Vec<_> = backup_events
        .iter()
        .filter(|event| event.outcome.failed())
        .collect();
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].entry, fixture.target_backup_entry());
    assert_eq!(faults[0].outcome, expected_outcome);

    fixture.clear_faults_and_events().await;
    fixture.destroy(fixture.target_id).await.unwrap();

    assert!(fixture.backup_is_empty(fixture.target_id).await);
    assert!(!fixture.recovery_exists(fixture.target_id).await);
    assert!(!fixture.context_is_complete(fixture.target_id).await);
    assert!(fixture.recovery_exists(fixture.current_id).await);
    assert!(fixture.context_is_complete(fixture.current_id).await);
}

/// A recovery-material delete failure leaves an empty backup namespace in a retryable state.
#[tokio::test]
async fn failed_recovery_material_deletion_is_retryable() {
    let fixture = CustodianFixture::new().await;
    fixture.fail_recovery_delete().await;

    let error = fixture.destroy(fixture.target_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(fixture.backup_is_empty(fixture.target_id).await);
    assert!(fixture.recovery_exists(fixture.target_id).await);
    assert!(fixture.context_is_complete(fixture.target_id).await);
    assert_same_events(
        &fixture.public_events().await,
        &[StorageEvent::new(
            fixture.target_recovery_entry(),
            StorageOp::Delete,
            StorageOutcome::FailedBeforeMutation,
        )],
    );

    fixture.clear_faults_and_events().await;
    fixture.destroy(fixture.target_id).await.unwrap();

    assert!(fixture.backup_is_empty(fixture.target_id).await);
    assert!(!fixture.recovery_exists(fixture.target_id).await);
    assert!(!fixture.context_is_complete(fixture.target_id).await);
}

/// Destruction of the only successful context is rejected without a storage operation.
#[tokio::test]
async fn last_custodian_context_destruction_has_no_side_effects() {
    let fixture = CustodianFixture::new().await;
    // First retire the target so the current context is the only successful context left.
    fixture.destroy(fixture.target_id).await.unwrap();
    fixture.clear_faults_and_events().await;

    let error = fixture.destroy(fixture.current_id).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(fixture.public_events().await.is_empty());
    assert!(fixture.backup_events().await.is_empty());
    assert!(fixture.recovery_exists(fixture.current_id).await);
    assert!(fixture.context_is_complete(fixture.current_id).await);
}

/// Custodian setup waits for the setup lock before it changes storage.
#[tokio::test]
async fn custodian_setup_waits_for_the_setup_lock() {
    let fixture = CustodianFixture::new().await;
    let setup_guard = fixture.manager.inner.custodian_setup_lock.lock().await;
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
