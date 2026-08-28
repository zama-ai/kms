use super::super::*;
use super::support::*;
use crate::vault::storage::test_support::{
    FaultPhase, StorageEvent, StorageOp, StorageOutcome, assert_same_events,
};
use crate::vault::storage::{Storage, read_context_at_id};
use std::{future::Future, task::Poll};

/// A failed context store leaves persistent and in-memory state unchanged.
#[rstest::rstest]
#[case::centralized_before(ManagerKind::Centralized, FaultPhase::BeforeMutation)]
#[case::centralized_after(ManagerKind::Centralized, FaultPhase::AfterMutation)]
#[case::threshold_before(ManagerKind::Threshold, FaultPhase::BeforeMutation)]
#[case::threshold_after(ManagerKind::Threshold, FaultPhase::AfterMutation)]
#[tokio::test]
async fn failed_context_creation_restores_state(
    #[case] manager_kind: ManagerKind,
    #[case] fault_phase: FaultPhase,
) {
    let fixture = ContextFixture::new(TargetState::Absent).await;
    let manager = fixture.manager(manager_kind).await;
    fixture.fail_target_store(fault_phase).await;

    let error = manager.create(&fixture.target).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(fixture.state().await, fixture.before);
    assert!(
        !manager
            .contains_consistent(fixture.target.context_id())
            .await
    );
    assert!(manager.contains_consistent(&fixture.keeper_id).await);
    let expected_events = match fault_phase {
        FaultPhase::BeforeMutation => vec![StorageEvent::new(
            fixture.target_entry.clone(),
            StorageOp::Store,
            StorageOutcome::FailedBeforeMutation,
        )],
        FaultPhase::AfterMutation => vec![
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Store,
                StorageOutcome::FailedAfterMutation,
            ),
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ),
        ],
    };
    assert_same_events(&fixture.events().await, &expected_events);
}

/// A delete failure before mutation keeps the context available across restart and retry.
#[rstest::rstest]
#[case::centralized(ManagerKind::Centralized)]
#[case::threshold(ManagerKind::Threshold)]
#[tokio::test]
async fn failed_context_destruction_is_retryable(#[case] manager_kind: ManagerKind) {
    let fixture = ContextFixture::new(TargetState::Stored).await;
    let manager = fixture.manager(manager_kind).await;
    fixture.fail_target_delete(FaultPhase::BeforeMutation).await;

    let error = manager
        .destroy(*fixture.target.context_id())
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(fixture.state().await, fixture.before);
    assert!(
        manager
            .contains_consistent(fixture.target.context_id())
            .await
    );
    assert!(manager.contains_consistent(&fixture.keeper_id).await);
    assert_same_events(
        &fixture.events().await,
        &[StorageEvent::new(
            fixture.target_entry.clone(),
            StorageOp::Delete,
            StorageOutcome::FailedBeforeMutation,
        )],
    );

    fixture.clear_faults().await;
    let restarted_manager = fixture.manager(manager_kind).await;
    restarted_manager
        .destroy(*fixture.target.context_id())
        .await
        .unwrap();

    assert_eq!(fixture.state().await, state_without_target(&fixture));
    assert!(
        !restarted_manager
            .contains_consistent(fixture.target.context_id())
            .await
    );
    assert!(
        restarted_manager
            .contains_consistent(&fixture.keeper_id)
            .await
    );
    assert_same_events(
        &fixture.events().await,
        &[
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Delete,
                StorageOutcome::FailedBeforeMutation,
            ),
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ),
        ],
    );
}

/// A delete error after mutation counts as success when the context is confirmed absent.
#[rstest::rstest]
#[case::centralized(ManagerKind::Centralized)]
#[case::threshold(ManagerKind::Threshold)]
#[tokio::test]
async fn context_destruction_accepts_a_confirmed_delete(#[case] manager_kind: ManagerKind) {
    let fixture = ContextFixture::new(TargetState::Stored).await;
    let manager = fixture.manager(manager_kind).await;
    fixture.fail_target_delete(FaultPhase::AfterMutation).await;

    manager.destroy(*fixture.target.context_id()).await.unwrap();

    assert_eq!(fixture.state().await, state_without_target(&fixture));
    assert!(
        !manager
            .contains_consistent(fixture.target.context_id())
            .await
    );
    assert!(manager.contains_consistent(&fixture.keeper_id).await);
    assert_same_events(
        &fixture.events().await,
        &[StorageEvent::new(
            fixture.target_entry.clone(),
            StorageOp::Delete,
            StorageOutcome::FailedAfterMutation,
        )],
    );
}

/// A rejected threshold store cannot remove a context that another call already stored.
#[tokio::test]
async fn rejected_context_store_keeps_an_existing_context() {
    let fixture = ContextFixture::new(TargetState::Stored).await;
    let base_kms = BaseKmsStruct::new(KMSType::Threshold, fixture.signing_key.clone()).unwrap();
    let session_maker = SessionMaker::empty_dummy_session(base_kms.new_rng().await);
    session_maker
        .add_context_info(None, &fixture.target)
        .await
        .unwrap();

    // Exercise the helper contract directly. The service lock and duplicate check would reject
    // this request before it reaches storage.
    let error = atomic_update_context(&session_maker, &fixture.storage, None, &fixture.target)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("Failed to store context"));
    assert_eq!(fixture.state().await, fixture.before);
    assert!(
        session_maker
            .context_exists(fixture.target.context_id())
            .await
    );
    assert!(fixture.events().await.is_empty());
}

/// A failed session update removes the context that the same call stored.
#[tokio::test]
async fn failed_session_update_rolls_back_the_stored_context() {
    let fixture = ContextFixture::new(TargetState::Absent).await;
    let base_kms = BaseKmsStruct::new(KMSType::Threshold, fixture.signing_key.clone()).unwrap();
    let session_maker = SessionMaker::empty_dummy_session(base_kms.new_rng().await);
    let mut invalid_context = fixture.target.clone();
    invalid_context.mpc_nodes[0].external_url = "http://localhost".to_string();

    let error = atomic_update_context(&session_maker, &fixture.storage, None, &invalid_context)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("missing port"));
    assert_eq!(fixture.state().await, fixture.before);
    assert!(
        !session_maker
            .context_exists(invalid_context.context_id())
            .await
    );
    assert_same_events(
        &fixture.events().await,
        &[
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Store,
                StorageOutcome::Created,
            ),
            StorageEvent::new(
                fixture.target_entry.clone(),
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ),
        ],
    );
}

/// A duplicate creation leaves the stored context and its surrounding state unchanged.
#[rstest::rstest]
#[case::centralized(ManagerKind::Centralized)]
#[case::threshold(ManagerKind::Threshold)]
#[tokio::test]
async fn duplicate_context_creation_keeps_the_stored_context(#[case] manager_kind: ManagerKind) {
    let fixture = ContextFixture::new(TargetState::Absent).await;
    let manager = fixture.manager(manager_kind).await;

    manager.create(&fixture.target).await.unwrap();
    let error = manager.create(&fixture.target).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::AlreadyExists);
    let after = fixture.state().await;
    assert_eq!(after.len(), fixture.before.len() + 1);
    for (entry, digest) in &fixture.before {
        assert_eq!(after.get(entry), Some(digest), "entry changed: {entry:?}");
    }
    assert!(after.contains_key(&fixture.target_entry));
    assert!(
        manager
            .contains_consistent(fixture.target.context_id())
            .await
    );
    assert!(manager.contains_consistent(&fixture.keeper_id).await);
    assert_same_events(
        &fixture.events().await,
        &[StorageEvent::new(
            fixture.target_entry.clone(),
            StorageOp::Store,
            StorageOutcome::Created,
        )],
    );
}

#[derive(Clone, Copy, Debug)]
enum ContextUpdate {
    Create,
    Destroy,
}

impl ContextUpdate {
    fn target_state(self) -> TargetState {
        match self {
            Self::Create => TargetState::Absent,
            Self::Destroy => TargetState::Stored,
        }
    }
}

/// Context creation and destruction wait for any active lifecycle update to complete.
#[rstest::rstest]
#[case::centralized_create(ManagerKind::Centralized, ContextUpdate::Create)]
#[case::centralized_destroy(ManagerKind::Centralized, ContextUpdate::Destroy)]
#[case::threshold_create(ManagerKind::Threshold, ContextUpdate::Create)]
#[case::threshold_destroy(ManagerKind::Threshold, ContextUpdate::Destroy)]
#[tokio::test]
async fn context_updates_wait_for_the_lifecycle_lock(
    #[case] manager_kind: ManagerKind,
    #[case] update_kind: ContextUpdate,
) {
    let fixture = ContextFixture::new(update_kind.target_state()).await;
    let manager = fixture.manager(manager_kind).await;
    let update_guard = manager.lock_updates().await;
    let update = async {
        match update_kind {
            ContextUpdate::Create => manager.create(&fixture.target).await.map(|_| ()),
            ContextUpdate::Destroy => manager.destroy(*fixture.target.context_id()).await,
        }
    };
    tokio::pin!(update);

    std::future::poll_fn(|context| match update.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => panic!("context update bypassed the lifecycle lock: {result:?}"),
    })
    .await;

    assert!(fixture.events().await.is_empty());
    drop(update_guard);
    update.await.unwrap();

    let (operation, outcome, target_exists) = match update_kind {
        ContextUpdate::Create => (StorageOp::Store, StorageOutcome::Created, true),
        ContextUpdate::Destroy => (StorageOp::Delete, StorageOutcome::Deleted, false),
    };
    assert_same_events(
        &fixture.events().await,
        &[StorageEvent::new(
            fixture.target_entry.clone(),
            operation,
            outcome,
        )],
    );
    assert_eq!(
        manager
            .contains_consistent(fixture.target.context_id())
            .await,
        target_exists
    );
}

/// A backup failure reports an error but keeps the durable context registered in memory.
#[rstest::rstest]
#[case::centralized(ManagerKind::Centralized)]
#[case::threshold(ManagerKind::Threshold)]
#[tokio::test]
async fn backup_failure_keeps_the_stored_context_registered(#[case] manager_kind: ManagerKind) {
    let (verification_key, signing_key, storage) = setup_crypto_storage(true).await;
    let context = context_info(
        ContextId::from_bytes([43; 32]),
        "backup-failure-target",
        &verification_key,
    );
    {
        let mut rng = AesRng::seed_from_u64(45);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_, backup_encryption_key) = encryption.keygen().unwrap();
        let backup_vault = storage.get_backup_vault().unwrap();
        let mut backup_vault = backup_vault.lock().await;
        match backup_vault.keychain.as_mut() {
            Some(KeychainProxy::SecretSharing(keychain)) => {
                keychain.set_backup_enc_key(RequestId::from_bytes([45; 32]), backup_encryption_key)
            }
            _ => panic!("expected a secret-sharing keychain"),
        }
    }
    {
        let mut private = storage.private_storage.lock().await;
        private
            .store_bytes(
                b"corrupt context",
                &RequestId::from_bytes([44; 32]),
                &PrivDataType::ContextInfo.to_string(),
            )
            .await
            .unwrap();
    }

    let base_kms = BaseKmsStruct::new(
        match manager_kind {
            ManagerKind::Centralized => KMSType::Centralized,
            ManagerKind::Threshold => KMSType::Threshold,
        },
        signing_key,
    )
    .unwrap();
    match manager_kind {
        ManagerKind::Centralized => {
            let manager =
                CentralizedContextManager::new(base_kms, storage.clone(), MetaStore::new(100, 10));
            assert_backup_failure(&manager, &storage, &context).await;
        }
        ManagerKind::Threshold => {
            let session_maker = SessionMaker::empty_dummy_session(base_kms.new_rng().await);
            let manager = ThresholdContextManager::new(
                base_kms,
                storage.clone(),
                MetaStore::new(100, 10),
                session_maker,
            );
            assert_backup_failure(&manager, &storage, &context).await;
        }
    }
}

async fn assert_backup_failure<M: ContextManager>(
    manager: &M,
    storage: &CryptoMaterialStorage<RamStorage, RamStorage>,
    context: &ContextInfo,
) {
    let error = manager
        .new_mpc_context(Request::new(NewMpcContextRequest {
            new_context: Some(context.clone().try_into().unwrap()),
        }))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.internal_err().to_string().contains("backing up"));
    let private = storage.private_storage.lock().await;
    assert_eq!(
        read_context_at_id(&*private, context.context_id())
            .await
            .unwrap(),
        *context
    );
    drop(private);
    assert!(
        manager
            .mpc_context_exists_in_cache(context.context_id())
            .await
    );
}
