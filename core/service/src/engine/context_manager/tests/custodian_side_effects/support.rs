//! Fixture support for custodian-context lifecycle failure tests.
//!
//! [`CustodianFixture`] creates a retired context and a current context through the service.
//! Its public and backup stores record events and can fail one exact storage coordinate.

use super::super::*;
use crate::vault::{
    VaultDataType,
    storage::{
        StorageReader,
        ram::FailingRamStorage,
        test_support::{
            BackupEntry, FaultPhase, StorageEntry, StorageEvent, failing_ram_storage,
            failing_ram_storage_mut,
        },
    },
};
use std::task::Poll;
use strum::IntoEnumIterator;

type TestStorage = CryptoMaterialStorage<FailingRamStorage, RamStorage>;
type TestManager = ThresholdContextManager<FailingRamStorage, RamStorage>;

const TARGET_CONTEXT_BYTE: u8 = 31;
const CURRENT_CONTEXT_BYTE: u8 = 32;
pub(super) const SETUP_CONTEXT_BYTE: u8 = 35;

/// Holds two custodian contexts and their persistent lifecycle state.
pub(super) struct CustodianFixture {
    pub(super) manager: TestManager,
    storage: TestStorage,
    pub(super) target_id: RequestId,
    pub(super) current_id: RequestId,
    target_backup_entry: BackupEntry,
    target_recovery_entry: StorageEntry,
}

impl CustodianFixture {
    /// Creates one retired context and one current context through the service.
    pub(super) async fn new() -> Self {
        let (_verification_key, signing_key, storage) = setup_crypto_storage_with_stores(
            true,
            FailingRamStorage::new(),
            RamStorage::new(),
            StorageProxy::from(FailingRamStorage::new()),
        )
        .await;
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, signing_key).unwrap();
        let session_maker = SessionMaker::four_party_dummy_session(
            None,
            None,
            &DEFAULT_EPOCH_ID,
            base_kms.new_rng().await,
        );
        let manager = ThresholdContextManager::new(
            base_kms,
            storage.clone(),
            MetaStore::new(100, 10),
            session_maker,
        );
        let target_id = RequestId::from_bytes([TARGET_CONTEXT_BYTE; 32]);
        let current_id = RequestId::from_bytes([CURRENT_CONTEXT_BYTE; 32]);
        manager
            .new_custodian_context(custodian_request(target_id, u64::from(TARGET_CONTEXT_BYTE)))
            .await
            .unwrap();
        manager
            .new_custodian_context(custodian_request(
                current_id,
                u64::from(CURRENT_CONTEXT_BYTE),
            ))
            .await
            .unwrap();

        let target_backup_entry = BackupEntry::new(
            target_id,
            RequestId::from_bytes(DUMMY_SIGNING_KEY_REQ_ID),
            None,
            PrivDataType::SigningKey,
        );
        let target_recovery_entry =
            StorageEntry::new(target_id, None, PubDataType::RecoveryMaterial.to_string());
        let fixture = Self {
            manager,
            storage,
            target_id,
            current_id,
            target_backup_entry,
            target_recovery_entry,
        };
        fixture.clear_events().await;
        fixture
    }

    /// Rejects one target backup deletion at `phase`.
    pub(super) async fn fail_backup_delete(&self, phase: FaultPhase) {
        let backup_vault = self.storage.backup_vault.as_ref().unwrap();
        let mut backup_vault = backup_vault.lock().await;
        let storage = failing_ram_storage_mut(&mut backup_vault);
        match phase {
            FaultPhase::BeforeMutation => {
                storage.set_fail_delete_at(self.target_backup_entry.storage_entry())
            }
            FaultPhase::AfterMutation => {
                storage.set_fail_delete_after_mutation_at(self.target_backup_entry.storage_entry())
            }
        }
    }

    /// Rejects deletion of the target's public recovery material.
    pub(super) async fn fail_recovery_delete(&self) {
        self.storage
            .public_storage
            .lock()
            .await
            .set_fail_delete_at(self.target_recovery_entry.clone());
    }

    /// Removes all fault points and recorded events from both mutable stores.
    pub(super) async fn clear_faults_and_events(&self) {
        {
            let mut public = self.storage.public_storage.lock().await;
            public.clear_fail_points();
            public.clear_events();
        }
        let backup_vault = self.storage.backup_vault.as_ref().unwrap();
        let mut backup_vault = backup_vault.lock().await;
        let backup = failing_ram_storage_mut(&mut backup_vault);
        backup.clear_fail_points();
        backup.clear_events();
    }

    /// Removes recorded events without changing configured faults.
    pub(super) async fn clear_events(&self) {
        self.storage.public_storage.lock().await.clear_events();
        let backup_vault = self.storage.backup_vault.as_ref().unwrap();
        let mut backup_vault = backup_vault.lock().await;
        failing_ram_storage_mut(&mut backup_vault).clear_events();
    }

    /// Requests destruction of `context_id`.
    pub(super) async fn destroy(
        &self,
        context_id: RequestId,
    ) -> Result<Response<Empty>, MetricedError> {
        self.manager
            .destroy_custodian_context(Request::new(DestroyCustodianContextRequest {
                context_id: Some(context_id.into()),
            }))
            .await
    }

    /// Returns whether public recovery material exists for `context_id`.
    pub(super) async fn recovery_exists(&self, context_id: RequestId) -> bool {
        self.storage
            .public_storage
            .lock()
            .await
            .data_exists(&context_id, &PubDataType::RecoveryMaterial.to_string())
            .await
            .unwrap()
    }

    /// Returns whether the meta store reports `context_id` as successful.
    pub(super) async fn context_is_complete(&self, context_id: RequestId) -> bool {
        self.manager
            .inner
            .custodian_meta_store
            .read()
            .await
            .get_successful_completed_request_ids()
            .any(|stored_id| stored_id == context_id)
    }

    /// Returns whether the backup namespace for `context_id` is empty.
    pub(super) async fn backup_is_empty(&self, context_id: RequestId) -> bool {
        let backup_vault = self.storage.backup_vault.as_ref().unwrap();
        let backup_vault = backup_vault.lock().await;
        for data_type in PrivDataType::iter() {
            let backend_type =
                VaultDataType::CustodianBackupData(context_id, data_type).to_string();
            if !backup_vault
                .storage
                .all_data_ids(&backend_type)
                .await
                .unwrap()
                .is_empty()
                || !backup_vault
                    .storage
                    .all_data_ids_from_all_epochs(&backend_type)
                    .await
                    .unwrap()
                    .is_empty()
            {
                return false;
            }
        }
        true
    }

    /// Returns recorded public storage events.
    pub(super) async fn public_events(&self) -> Vec<StorageEvent> {
        self.storage.public_storage.lock().await.events().to_vec()
    }

    /// Returns recorded backup storage events.
    pub(super) async fn backup_events(&self) -> Vec<StorageEvent> {
        let backup_vault = self.storage.backup_vault.as_ref().unwrap();
        let backup_vault = backup_vault.lock().await;
        failing_ram_storage(&backup_vault).events().to_vec()
    }

    /// Returns the target backup coordinate used by fault assertions.
    pub(super) fn target_backup_entry(&self) -> StorageEntry {
        self.target_backup_entry.storage_entry()
    }

    /// Returns the target recovery coordinate used by fault assertions.
    pub(super) fn target_recovery_entry(&self) -> StorageEntry {
        self.target_recovery_entry.clone()
    }
}

/// Builds a valid custodian-context request with deterministic keys.
pub(super) fn custodian_request(
    context_id: RequestId,
    seed: u64,
) -> Request<NewCustodianContextRequest> {
    let threshold = 1;
    let mut rng = AesRng::seed_from_u64(seed);
    let mut custodian_nodes = Vec::new();
    for index in 1..=3 {
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_, public_enc_key) = encryption.keygen().unwrap();
        let (public_verf_key, _) = gen_sig_keys(&mut rng);
        custodian_nodes.push(
            InternalCustodianSetupMessage {
                header: HEADER.to_string(),
                custodian_role: Role::indexed_from_one(index),
                name: format!("Custodian-{index}"),
                random_value: [seed as u8; 32],
                timestamp: SystemTime::now(),
                public_enc_key,
                public_verf_key,
            }
            .try_into()
            .unwrap(),
        );
    }

    Request::new(NewCustodianContextRequest {
        new_custodian_context: Some(CustodianContext {
            custodian_nodes,
            custodian_context_id: Some(context_id.into()),
            threshold,
        }),
        mpc_context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
    })
}

/// Polls `future` once and requires it to remain pending.
///
/// The caller must also verify that the pending operation did not emit a storage event.
pub(super) async fn assert_pending<F: std::future::Future>(mut future: std::pin::Pin<&mut F>) {
    std::future::poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("custodian setup bypassed the setup lock"),
    })
    .await;
}
