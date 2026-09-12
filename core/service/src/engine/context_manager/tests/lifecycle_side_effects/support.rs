//! Fixtures for MPC context creation and destruction failure tests.
//!
//! [`ContextFixture`] uses [`FailingRamStorage`] as the private store. It seeds a keeper context,
//! optionally seeds a target context, and loads the same data into a centralized cache or a
//! threshold session maker. Tests can then compare storage state and lifecycle state.

use super::super::*;
use crate::engine::rng_source::{RngSource, test_rng_source};
use crate::{
    cryptography::signatures::{PublicSigKey, gen_sig_keys},
    util::meta_store::MetaStore,
    vault::storage::{
        crypto_material::CryptoMaterialStorage,
        ram::{FailingRamStorage, RamStorage},
        store_context_at_id, store_versioned_at_request_id,
        test_support::{FaultPhase, StorageEntry, StorageEvent, StorageState},
    },
};
use kms_grpc::rpc_types::{KMSType, PrivDataType};
use rand::rngs::OsRng;
use std::sync::Arc;
use threshold_networking::{
    grpc::{CoreToCoreNetworkConfig, GrpcNetworkingManager},
    tls::AttestedVerifier,
};
use tokio::sync::RwLock;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_util::task::TaskTracker;

type TestStorage = CryptoMaterialStorage<RamStorage, FailingRamStorage>;

/// Selects whether the fixture seeds the target context before the test starts.
#[derive(Clone, Copy, Debug)]
pub(super) enum InitialTargetContextState {
    Absent,
    Stored,
}

pub(super) enum TestContextManager {
    Centralized(CentralizedContextManager<RamStorage, FailingRamStorage>),
    Threshold(ThresholdContextManager<RamStorage, FailingRamStorage>),
}

impl TestContextManager {
    pub(super) async fn new_mpc_context(
        &self,
        context: &ContextInfo,
    ) -> Result<Response<Empty>, MetricedError> {
        let request = Request::new(NewMpcContextRequest {
            new_context: Some(context.clone().try_into().unwrap()),
        });
        match self {
            Self::Centralized(manager) => manager.new_mpc_context(request).await,
            Self::Threshold(manager) => manager.new_mpc_context(request).await,
        }
    }

    pub(super) async fn destroy_mpc_context(
        &self,
        context_id: ContextId,
    ) -> Result<(), MetricedError> {
        let request = Request::new(DestroyMpcContextRequest {
            context_id: Some(context_id.into()),
        });
        match self {
            Self::Centralized(manager) => manager.destroy_mpc_context(request).await,
            Self::Threshold(manager) => manager.destroy_mpc_context(request).await,
        }
    }

    /// Holds the manager's lifecycle lock so tests can verify that an update waits for it.
    pub(super) async fn lock_updates(&self) -> tokio::sync::MutexGuard<'_, ()> {
        match self {
            Self::Centralized(manager) => manager.inner.mpc_context_update_lock.lock().await,
            Self::Threshold(manager) => manager.inner.mpc_context_update_lock.lock().await,
        }
    }

    /// Returns whether persistent and in-memory state both contain `context_id`.
    pub(super) async fn mpc_context_exists_and_consistent(&self, context_id: &ContextId) -> bool {
        match self {
            Self::Centralized(manager) => manager
                .mpc_context_exists_and_consistent(context_id)
                .await
                .unwrap(),
            Self::Threshold(manager) => manager
                .mpc_context_exists_and_consistent(context_id)
                .await
                .unwrap(),
        }
    }
}

/// Holds the persistent state, target context, and signing key for one lifecycle test.
pub(super) struct ContextFixture {
    pub(super) storage: TestStorage,
    pub(super) signing_key: PrivateSigKey,
    pub(super) target: ContextInfo,
    pub(super) keeper_id: ContextId,
    pub(super) target_entry: StorageEntry,
    pub(super) before: StorageState,
}

impl ContextFixture {
    pub(super) async fn new(target_state: InitialTargetContextState) -> Self {
        let storage =
            CryptoMaterialStorage::from(RamStorage::new(), FailingRamStorage::new(), None);
        let (verification_key, signing_key) = gen_sig_keys(&mut OsRng);
        let target = context_info(
            ContextId::from_bytes([41; 32]),
            "target-node",
            &verification_key,
        );
        let keeper = context_info(
            ContextId::from_bytes([42; 32]),
            "keeper-node",
            &verification_key,
        );
        let target_entry = StorageEntry::new(
            (*target.context_id()).into(),
            None,
            PrivDataType::ContextInfo.to_string(),
        );

        {
            let mut private = storage.private_storage.lock().await;
            store_versioned_at_request_id(
                &mut *private,
                &RequestId::from_bytes(DUMMY_SIGNING_KEY_REQ_ID),
                &signing_key,
                &PrivDataType::SigningKey.to_string(),
            )
            .await
            .unwrap();
            store_context_at_id(&mut *private, keeper.context_id(), &keeper)
                .await
                .unwrap();
            match target_state {
                InitialTargetContextState::Absent => {}
                InitialTargetContextState::Stored => {
                    store_context_at_id(&mut *private, target.context_id(), &target)
                        .await
                        .unwrap();
                }
            }
            private.clear_events();
        }

        let before = storage.private_storage.lock().await.state();
        Self {
            storage,
            signing_key,
            target,
            keeper_id: *keeper.context_id(),
            target_entry,
            before,
        }
    }

    pub(super) async fn manager(&self, kms_type: KMSType) -> TestContextManager {
        let base_kms = BaseKmsStruct::new(kms_type, self.signing_key.clone(), test_rng_source());

        match kms_type {
            KMSType::Centralized => {
                let manager = CentralizedContextManager::new(
                    base_kms,
                    self.storage.clone(),
                    MetaStore::new(100, 10),
                    Arc::new(TaskTracker::new()),
                );
                manager.load_mpc_context_from_storage().await.unwrap();
                TestContextManager::Centralized(manager)
            }
            KMSType::Threshold => {
                let session_maker = SessionMaker::empty_dummy_session(base_kms.new_rng());
                let manager = ThresholdContextManager::new(
                    base_kms,
                    self.storage.clone(),
                    MetaStore::new(100, 10),
                    session_maker,
                    false,
                    Arc::new(TaskTracker::new()),
                );
                manager.load_mpc_context_from_storage().await.unwrap();
                TestContextManager::Threshold(manager)
            }
        }
    }

    pub(super) async fn fail_target_store(&self, phase: FaultPhase) {
        let mut private = self.storage.private_storage.lock().await;
        match phase {
            FaultPhase::BeforeMutation => private.set_fail_store_at(self.target_entry.clone()),
            FaultPhase::AfterMutation => {
                private.set_fail_store_after_mutation_at(self.target_entry.clone())
            }
        }
    }

    pub(super) async fn fail_target_delete(&self, phase: FaultPhase) {
        let mut private = self.storage.private_storage.lock().await;
        match phase {
            FaultPhase::BeforeMutation => private.set_fail_delete_at(self.target_entry.clone()),
            FaultPhase::AfterMutation => {
                private.set_fail_delete_after_mutation_at(self.target_entry.clone())
            }
        }
    }

    pub(super) async fn clear_faults(&self) {
        self.storage
            .private_storage
            .lock()
            .await
            .clear_fail_points();
    }

    pub(super) async fn clear_events(&self) {
        self.storage.private_storage.lock().await.clear_events();
    }

    pub(super) async fn state(&self) -> StorageState {
        self.storage.private_storage.lock().await.state()
    }

    pub(super) async fn events(&self) -> Vec<StorageEvent> {
        self.storage.private_storage.lock().await.events().to_vec()
    }
}

/// Returns an empty session maker with attested TLS verification enabled.
pub(super) fn attested_session_maker(rng: AesRng) -> SessionMaker {
    let _ = default_provider().install_default();
    let verifier = Arc::new(
        AttestedVerifier::new(
            None,
            false,
            #[cfg(feature = "testing")]
            true,
        )
        .unwrap(),
    );
    let networking_manager = Arc::new(RwLock::new(
        GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap(),
    ));
    SessionMaker::new_uninitialized(
        networking_manager,
        Some(verifier),
        Arc::new(RngSource::from_rng(rng)),
    )
}

pub(super) fn state_without_target(fixture: &ContextFixture) -> StorageState {
    let mut expected = fixture.before.clone();
    expected.remove(&fixture.target_entry);
    expected
}

pub(super) fn context_info(
    context_id: ContextId,
    identity: &str,
    verification_key: &PublicSigKey,
) -> ContextInfo {
    ContextInfo {
        mpc_nodes: vec![NodeInfo {
            mpc_identity: identity.to_string(),
            party_id: 1,
            external_url: "http://localhost:12345".to_string(),
            ca_cert: None,
            public_storage_url: "http://storage".to_string(),
            public_storage_prefix: None,
            extra_signer_addresses: vec![],
            scheme_digests: SchemeDigests::from_ecdsa_verification_key(verification_key),
        }],
        context_id,
        software_version: SoftwareVersion {
            major: 0,
            minor: 1,
            patch: 0,
            tag: None,
        },
        threshold: 0,
        pcr_values: vec![],
    }
}
