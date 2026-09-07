//! Shared storage setup and assertions for migration side-effect tests.

use super::super::super::*;
use crate::{
    engine::context::{ContextInfo, NodeInfo, SchemeDigests, SoftwareVersion},
    vault::storage::{
        Storage, StorageExt,
        ram::FailingRamStorage,
        test_support::{StorageEntry, StorageState},
    },
};
use kms_grpc::RequestId;

const CONTROL_TYPE: &str = "MigrationControl";
pub(super) const LEGACY_CRS_DATA: &[u8] = b"legacy CRS metadata";

/// Holds one legacy CRS entry, its epoch target, and unrelated private entries.
pub(super) struct CrsMigrationFixture {
    pub(super) storage: FailingRamStorage,
    pub(super) legacy_entry: StorageEntry,
    pub(super) target_entry: StorageEntry,
    pub(super) control_entries: [StorageEntry; 2],
    pub(super) before: StorageState,
}

impl CrsMigrationFixture {
    pub(super) async fn new(name: &str, target_data: Option<&[u8]>) -> Self {
        let mut storage = FailingRamStorage::new();
        let crs_id = request_id(name);
        let data_type = PrivDataType::CrsInfo.to_string();
        let legacy_entry = StorageEntry::new(crs_id, None, &data_type);
        let target_entry = StorageEntry::new(crs_id, Some(*DEFAULT_EPOCH_ID), &data_type);
        storage
            .store_bytes(LEGACY_CRS_DATA, &crs_id, &data_type)
            .await
            .unwrap();
        if let Some(target_data) = target_data {
            storage
                .store_bytes_at_epoch(target_data, &crs_id, &DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap();
        }
        let control_entries = seed_controls(&mut storage).await;
        storage.clear_events();
        let before = storage.state();

        Self {
            storage,
            legacy_entry,
            target_entry,
            control_entries,
            before,
        }
    }

    pub(super) fn assert_controls_unchanged(&self) {
        let state = self.storage.state();
        for entry in &self.control_entries {
            assert_eq!(state.get(entry), self.before.get(entry));
        }
    }
}

pub(super) fn request_id(name: &str) -> RequestId {
    derive_request_id(name).unwrap()
}

pub(super) fn test_prss(threshold: u8) -> PRSSSetupCombined {
    PRSSSetupCombined {
        prss_setup_z128: PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]),
        prss_setup_z64: PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]),
        num_parties: 4,
        threshold,
    }
}

pub(super) fn test_context(context_id: ContextId) -> ContextInfo {
    ContextInfo {
        mpc_nodes: vec![NodeInfo {
            mpc_identity: "migration-test-node".to_string(),
            party_id: 1,
            external_url: "https://doesnotexist.zama.ai".to_string(),
            ca_cert: None,
            public_storage_url: String::new(),
            public_storage_prefix: None,
            extra_signer_addresses: vec![],
            scheme_digests: SchemeDigests::new(),
        }],
        context_id,
        software_version: SoftwareVersion::current().unwrap(),
        threshold: 0,
        pcr_values: vec![],
    }
}

/// Store two unrelated entries: a test-only value and a signing key.
pub(super) async fn seed_controls(storage: &mut FailingRamStorage) -> [StorageEntry; 2] {
    let synthetic_id = request_id("migration_side_effect_synthetic_control");
    storage
        .store_bytes(b"unrelated", &synthetic_id, CONTROL_TYPE)
        .await
        .unwrap();
    let signing_key_id = request_id("migration_side_effect_signing_key_control");
    let signing_key_type = PrivDataType::SigningKey.to_string();
    storage
        .store_bytes(b"unrelated signing key", &signing_key_id, &signing_key_type)
        .await
        .unwrap();

    [
        StorageEntry::new(synthetic_id, None, CONTROL_TYPE),
        StorageEntry::new(signing_key_id, None, signing_key_type),
    ]
}
