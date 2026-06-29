use crate::backup::BackupCiphertext;
use crate::backup::custodian::Custodian;
use crate::backup::seed_phrase::custodian_from_seed_phrase;
use crate::client::client_wasm::Client;
use crate::client::test_tools::ServerHandle;
use crate::client::tests::common::{
    PollConfig, keygen_config, retrying_poll, uncompressed_keygen_config,
};
use crate::client::tests::threshold::common::run_insecure_preproc;
use crate::client::tests::threshold::crs_gen_tests::run_crs;
use crate::client::tests::threshold::custodian_context_tests::run_new_cus_context;
use crate::client::tests::threshold::key_gen_tests::run_threshold_keygen;
use crate::client::tests::threshold::public_decryption_tests::run_decryption_threshold;
use crate::consts::DEFAULT_EPOCH_ID;
use crate::consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::consts::{
    BACKUP_STORAGE_PREFIX_THRESHOLD_ALL, DEFAULT_MPC_CONTEXT, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
    SIGNING_KEY_ID,
};
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
use crate::cryptography::signatures::PrivateSigKey;
use crate::cryptography::signatures::PublicSigKey;
use crate::engine::base::derive_request_id;
use crate::engine::base::{CrsGenMetadata, DSEP_PUBDATA_KEY};
use crate::engine::context::{ContextInfo, SignerAddress};
use crate::testing::setup::ThresholdTestEnv;
use crate::util::key_setup::test_tools::EncryptionConfig;
use crate::util::key_setup::test_tools::TestingPlaintext;
use crate::util::key_setup::test_tools::{
    purge_backup, read_custodian_backup_files, read_custodian_backup_files_with_epoch,
};
use crate::vault::storage::StorageType;
use crate::vault::storage::crypto_material::{data_exists, data_exists_at_epoch};
use crate::vault::storage::delete_at_request_and_epoch_id;
use crate::vault::storage::delete_at_request_id;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::read_context_at_id;
use crate::vault::storage::read_versioned_at_request_and_epoch_id;
use crate::vault::storage::read_versioned_at_request_id;

use aes_prng::AesRng;
use alloy_primitives::Address;
use hashing::hash_versioned;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::{
    CrsInfo, CustodianRecoveryInitRequest, CustodianRecoveryOutput, CustodianRecoveryRequest,
    Empty, KeyInfo, PreviousEpochInfo, RecoveryRequest,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{RequestId, kms::v1::FheParameter, rpc_types::PrivDataType};
use rand::SeedableRng;
use std::collections::HashMap;
use tfhe::safe_serialization::safe_deserialize;
use threshold_types::role::Role;
use tokio::task::JoinSet;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Common test scaffolding
// ---------------------------------------------------------------------------

/// Shared environment for threshold custodian-backup tests.
///
/// Spins up a 4-party threshold cluster with custodian backup enabled and
/// creates an initial custodian context.
struct ThresholdBackupTestEnv {
    kms_servers: Option<HashMap<u32, ServerHandle>>,
    kms_clients: Option<HashMap<u32, CoreServiceEndpointClient<Channel>>>,
    internal_client: Option<Client>,
    mnemonics: Vec<String>,
    req_new_cus: RequestId,
    material_dir: tempfile::TempDir,
}

impl ThresholdBackupTestEnv {
    const AMOUNT_PARTIES: usize = 4;

    async fn new(test_name: &str, amount_custodians: usize, threshold: u32) -> Self {
        let dkg_param: WrappedDKGParams = FheParameter::Test.into();
        let req_new_cus: RequestId = derive_request_id(test_name).unwrap();

        let (material_dir, servers, clients, mut internal_client) = {
            let env = ThresholdTestEnv::builder()
                .with_test_name(test_name)
                .with_party_count(Self::AMOUNT_PARTIES)
                .with_custodian_keychain()
                .with_prss()
                .build()
                .await
                .unwrap();
            let internal_client = env.create_internal_client(&dkg_param, None).await.unwrap();
            (env.material_dir, env.servers, env.clients, internal_client)
        };

        let mnemonics = run_new_cus_context(
            &clients,
            &mut internal_client,
            &req_new_cus,
            amount_custodians,
            threshold,
        )
        .await;

        Self {
            kms_servers: Some(servers),
            kms_clients: Some(clients),
            internal_client: Some(internal_client),
            mnemonics,
            req_new_cus,
            material_dir,
        }
    }

    fn test_path(&self) -> Option<&std::path::Path> {
        Some(self.material_dir.path())
    }

    fn backup_prefixes(&self) -> &[Option<String>] {
        &BACKUP_STORAGE_PREFIX_THRESHOLD_ALL[0..Self::AMOUNT_PARTIES]
    }

    fn priv_prefixes(&self) -> &[Option<String>] {
        &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..Self::AMOUNT_PARTIES]
    }

    fn pub_prefixes(&self) -> &[Option<String>] {
        &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..Self::AMOUNT_PARTIES]
    }

    fn kms_clients(&self) -> &HashMap<u32, CoreServiceEndpointClient<Channel>> {
        self.kms_clients.as_ref().unwrap()
    }

    fn internal_client(&self) -> &Client {
        self.internal_client.as_ref().unwrap()
    }

    /// Shut down servers and drop clients. The env remains usable for
    /// `test_path()`, `req_new_cus`, `mnemonics`, and prefix accessors.
    async fn shutdown(&mut self) {
        self.kms_clients.take();
        self.internal_client.take();
        if let Some(servers) = self.kms_servers.take() {
            for (_, s) in servers {
                s.assert_shutdown().await;
            }
        }
    }

    /// Spawn a fresh KMS server attached to this env's material directory. Use to assert state persists across server
    /// lifetimes. The wrapper must outlive the returned pair.
    async fn spawn_server_on_existing_material(
        &self,
    ) -> (
        HashMap<u32, ServerHandle>,
        HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) {
        ThresholdTestEnv::builder()
            .with_party_count(Self::AMOUNT_PARTIES)
            .with_custodian_keychain()
            .with_prss()
            .from_path(self.material_dir.path())
            .await
            .unwrap()
    }

    /// Construct a fresh internal Client backed by this env's material dir.
    async fn create_internal_client(
        &self,
        dkg_param: &threshold_execution::tfhe_internals::parameters::DKGParams,
    ) -> Client {
        let path = self.material_dir.path();
        let mut pub_storage_map = HashMap::new();
        for (i, prefix) in PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..Self::AMOUNT_PARTIES]
            .iter()
            .enumerate()
        {
            let pub_storage =
                FileStorage::new(Some(path), StorageType::PUB, prefix.as_deref()).unwrap();
            pub_storage_map.insert((i + 1) as u32, pub_storage);
        }
        let client_storage = FileStorage::new(Some(path), StorageType::CLIENT, None).unwrap();
        Client::new_client(client_storage, pub_storage_map, dkg_param, None)
            .await
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(7, 3)]
#[case(3, 1)]
async fn test_auto_update_backups_threshold(#[case] custodians: usize, #[case] threshold: u32) {
    auto_update_backup(custodians, threshold).await;
}

async fn auto_update_backup(amount_custodians: usize, threshold: u32) {
    let n = ThresholdBackupTestEnv::AMOUNT_PARTIES;
    let mut env = ThresholdBackupTestEnv::new(
        &format!("auto_update_backups_threshold_{n}_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;

    // Check that signing key was backed up, since it will always be there
    let initial_backup: Vec<BackupCiphertext> = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(initial_backup.len(), n); // exactly one per party

    env.shutdown().await;

    // Purge backup
    purge_backup(env.test_path(), env.backup_prefixes()).await;
    // Check that the backup is still there after reboot
    let (_kms_servers, _kms_clients) = env.spawn_server_on_existing_material().await;
    let _reread_backup: Vec<BackupCiphertext> = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        env.backup_prefixes(),
    )
    .await;
}
#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(7, 3)]
#[case(3, 1)]
async fn test_backup_after_crs_threshold(#[case] custodians: usize, #[case] threshold: u32) {
    backup_after_crs(custodians, threshold).await;
}
async fn backup_after_crs(amount_custodians: usize, threshold: u32) {
    let n = ThresholdBackupTestEnv::AMOUNT_PARTIES;
    let mut env = ThresholdBackupTestEnv::new(
        &format!("backup_after_crs_threshold_{n}_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;
    let crs_req: RequestId = derive_request_id(&format!(
        "backup_after_crs_threshold_crs_{n}_{amount_custodians}_{threshold}"
    ))
    .unwrap();

    // Generate a new crs
    run_crs(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        true,
        &crs_req,
        Some(16),
        env.test_path(),
    )
    .await;

    // Sleep briefly to allow backup to be written (since backup is done asynchronously after generation)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Check that the new CRS was backed up
    let crss: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &crs_req,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::CrsInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;

    // Validate each backup
    assert_eq!(crss.len(), n);
    for i in 0..crss.len() - 1 {
        // Check that each is different since it is supposed to be secret shared
        assert!(crss[i] != crss[i + 1]);
        // Check that the format is correct
        assert!(crss[i].priv_data_type == PrivDataType::CrsInfo);
    }
    assert!(crss[crss.len() - 1].priv_data_type == PrivDataType::CrsInfo);

    // Read CRS metadata from private storage for reference before recovery
    let mut original_crs_metadata = Vec::with_capacity(n);
    for storage_prefix in env.priv_prefixes().iter() {
        let cur_priv_store = FileStorage::new(
            env.test_path(),
            StorageType::PRIV,
            storage_prefix.as_deref(),
        )
        .unwrap();
        let cur_meta: CrsGenMetadata = read_versioned_at_request_and_epoch_id(
            &cur_priv_store,
            &crs_req,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
        original_crs_metadata.push(cur_meta);
    }

    env.shutdown().await;

    // Capture operator verification keys (needed for `run_full_custodian_recovery` below).
    let operator_verf_keys = operator_verf_key_map(env.test_path(), env.pub_prefixes()).await;
    let custodian_context_id = env.req_new_cus;

    // Delete only the CRS metadata for each party. Signing keys stay intact so the cluster can spawn via
    // `spawn_server_on_existing_material`.
    for storage_prefix in env.priv_prefixes().iter() {
        let mut cur_priv_store = FileStorage::new(
            env.test_path(),
            StorageType::PRIV,
            storage_prefix.as_deref(),
        )
        .unwrap();
        delete_at_request_and_epoch_id(
            &mut cur_priv_store,
            &crs_req,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let (kms_servers, kms_clients) = env.spawn_server_on_existing_material().await;

    // Execute the backup restore
    run_full_custodian_recovery(
        &kms_clients,
        &operator_verf_keys,
        custodian_context_id,
        env.mnemonics.clone(),
        n,
        None,
    )
    .await;

    // Verify CRS metadata was recovered correctly
    for (i, storage_prefix) in env.priv_prefixes().iter().enumerate() {
        let cur_priv_store = FileStorage::new(
            env.test_path(),
            StorageType::PRIV,
            storage_prefix.as_deref(),
        )
        .unwrap();
        let recovered_meta: CrsGenMetadata = read_versioned_at_request_and_epoch_id(
            &cur_priv_store,
            &crs_req,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(recovered_meta, original_crs_metadata[i]);
    }

    shutdown_servers(kms_servers).await;
    drop(kms_clients);
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(7, 3)]
#[case(3, 1)]
async fn test_decrypt_after_recovery_threshold(#[case] custodians: usize, #[case] threshold: u32) {
    decrypt_after_recovery(custodians, threshold).await;
}

async fn decrypt_after_recovery(amount_custodians: usize, threshold: u32) {
    let n = ThresholdBackupTestEnv::AMOUNT_PARTIES;
    let mut env = ThresholdBackupTestEnv::new(
        &format!("decrypt_after_recovery_threshold_{n}_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;
    let req_key_id: RequestId = derive_request_id(&format!(
        "decrypt_after_recovery_threshold_key_{n}_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let preproc_id: RequestId = derive_request_id(&format!(
        "decrypt_after_recovery_threshold_preproc_{n}_{amount_custodians}_{threshold}"
    ))
    .unwrap();

    // Generate a key
    let (keyset_config, keyset_added_info) = keygen_config();
    run_insecure_preproc(env.kms_clients(), &preproc_id, FheParameter::Test)
        .await
        .unwrap();
    let _keys = run_threshold_keygen(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        &preproc_id,
        &req_key_id,
        keyset_config,
        keyset_added_info,
        true,
        env.test_path(),
        0,
    )
    .await;

    env.shutdown().await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();

    // Capture state while disk is intact. `sig_keys` is the byte-level snapshot we'll compare against after recovery to
    // verify signing keys are preserved exactly.
    let sig_keys = read_signing_keys(env.test_path(), env.priv_prefixes()).await;
    let operator_verf_keys = operator_verf_key_map(env.test_path(), env.pub_prefixes()).await;
    let custodian_context_id = env.req_new_cus;

    // Boot fresh servers.
    let (kms_servers, kms_clients) = env.spawn_server_on_existing_material().await;

    // Delete the FHE shares and the per-party signing keys so we can check them after recovery.
    for storage_prefix in env.priv_prefixes().iter() {
        let mut cur_priv_store = FileStorage::new(
            env.test_path(),
            StorageType::PRIV,
            storage_prefix.as_deref(),
        )
        .unwrap();
        delete_at_request_and_epoch_id(
            &mut cur_priv_store,
            &req_key_id,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
        delete_at_request_id(
            &mut cur_priv_store,
            &SIGNING_KEY_ID,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();

        assert!(
            !data_exists_at_epoch(
                &cur_priv_store,
                &req_key_id,
                &DEFAULT_EPOCH_ID,
                &PrivDataType::FheKeyInfo.to_string()
            )
            .await
            .unwrap()
        );
        assert!(
            !data_exists(
                &cur_priv_store,
                &SIGNING_KEY_ID,
                &PrivDataType::SigningKey.to_string()
            )
            .await
            .unwrap()
        );
    }

    // Execute the backup restore.
    run_full_custodian_recovery(
        &kms_clients,
        &operator_verf_keys,
        custodian_context_id,
        env.mnemonics.clone(),
        n,
        None,
    )
    .await;

    // Signing keys must be back on disk, byte-equal to the originals.
    let recovered_sig_keys = read_signing_keys(env.test_path(), env.priv_prefixes()).await;
    assert_eq!(recovered_sig_keys, sig_keys);

    // Reboot the servers and verify decryption
    shutdown_servers(kms_servers).await;
    drop(kms_clients);
    let (mut kms_servers, mut kms_clients) = env.spawn_server_on_existing_material().await;
    let mut internal_client = env.create_internal_client(&dkg_param).await;
    run_decryption_threshold(
        n,
        &mut kms_servers,
        &mut kms_clients,
        &mut internal_client,
        None,
        &req_key_id,
        None,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        None,
        1,
        env.test_path(),
    )
    .await;
}

/// Same intent as centralized negative test: corrupt signcryption for two custodians; invalid
/// outputs are filtered and recovery still restores signing keys (`assert_eq!` on recovered keys).
#[tokio::test]
async fn test_decrypt_after_recovery_threshold_negative() {
    decrypt_after_recovery_negative(5, 2).await;
}

fn corrupt_custodian_outputs(cus_out: &mut HashMap<Address, (u32, CustodianRecoveryRequest)>) {
    // Change a bit in two of the custodians contribution to the recover requests to make them invalid
    for (_, cur_payload) in cus_out.values_mut() {
        // First custodian 1
        cur_payload
            .custodian_recovery_outputs
            .get_mut(0)
            .map(|inner| {
                inner
                    .backup_output
                    .as_mut()
                    // Flip a bit in the 11th byte
                    .map(|back_out| back_out.signcryption[11] ^= 1)
            });
        // Then in custodian 3
        cur_payload
            .custodian_recovery_outputs
            .get_mut(2)
            .map(|inner| {
                inner
                    .backup_output
                    .as_mut()
                    // Flip a bit in the 7th byte
                    .map(|back_out| back_out.signcryption[7] ^= 1)
            });
    }
}

async fn decrypt_after_recovery_negative(amount_custodians: usize, threshold: u32) {
    let n = ThresholdBackupTestEnv::AMOUNT_PARTIES;
    let mut env = ThresholdBackupTestEnv::new(
        &format!("decrypt_after_recovery_threshold_negative_{n}_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;
    let req_key_id: RequestId = derive_request_id(&format!(
        "decrypt_after_recovery_threshold_negative_key_{n}_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let preproc_id: RequestId = derive_request_id(&format!(
        "decrypt_after_recovery_threshold_negative_preproc_{n}_{amount_custodians}_{threshold}"
    ))
    .unwrap();

    // Generate a key so we have FHE material to delete + recover.
    let (keyset_config, keyset_added_info) = keygen_config();
    run_insecure_preproc(env.kms_clients(), &preproc_id, FheParameter::Test)
        .await
        .unwrap();
    let _keys = run_threshold_keygen(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        &preproc_id,
        &req_key_id,
        keyset_config,
        keyset_added_info,
        true,
        env.test_path(),
        0,
    )
    .await;

    env.shutdown().await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();

    // Capture state while disk is intact.
    let sig_keys = read_signing_keys(env.test_path(), env.priv_prefixes()).await;
    let operator_verf_keys = operator_verf_key_map(env.test_path(), env.pub_prefixes()).await;
    let custodian_context_id = env.req_new_cus;

    // Boot fresh serversso they can load signing keys into memory before deleting.
    let (kms_servers, kms_clients) = env.spawn_server_on_existing_material().await;

    // Delete the FHE shares and the per-party signing keys (so we can byte-compare them after recovery).
    for storage_prefix in env.priv_prefixes().iter() {
        let mut cur_priv_store = FileStorage::new(
            env.test_path(),
            StorageType::PRIV,
            storage_prefix.as_deref(),
        )
        .unwrap();
        delete_at_request_and_epoch_id(
            &mut cur_priv_store,
            &req_key_id,
            &DEFAULT_EPOCH_ID,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
        delete_at_request_id(
            &mut cur_priv_store,
            &SIGNING_KEY_ID,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
    }

    // Execute the backup restore with corrupted custodian outputs. With threshold=2 of 5 custodians, the quorum
    // tolerates 2 bad shares.
    run_full_custodian_recovery(
        &kms_clients,
        &operator_verf_keys,
        custodian_context_id,
        env.mnemonics.clone(),
        n,
        Some(corrupt_custodian_outputs),
    )
    .await;

    // Signing keys must be back on disk, byte-equal to the originals — the corrupted
    // custodian outputs must not have changed what the recovery wrote.
    let recovered_sig_keys = read_signing_keys(env.test_path(), env.priv_prefixes()).await;
    assert_eq!(recovered_sig_keys, sig_keys);

    // Decryption succeeds means recovery worked despite the tampered custodian outputs.
    shutdown_servers(kms_servers).await;
    drop(kms_clients);
    let (mut kms_servers, mut kms_clients) = env.spawn_server_on_existing_material().await;
    let mut internal_client = env.create_internal_client(&dkg_param).await;
    run_decryption_threshold(
        n,
        &mut kms_servers,
        &mut kms_clients,
        &mut internal_client,
        None,
        &req_key_id,
        None,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        None,
        1,
        env.test_path(),
    )
    .await;
}

/// Test that PRSS data (PrssSetupCombined) is present in the custodian backup vault
/// after server startup with `ensure_default_prss: true`.
#[tokio::test(flavor = "multi_thread")]
async fn test_prss_in_custodian_backup_threshold() {
    let mut env =
        ThresholdBackupTestEnv::new("test_prss_in_custodian_backup_threshold", 3, 1).await;

    // PRSS is stored with epoch_id.into() as the request_id (non-epoched layout)
    let prss_req_id: RequestId = (*DEFAULT_EPOCH_ID).into();
    let backup: Vec<BackupCiphertext> = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &prss_req_id,
        &PrivDataType::PrssSetupCombined.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        backup.len(),
        ThresholdBackupTestEnv::AMOUNT_PARTIES,
        "Expected one PRSS backup entry per party"
    );
    for entry in &backup {
        assert_eq!(entry.priv_data_type, PrivDataType::PrssSetupCombined);
    }

    env.shutdown().await;
}

/// Test that FHE key material is present in the custodian backup vault
/// immediately after key generation (not just after recovery).
#[tokio::test(flavor = "multi_thread")]
async fn test_keygen_backup_presence_threshold() {
    let mut env = ThresholdBackupTestEnv::new("test_keygen_backup_presence_threshold", 3, 1).await;
    let req_key_id: RequestId =
        derive_request_id("test_keygen_backup_presence_threshold_key").unwrap();
    let preproc_id: RequestId =
        derive_request_id("test_keygen_backup_presence_threshold_preproc").unwrap();

    // Generate a key
    let (keyset_config, keyset_added_info) = uncompressed_keygen_config();
    run_insecure_preproc(env.kms_clients(), &preproc_id, FheParameter::Test)
        .await
        .unwrap();
    let _keys = run_threshold_keygen(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        &preproc_id,
        &req_key_id,
        keyset_config,
        keyset_added_info,
        true,
        env.test_path(),
        0,
    )
    .await;
    // Sleep briefly to allow backup to be written (since backup is done asynchronously after keygen)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Verify FHE key material appears in backup immediately after keygen
    let key_backup: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &req_key_id,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::FheKeyInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        key_backup.len(),
        ThresholdBackupTestEnv::AMOUNT_PARTIES,
        "Expected one FheKeyInfo backup entry per party after keygen"
    );
    for entry in &key_backup {
        assert_eq!(entry.priv_data_type, PrivDataType::FheKeyInfo);
    }

    env.shutdown().await;
}

/// Test that re-creating a custodian context with pre-existing key material
/// results in re-encrypted backup entries (different ciphertexts).
#[tokio::test(flavor = "multi_thread")]
async fn test_custodian_reencryption_with_existing_data_threshold() {
    // env already creates the first custodian context (env.req_new_cus)
    let mut env = ThresholdBackupTestEnv::new("test_custodian_reencryption_threshold", 3, 1).await;
    let req_cus_b: RequestId =
        derive_request_id("test_custodian_reencryption_threshold_cus_b").unwrap();
    let req_key_id: RequestId =
        derive_request_id("test_custodian_reencryption_threshold_key").unwrap();
    let preproc_id: RequestId =
        derive_request_id("test_custodian_reencryption_threshold_preproc").unwrap();

    // Generate a key
    let (keyset_config, keyset_added_info) = uncompressed_keygen_config();
    run_insecure_preproc(env.kms_clients(), &preproc_id, FheParameter::Test)
        .await
        .unwrap();
    let _keys = run_threshold_keygen(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        &preproc_id,
        &req_key_id,
        keyset_config,
        keyset_added_info,
        true,
        env.test_path(),
        0,
    )
    .await;
    // Sleep briefly to allow backup to be written (since backup is done asynchronously after generation)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Read backup under first custodian context
    let backup_a: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &req_key_id,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::FheKeyInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(backup_a.len(), ThresholdBackupTestEnv::AMOUNT_PARTIES);

    // Create second custodian context (triggers re-encryption of all backup data)
    let _mnemonics_b = run_new_cus_context(
        env.kms_clients.as_ref().unwrap(),
        env.internal_client.as_mut().unwrap(),
        &req_cus_b,
        3,
        1,
    )
    .await;

    // Read backup under second custodian context
    let backup_b: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &req_cus_b,
        &req_key_id,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::FheKeyInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        backup_b.len(),
        ThresholdBackupTestEnv::AMOUNT_PARTIES,
        "Expected backup entries under new custodian context after re-encryption"
    );

    // Verify ciphertexts differ (re-encrypted, not copied)
    for i in 0..ThresholdBackupTestEnv::AMOUNT_PARTIES {
        assert_ne!(
            backup_a[i].ciphertext, backup_b[i].ciphertext,
            "Backup ciphertexts should differ after custodian context change (party {i})"
        );
    }

    env.shutdown().await;
}

/// Test that creating a new MPC context results in the ContextInfo
/// being backed up in the custodian backup vault (threshold mode).
#[tokio::test(flavor = "multi_thread")]
async fn test_mpc_context_backup_threshold() {
    let mut env = ThresholdBackupTestEnv::new("test_mpc_context_backup_threshold", 3, 1).await;
    let n = ThresholdBackupTestEnv::AMOUNT_PARTIES;
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..n];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..n];

    // Build a new MPC context by cloning the default one
    let priv_store_0 = FileStorage::new(
        env.test_path(),
        StorageType::PRIV,
        priv_storage_prefixes[0].as_deref(),
    )
    .unwrap();
    let default_context: ContextInfo = read_context_at_id(&priv_store_0, &DEFAULT_MPC_CONTEXT)
        .await
        .unwrap();
    let new_context = {
        let mut ctx = default_context.clone();
        let mut rng = AesRng::seed_from_u64(99);
        let context_id = RequestId::new_random(&mut rng);
        ctx.context_id = context_id.into();
        // Fill in verification keys from public storage
        let all_pub_storage: Vec<FileStorage> = pub_storage_prefixes
            .iter()
            .map(|prefix| {
                FileStorage::new(env.test_path(), StorageType::PUB, prefix.as_deref()).unwrap()
            })
            .collect();
        for node in ctx.mpc_nodes.iter_mut() {
            let pk: PublicSigKey = read_versioned_at_request_id(
                &all_pub_storage[node.party_id as usize - 1],
                &SIGNING_KEY_ID,
                &PubDataType::VerfKey.to_string(),
            )
            .await
            .unwrap();
            node.signer_address = Some(SignerAddress(pk.address()));
            node.external_url = format!("http://example.com:8080/party{}", node.party_id);
        }
        ctx
    };
    let new_context_id = *new_context.context_id();

    // Send new MPC context to all parties
    {
        let req = env
            .internal_client
            .as_mut()
            .unwrap()
            .new_mpc_context_request(new_context)
            .unwrap();
        let mut req_tasks = JoinSet::new();
        for client in env.kms_clients().values() {
            let req_clone = req.clone();
            let mut client = client.clone();
            req_tasks.spawn(async move { client.new_mpc_context(req_clone).await });
        }
        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), env.kms_clients().len());
    }

    // Verify ContextInfo for the new context appears in backup
    let context_backup: Vec<BackupCiphertext> = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &new_context_id.into(),
        &PrivDataType::ContextInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        context_backup.len(),
        n,
        "Expected ContextInfo backup entry per party after new MPC context"
    );
    for entry in &context_backup {
        assert_eq!(entry.priv_data_type, PrivDataType::ContextInfo);
    }

    env.shutdown().await;
}

/// Test that backup contains reshared key material and CRS after an epoch
/// transition (reshare). This validates that `update_backup_vault` is called
/// after `store_reshared_keys` completes.
#[tokio::test(flavor = "multi_thread")]
async fn test_backup_after_reshare_threshold() {
    let mut env = ThresholdBackupTestEnv::new("test_backup_after_reshare_threshold", 3, 1).await;
    let n = ThresholdBackupTestEnv::AMOUNT_PARTIES;
    let req_key_id: RequestId =
        derive_request_id("test_backup_after_reshare_threshold_key").unwrap();
    let preproc_id: RequestId =
        derive_request_id("test_backup_after_reshare_threshold_preproc").unwrap();
    let crs_req: RequestId = derive_request_id("test_backup_after_reshare_threshold_crs").unwrap();
    let new_epoch_id: EpochId = derive_request_id("test_backup_after_reshare_threshold_epoch")
        .unwrap()
        .into();

    // Generate a key (so we have material to reshare)
    let (keyset_config, keyset_added_info) = uncompressed_keygen_config();
    run_insecure_preproc(env.kms_clients(), &preproc_id, FheParameter::Test)
        .await
        .unwrap();
    let (keyset, _) = run_threshold_keygen(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        &preproc_id,
        &req_key_id,
        keyset_config,
        keyset_added_info,
        true,
        env.test_path(),
        0,
    )
    .await;

    // Compute key digests needed for the reshare request
    let (_, public_key, server_key) = keyset.get_uncompressed();
    let server_key_digest = hash_versioned(&DSEP_PUBDATA_KEY, &server_key).unwrap();
    let public_key_digest = hash_versioned(&DSEP_PUBDATA_KEY, &public_key).unwrap();

    // Generate CRS (so we have CRS to reshare)
    let crs_info_vec = run_crs(
        FheParameter::Test,
        env.kms_clients(),
        env.internal_client(),
        true,
        &crs_req,
        Some(16),
        env.test_path(),
    )
    .await;
    assert_eq!(crs_info_vec.len(), 1);
    let crs_info_item = &crs_info_vec[0];
    // Sleep briefly to allow backup to be written (since backup is done asynchronously after generation)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Verify initial backup exists at default epoch before reshare
    let initial_key_backup: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &req_key_id,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::FheKeyInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        initial_key_backup.len(),
        n,
        "Expected initial FheKeyInfo backup before reshare"
    );

    // Build the reshare request
    let previous_epoch = PreviousEpochInfo {
        context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
        epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
        keys_info: vec![KeyInfo {
            key_id: Some(req_key_id.into()),
            preproc_id: Some(preproc_id.into()),
            key_parameters: FheParameter::Test.into(),
            key_digests: vec![
                kms_grpc::kms::v1::KeyDigest {
                    key_type: PubDataType::ServerKey.to_string(),
                    digest: server_key_digest,
                },
                kms_grpc::kms::v1::KeyDigest {
                    key_type: PubDataType::PublicKey.to_string(),
                    digest: public_key_digest,
                },
            ],
        }],
        crs_info: vec![CrsInfo {
            crs_id: crs_info_item.crs_id.clone(),
            crs_digest: crs_info_item.crs_digest.clone(),
        }],
    };

    let epoch_request = env
        .internal_client()
        .new_epoch_request(
            &DEFAULT_MPC_CONTEXT,
            &new_epoch_id,
            Some(previous_epoch),
            Some(&crate::dummy_domain()),
        )
        .unwrap();

    // Execute the reshare on all parties
    let mut tasks = JoinSet::new();
    for client in env.kms_clients().values() {
        let req = epoch_request.clone();
        let mut client = client.clone();
        tasks.spawn(async move { client.new_mpc_epoch(tonic::Request::new(req)).await });
    }
    for res in tasks.join_all().await {
        assert!(res.is_ok(), "Reshare failed: {:?}", res.err());
    }

    // Poll until reshare completes
    let new_epoch_req_id: RequestId = new_epoch_id.into();
    for client in env.kms_clients().values() {
        // Poll every 500ms for up to 50 tries before giving up.
        if let Err(e) = retrying_poll(
            client.clone(),
            new_epoch_req_id.into(),
            "reshare epoch result",
            PollConfig::default(),
            |client, request| Box::pin(async move { client.get_epoch_result(request).await }),
        )
        .await
        {
            panic!("Failed waiting for reshare to complete: {e:?}");
        }
    }

    // Verify that reshared FheKeyInfo appears in backup at the NEW epoch
    let reshared_key_backup: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &req_key_id,
        new_epoch_id,
        &PrivDataType::FheKeyInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        reshared_key_backup.len(),
        n,
        "Expected one FheKeyInfo backup entry per party at the new epoch after reshare"
    );
    for entry in &reshared_key_backup {
        assert_eq!(entry.priv_data_type, PrivDataType::FheKeyInfo);
    }

    // Verify that reshared CrsInfo appears in backup at the NEW epoch
    let crs_id: RequestId = crs_info_item.crs_id.as_ref().unwrap().try_into().unwrap();
    let reshared_crs_backup: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &crs_id,
        new_epoch_id,
        &PrivDataType::CrsInfo.to_string(),
        env.backup_prefixes(),
    )
    .await;
    assert_eq!(
        reshared_crs_backup.len(),
        n,
        "Expected one CrsInfo backup entry per party at the new epoch after reshare"
    );
    for entry in &reshared_crs_backup {
        assert_eq!(entry.priv_data_type, PrivDataType::CrsInfo);
    }

    env.shutdown().await;
}

async fn shutdown_servers(kms_servers: HashMap<u32, ServerHandle>) {
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
}
#[expect(clippy::type_complexity)]
async fn run_full_custodian_recovery(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    operator_verf_keys: &HashMap<u32, PublicSigKey>,
    custodian_context_id: RequestId,
    mnemonics: Vec<String>,
    amount_parties: usize,
    mutate_outputs: Option<fn(&mut HashMap<Address, (u32, CustodianRecoveryRequest)>)>,
) {
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = run_custodian_recovery_init(kms_clients).await;
    assert_eq!(recovery_req_resp.len(), amount_parties);
    let mut cus_out = emulate_custodian(
        &mut rng,
        recovery_req_resp,
        operator_verf_keys,
        custodian_context_id,
        mnemonics,
    )
    .await;
    if let Some(mutate) = mutate_outputs {
        mutate(&mut cus_out);
    }
    let recovery_output = run_custodian_backup_recovery(kms_clients, &cus_out).await;
    assert_eq!(recovery_output.len(), amount_parties);
    let res = run_restore_from_backup(kms_clients).await;
    assert_eq!(res.len(), amount_parties);
}
async fn read_signing_keys(
    test_path: Option<&std::path::Path>,
    priv_storage_prefixes: &[Option<String>],
) -> Vec<PrivateSigKey> {
    let mut sig_keys = Vec::new();
    for storage_prefix in priv_storage_prefixes.iter() {
        let cur_priv_store =
            FileStorage::new(test_path, StorageType::PRIV, storage_prefix.as_deref()).unwrap();
        let cur_sk: PrivateSigKey = read_versioned_at_request_id(
            &cur_priv_store,
            &SIGNING_KEY_ID,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        sig_keys.push(cur_sk);
    }
    sig_keys
}

#[cfg(feature = "testing")]
async fn operator_verf_key_map(
    test_path: Option<&std::path::Path>,
    pub_storage_prefixes: &[Option<String>],
) -> HashMap<u32, PublicSigKey> {
    let mut verf_keys = Vec::new();
    for storage_prefix in pub_storage_prefixes.iter() {
        let cur_pub_store =
            FileStorage::new(test_path, StorageType::PUB, storage_prefix.as_deref()).unwrap();
        let cur_pk: PublicSigKey = read_versioned_at_request_id(
            &cur_pub_store,
            &SIGNING_KEY_ID,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();
        verf_keys.push(cur_pk);
    }
    verf_keys
        .into_iter()
        .enumerate()
        .map(|(idx, pk)| ((idx + 1) as u32, pk))
        .collect()
}

// Right now only used by insecure tests
async fn run_custodian_recovery_init(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> Vec<(u32, RecoveryRequest)> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        tasks_gen.spawn(async move {
            (
                i,
                cur_client
                    .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
                        overwrite_ephemeral_key: false,
                    }))
                    .await,
            )
        });
    }
    let mut responses_gen = Vec::new();
    while let Some(inner) = tasks_gen.join_next().await {
        let resp = inner.unwrap();
        responses_gen.push(resp);
    }
    assert_eq!(responses_gen.len(), amount_parties);
    let mut res = Vec::new();
    for (i, response) in responses_gen {
        assert!(response.is_ok());
        res.push((i, response.unwrap().into_inner()));
    }
    res
}

// Right now only used by insecure tests
async fn run_custodian_backup_recovery(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    reqs: &HashMap<Address, (u32, CustodianRecoveryRequest)>,
) -> Vec<Empty> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for (client_id, req) in reqs.values() {
        let mut cur_client = kms_clients.get(client_id).unwrap().clone();
        let req_clone = req.clone();
        tasks_gen.spawn(async move {
            cur_client
                .custodian_backup_recovery(tonic::Request::new(req_clone))
                .await
        });
    }

    let mut responses_gen = Vec::new();
    while let Some(inner) = tasks_gen.join_next().await {
        let resp = inner.unwrap();
        responses_gen.push(resp);
    }
    assert_eq!(responses_gen.len(), amount_parties);
    let mut res = Vec::new();
    for response in responses_gen {
        assert!(response.is_ok());
        res.push(response.unwrap().into_inner());
    }
    res
}

// Right now only used by insecure tests
async fn run_restore_from_backup(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> Vec<Empty> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        tasks_gen.spawn(async move {
            cur_client
                .restore_from_backup(tonic::Request::new(Empty {}))
                .await
        });
    }
    let mut responses_gen = Vec::new();
    while let Some(inner) = tasks_gen.join_next().await {
        let resp = inner.unwrap();
        responses_gen.push(resp);
    }
    assert_eq!(responses_gen.len(), amount_parties);
    let mut res = Vec::new();
    for response in responses_gen {
        assert!(response.is_ok());
        res.push(response.unwrap().into_inner());
    }
    res
}

// Right now only used by insecure tests
async fn emulate_custodian(
    rng: &mut AesRng,
    recovery_requests: Vec<(u32, RecoveryRequest)>,
    operator_verf_keys: &HashMap<u32, PublicSigKey>,
    custodian_context_id: RequestId,
    mnemonics: Vec<String>,
) -> HashMap<Address, (u32, CustodianRecoveryRequest)> {
    // Setup a map to contain the results for each operator role
    let mut outputs_for_operators: HashMap<(u32, Address), Vec<CustodianRecoveryOutput>> =
        HashMap::new();

    for (cur_idx, cur_mnemonic) in mnemonics.iter().enumerate() {
        let custodian: Custodian =
            custodian_from_seed_phrase(cur_mnemonic, Role::indexed_from_zero(cur_idx)).unwrap();
        for (i, cur_recovery_req) in &recovery_requests {
            let cur_verf_key = operator_verf_keys
                .get(i)
                .expect("operator verification key missing for party {cur_idx}");
            let cur_cus_reenc = cur_recovery_req.cts.get(&((cur_idx + 1) as u64)).unwrap();
            let cur_enc_key = safe_deserialize(
                std::io::Cursor::new(&cur_recovery_req.ephem_op_enc_key),
                SAFE_SER_SIZE_LIMIT,
            )
            .unwrap();
            let cur_out = custodian
                .verify_reencrypt(
                    rng,
                    &cur_cus_reenc.to_owned().try_into().unwrap(),
                    cur_verf_key,
                    &cur_enc_key,
                )
                .unwrap();
            // Add the result from this custodian to the map of results to the correct operator
            match outputs_for_operators.entry((*i, cur_verf_key.address())) {
                std::collections::hash_map::Entry::Occupied(occupied_entry) => {
                    occupied_entry.into_mut().push(cur_out.try_into().unwrap());
                }
                std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(vec![cur_out.try_into().unwrap()]);
                }
            };
        }
    }
    outputs_for_operators
        .into_iter()
        .map(|((i, k), v)| {
            (
                k,
                (
                    i,
                    CustodianRecoveryRequest {
                        custodian_context_id: Some(custodian_context_id.into()),
                        custodian_recovery_outputs: v,
                    },
                ),
            )
        })
        .collect::<HashMap<Address, (u32, CustodianRecoveryRequest)>>()
}
