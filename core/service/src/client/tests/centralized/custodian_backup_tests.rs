use crate::backup::BackupCiphertext;
use crate::backup::custodian::Custodian;
use crate::backup::seed_phrase::custodian_from_seed_phrase;
use crate::client::client_wasm::Client;
use crate::client::test_tools::{ServerHandle, centralized_custodian_handles};
#[cfg(feature = "insecure")]
use crate::client::tests::centralized::crs_gen_tests::run_crs_centralized;
use crate::client::tests::centralized::custodian_context_tests::run_new_cus_context;
use crate::client::tests::centralized::key_gen_tests::run_key_gen_centralized;
use crate::client::tests::centralized::public_decryption_tests::run_decryption_centralized;
use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey};
use crate::engine::context::ContextInfo;
use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
use crate::util::key_setup::test_tools::{
    purge_backup, read_custodian_backup_files, read_custodian_backup_files_with_epoch,
};
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{StorageType, read_context_at_id, read_versioned_at_request_id};
use crate::{
    client::tests::common::TIME_TO_SLEEP_MS, cryptography::internal_crypto_types::WrappedDKGParams,
    engine::base::derive_request_id, util::key_setup::test_tools::purge_priv,
};
use aes_prng::AesRng;
use kms_grpc::kms::v1::{
    CustodianRecoveryInitRequest, CustodianRecoveryRequest, Empty, RecoveryRequest,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{RequestId, kms::v1::FheParameter, rpc_types::PrivDataType};
use rand::SeedableRng;
use serial_test::serial;
use std::path::Path;
use tfhe::safe_serialization::safe_deserialize;
use threshold_types::role::Role;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Common test scaffolding
// ---------------------------------------------------------------------------

/// Shared environment for centralized custodian-backup tests.
///
/// Spins up a single centralized KMS server with custodian backup enabled and
/// creates an initial custodian context.
struct CentralizedBackupTestEnv {
    kms_server: Option<ServerHandle>,
    kms_client: Option<CoreServiceEndpointClient<Channel>>,
    internal_client: Option<Client>,
    mnemonics: Vec<String>,
    req_new_cus: RequestId,
    temp_dir: tempfile::TempDir,
}

impl CentralizedBackupTestEnv {
    async fn new(test_name: &str, amount_custodians: usize, threshold: u32) -> Self {
        let dkg_param: WrappedDKGParams = FheParameter::Test.into();
        let temp_dir = tempfile::tempdir().unwrap();
        let test_path = Some(temp_dir.path());
        let req_new_cus: RequestId = derive_request_id(test_name).unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client, mut internal_client) =
            centralized_custodian_handles(&dkg_param, None, test_path, None, None).await;
        let mnemonics = run_new_cus_context(
            &mut kms_client,
            &mut internal_client,
            &req_new_cus,
            amount_custodians,
            threshold,
        )
        .await;

        Self {
            kms_server: Some(kms_server),
            kms_client: Some(kms_client),
            internal_client: Some(internal_client),
            mnemonics,
            req_new_cus,
            temp_dir,
        }
    }

    fn test_path(&self) -> Option<&Path> {
        Some(self.temp_dir.path())
    }

    /// Shut down server and drop clients. The env remains usable for
    /// `test_path()`, `req_new_cus`, `mnemonics`, etc.
    async fn shutdown(&mut self) {
        self.kms_client.take();
        self.internal_client.take();
        if let Some(server) = self.kms_server.take() {
            server.assert_shutdown().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_auto_update_backups_central() {
    auto_update_backup(5, 2).await;
}

async fn auto_update_backup(amount_custodians: usize, threshold: u32) {
    let mut env = CentralizedBackupTestEnv::new(
        &format!("auto_update_backup_central_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;

    // Check that signing key was backed up, since it will always be there
    let _non_custodian_backup = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        &[None],
    )
    .await;

    env.shutdown().await;

    // Purge backup
    purge_backup(env.test_path(), &[None]).await;

    // Check that the backup is still there after reboot
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    let (_kms_server, _kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, env.test_path(), None, None).await;
    let _reread_backup = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        &[None],
    )
    .await;
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_backup_after_crs_central() {
    backup_after_crs(5, 2).await;
}

#[cfg(feature = "insecure")]
async fn backup_after_crs(amount_custodians: usize, threshold: u32) {
    let mut env = CentralizedBackupTestEnv::new(
        &format!("backup_after_crs_central_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;
    let crs_req: RequestId = derive_request_id(&format!(
        "backup_after_crs_central_crs_{amount_custodians}_{threshold}"
    ))
    .unwrap();

    run_crs_centralized(
        env.kms_client.as_mut().unwrap(),
        env.internal_client.as_ref().unwrap(),
        &crs_req,
        FheParameter::Test,
        true,
        Some(env.temp_dir.path()),
    )
    .await;

    // Check that the new CRS was backed up
    let crss = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &crs_req,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::CrsInfo.to_string(),
        &[None],
    )
    .await;
    assert!(crss[0].priv_data_type == PrivDataType::CrsInfo);

    env.shutdown().await;

    // Check that the backup is still there and unmodified after reboot
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    let (_kms_server, _kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, env.test_path(), None, None).await;
    let reread_crss = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &crs_req,
        *DEFAULT_EPOCH_ID,
        &PrivDataType::CrsInfo.to_string(),
        &[None],
    )
    .await;
    assert_eq!(reread_crss, crss);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_decrypt_after_recovery_central() {
    decrypt_after_recovery(5, 2).await;
}

async fn decrypt_after_recovery(amount_custodians: usize, threshold: u32) {
    let mut env = CentralizedBackupTestEnv::new(
        &format!("decrypt_after_recovery_central_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;
    let key_id: RequestId = derive_request_id(&format!(
        "decrypt_after_recovery_central_key_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let epoch_id = *DEFAULT_EPOCH_ID;

    run_key_gen_centralized(
        env.kms_client.as_mut().unwrap(),
        env.internal_client.as_ref().unwrap(),
        &key_id,
        &epoch_id,
        FheParameter::Test,
        None,
        None,
        Some(env.temp_dir.path()),
    )
    .await;

    env.shutdown().await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();

    // Read the private signing key for reference
    let priv_store = FileStorage::new(env.test_path(), StorageType::PRIV, None).unwrap();
    let sig_key: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();

    // Purge the private storage to test the backup
    purge_priv(env.test_path(), &[None]).await;

    // Reboot the servers
    let (kms_server, mut kms_client, internal_client) =
        centralized_custodian_handles(&dkg_param, None, env.test_path(), None, None).await;
    // Purge the private storage again to delete the signing key
    purge_priv(env.test_path(), &[None]).await;

    // Execute the backup restoring
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = kms_client
        .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
            overwrite_ephemeral_key: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let cus_rec_req = emulate_custodian(
        &mut rng,
        recovery_req_resp,
        env.mnemonics.clone(),
        env.test_path(),
    )
    .await;
    let _recovery_output = kms_client
        .custodian_backup_recovery(tonic::Request::new(cus_rec_req))
        .await
        .unwrap();
    let _restore_output = kms_client
        .restore_from_backup(tonic::Request::new(Empty {}))
        .await
        .unwrap();

    // Check that the key material is back
    let sk: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(sk, sig_key);

    kms_server.assert_shutdown().await;
    drop(kms_client);
    drop(internal_client);
    let (_kms_server, kms_client, mut internal_client) =
        centralized_custodian_handles(&dkg_param, None, env.test_path(), None, None).await;

    // Check the data is correctly recovered
    run_decryption_centralized(
        &kms_client,
        &mut internal_client,
        &key_id,
        None,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        1,
        env.test_path(),
    )
    .await;
}

/// Two custodians submit corrupted signcryption; those outputs are rejected and recovery still
/// completes with the remaining valid shares (see `assert_eq!(sig_key, new_sig_key)` at end).
#[tokio::test]
#[serial]
async fn test_decrypt_after_recovery_centralized_negative() {
    decrypt_after_recovery_negative(5, 2).await;
}

async fn decrypt_after_recovery_negative(amount_custodians: usize, threshold: u32) {
    let mut env = CentralizedBackupTestEnv::new(
        &format!("decrypt_after_recovery_central_negative_{amount_custodians}_{threshold}"),
        amount_custodians,
        threshold,
    )
    .await;

    env.shutdown().await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();

    // Read the private signing key for reference
    let priv_store = FileStorage::new(env.test_path(), StorageType::PRIV, None).unwrap();
    let sig_key: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();

    // Purge the private storage to test the backup
    purge_priv(env.test_path(), &[None]).await;

    // Reboot the servers
    let (_kms_server, mut kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, env.test_path(), None, None).await;
    // Purge the private storage again to delete the signing key
    purge_priv(env.test_path(), &[None]).await;

    // Execute the backup restoring
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = kms_client
        .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
            overwrite_ephemeral_key: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let mut cus_rec_req = emulate_custodian(
        &mut rng,
        recovery_req_resp,
        env.mnemonics.clone(),
        env.test_path(),
    )
    .await;
    // Change a bit in two of the custodians contribution to the recover requests to make them invalid
    // First custodian 1
    cus_rec_req
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
    cus_rec_req
        .custodian_recovery_outputs
        .get_mut(2)
        .map(|inner| {
            inner
                .backup_output
                .as_mut()
                // Flip a bit in the 7th byte
                .map(|back_out| back_out.signcryption[7] ^= 1)
        });
    let _recovery_output = kms_client
        .custodian_backup_recovery(tonic::Request::new(cus_rec_req))
        .await
        .unwrap();
    let _restore_output = kms_client
        .restore_from_backup(tonic::Request::new(Empty {}))
        .await
        .unwrap();

    // Check that the key material is back
    let new_sig_key: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    // Check the data is correctly recovered
    assert_eq!(sig_key, new_sig_key);
}

/// Test that FHE key material is present in the custodian backup vault
/// immediately after key generation (centralized mode).
#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_keygen_backup_presence_central() {
    let mut env = CentralizedBackupTestEnv::new("test_keygen_backup_presence_central", 3, 1).await;
    let key_id: RequestId = derive_request_id("test_keygen_backup_presence_central_key").unwrap();
    let epoch_id = *DEFAULT_EPOCH_ID;

    run_key_gen_centralized(
        env.kms_client.as_mut().unwrap(),
        env.internal_client.as_ref().unwrap(),
        &key_id,
        &epoch_id,
        FheParameter::Test,
        None,
        None,
        Some(env.temp_dir.path()),
    )
    .await;

    // Verify FHE key material appears in backup immediately after keygen
    let key_backup: Vec<BackupCiphertext> = read_custodian_backup_files_with_epoch(
        env.test_path(),
        &env.req_new_cus,
        &key_id,
        epoch_id,
        &PrivDataType::FhePrivateKey.to_string(),
        &[None],
    )
    .await;
    assert_eq!(
        key_backup.len(),
        1,
        "Expected one FhePrivateKey backup entry for centralized mode"
    );
    assert_eq!(key_backup[0].priv_data_type, PrivDataType::FhePrivateKey);

    env.shutdown().await;
}

/// Test that creating a new MPC context results in the ContextInfo
/// being backed up in the custodian backup vault (centralized mode).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_mpc_context_backup_central() {
    let mut env = CentralizedBackupTestEnv::new("test_mpc_context_backup_central", 3, 1).await;

    // Build a new MPC context by cloning the default one
    let priv_store = FileStorage::new(env.test_path(), StorageType::PRIV, None).unwrap();
    let default_context: ContextInfo = read_context_at_id(&priv_store, &DEFAULT_MPC_CONTEXT)
        .await
        .unwrap();
    let new_context = {
        let mut ctx = default_context.clone();
        let mut rng = AesRng::seed_from_u64(42);
        let context_id = kms_grpc::RequestId::new_random(&mut rng);
        ctx.context_id = context_id.into();
        // Fill in verification key from public storage
        let pub_store = FileStorage::new(env.test_path(), StorageType::PUB, None).unwrap();
        for node in ctx.mpc_nodes.iter_mut() {
            let pk: PublicSigKey = read_versioned_at_request_id(
                &pub_store,
                &SIGNING_KEY_ID,
                &PubDataType::VerfKey.to_string(),
            )
            .await
            .unwrap();
            node.verification_key = Some(pk);
            node.external_url = "http://fake.url:8080".to_string();
        }
        ctx
    };
    let new_context_id = *new_context.context_id();

    // Send new MPC context
    let req = env
        .internal_client
        .as_mut()
        .unwrap()
        .new_mpc_context_request(new_context)
        .unwrap();
    env.kms_client
        .as_mut()
        .unwrap()
        .new_mpc_context(tonic::Request::new(req))
        .await
        .unwrap();

    // Verify ContextInfo for the new context appears in backup
    let context_backup: Vec<BackupCiphertext> = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &new_context_id.into(),
        &PrivDataType::ContextInfo.to_string(),
        &[None],
    )
    .await;
    assert_eq!(
        context_backup.len(),
        1,
        "Expected ContextInfo backup entry after new MPC context"
    );
    assert_eq!(context_backup[0].priv_data_type, PrivDataType::ContextInfo);

    env.shutdown().await;
}

async fn emulate_custodian(
    rng: &mut AesRng,
    recovery_request: RecoveryRequest,
    mnemonics: Vec<String>,
    test_path: Option<&Path>,
) -> CustodianRecoveryRequest {
    let backup_id = recovery_request.backup_id.clone().unwrap();
    let mut cus_outputs = Vec::new();
    for (cur_idx, cur_mnemonic) in mnemonics.iter().enumerate() {
        let custodian: Custodian =
            custodian_from_seed_phrase(cur_mnemonic, Role::indexed_from_zero(cur_idx)).unwrap();
        let pub_storage = FileStorage::new(test_path, StorageType::PUB, None).unwrap();
        let verf_key = read_versioned_at_request_id(
            &pub_storage,
            &SIGNING_KEY_ID,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();
        let cur_cus_reenc = recovery_request.cts.get(&((cur_idx + 1) as u64)).unwrap();
        let cur_enc_key = safe_deserialize(
            std::io::Cursor::new(&recovery_request.ephem_op_enc_key),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let cur_out = custodian
            .verify_reencrypt(
                rng,
                &cur_cus_reenc.to_owned().try_into().unwrap(),
                &verf_key,
                &cur_enc_key,
                backup_id.clone().try_into().unwrap(),
            )
            .unwrap();
        // Add the result from this custodian to the map of results to the correct operator
        cus_outputs.push(cur_out.try_into().unwrap());
    }
    CustodianRecoveryRequest {
        custodian_context_id: Some(backup_id.clone()),
        custodian_recovery_outputs: cus_outputs,
    }
}
