use crate::backup::BackupCiphertext;
use crate::backup::custodian::Custodian;
use crate::backup::seed_phrase::custodian_from_seed_phrase;
use crate::client::client_wasm::Client;
use crate::client::test_tools::ServerHandle;
use crate::client::tests::centralized::crs_gen_tests::run_crs_centralized;
use crate::client::tests::centralized::custodian_context_tests::run_new_cus_context;
use crate::client::tests::centralized::key_gen_tests::run_key_gen_centralized;
use crate::client::tests::centralized::public_decryption_tests::run_decryption_centralized;
use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
use crate::cryptography::signatures::PublicSigKey;
use crate::engine::context::{ContextInfo, SignerAddress};
use crate::testing::setup::CentralizedTestEnv;
use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
use crate::util::key_setup::test_tools::{
    purge_backup, read_custodian_backup_files, read_custodian_backup_files_with_epoch,
};
use crate::vault::storage::crypto_material::data_exists_at_epoch;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{
    StorageType, delete_at_request_and_epoch_id, read_context_at_id, read_versioned_at_request_id,
};
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
};
use aes_prng::AesRng;
use kms_grpc::kms::v1::{
    CustodianRecoveryInitRequest, CustodianRecoveryRequest, Empty, RecoveryRequest,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{RequestId, kms::v1::FheParameter, rpc_types::PrivDataType};
use rand::SeedableRng;
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
    material_dir: tempfile::TempDir,
}

impl CentralizedBackupTestEnv {
    async fn new(test_name: &str, amount_custodians: usize, threshold: u32) -> Self {
        let dkg_param: WrappedDKGParams = FheParameter::Test.into();
        let req_new_cus: RequestId = derive_request_id(test_name).unwrap();

        let test_env = CentralizedTestEnv::builder()
            .with_test_name(test_name)
            .with_custodian_keychain()
            .build()
            .await
            .unwrap();
        let mut internal_client = test_env.create_internal_client(&dkg_param).await.unwrap();
        let CentralizedTestEnv {
            material_dir,
            server: kms_server,
            client: mut kms_client,
        } = test_env;
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
            material_dir,
        }
    }

    fn test_path(&self) -> Option<&Path> {
        Some(self.material_dir.path())
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

    /// Spawn a fresh KMS server attached to this env's material directory. Use to assert state persists across server
    /// lifetimes. The wrapper must outlive the returned pair.
    async fn spawn_server_on_existing_material(
        &self,
    ) -> (ServerHandle, CoreServiceEndpointClient<Channel>) {
        CentralizedTestEnv::builder()
            .with_custodian_keychain()
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
        let pub_storage = FileStorage::new(Some(path), StorageType::PUB, None).unwrap();
        let client_storage = FileStorage::new(Some(path), StorageType::CLIENT, None).unwrap();
        Client::new_client(
            client_storage,
            std::collections::HashMap::from([(1u32, pub_storage)]),
            dkg_param,
            None,
        )
        .await
        .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
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
    let (_kms_server, _kms_client) = env.spawn_server_on_existing_material().await;
    let _reread_backup = read_custodian_backup_files(
        env.test_path(),
        &env.req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        &[None],
    )
    .await;
}
#[tokio::test(flavor = "multi_thread")]
async fn test_backup_after_crs_central() {
    backup_after_crs(5, 2).await;
}
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
        Some(env.material_dir.path()),
    )
    .await;
    // Sleep briefly to allow backup to be written (since backup is done asynchronously after generation)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
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
    let (_kms_server, _kms_client) = env.spawn_server_on_existing_material().await;
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
        Some(env.material_dir.path()),
    )
    .await;

    env.shutdown().await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();

    // Delete only the FHE private key for this `key_id`, leaving signing keys intact so the server can boot without
    // help. The test then verifies that custodian backup recovery restores the deleted FHE key (proven by a successful
    // decryption call at the end).
    let mut priv_storage = FileStorage::new(env.test_path(), StorageType::PRIV, None).unwrap();
    delete_at_request_and_epoch_id(
        &mut priv_storage,
        &key_id,
        &epoch_id,
        &PrivDataType::FhePrivateKey.to_string(),
    )
    .await
    .unwrap();
    // Sanity check that the key is indeed gone.
    assert!(
        !data_exists_at_epoch(
            &priv_storage,
            &key_id,
            &epoch_id,
            &PrivDataType::FhePrivateKey.to_string()
        )
        .await
        .unwrap()
    );

    // Reboot the server.
    let (kms_server, mut kms_client) = env.spawn_server_on_existing_material().await;

    // Execute the backup restoring.
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
        env.req_new_cus,
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

    // Decryption succeeds only if the FHE private key was correctly restored
    // by the custodian recovery + restore_from_backup calls above.
    kms_server.assert_shutdown().await;
    drop(kms_client);
    let (_kms_server, kms_client) = env.spawn_server_on_existing_material().await;
    let mut internal_client = env.create_internal_client(&dkg_param).await;
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
/// completes with the remaining valid shares — proven by a successful decryption call on a
/// recovered FHE private key at the end.
#[tokio::test]
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
    let key_id: RequestId = derive_request_id(&format!(
        "decrypt_after_recovery_central_negative_key_{amount_custodians}_{threshold}"
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
        Some(env.material_dir.path()),
    )
    .await;

    env.shutdown().await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();

    // Delete the FHE privkey. Leave the signing keys so the server can reboot.
    let mut priv_storage = FileStorage::new(env.test_path(), StorageType::PRIV, None).unwrap();
    delete_at_request_and_epoch_id(
        &mut priv_storage,
        &key_id,
        &epoch_id,
        &PrivDataType::FhePrivateKey.to_string(),
    )
    .await
    .unwrap();

    let (kms_server, mut kms_client) = env.spawn_server_on_existing_material().await;

    // Tamper with two of the five custodian recovery outputs. Recovery must
    // still succeed because threshold=2 allows for 2 invalid contributions.
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
        env.req_new_cus,
        env.mnemonics.clone(),
        env.test_path(),
    )
    .await;
    // Flip a bit in custodian #1's signcryption (byte 11).
    cus_rec_req
        .custodian_recovery_outputs
        .get_mut(0)
        .map(|inner| {
            inner
                .backup_output
                .as_mut()
                .map(|back_out| back_out.signcryption[11] ^= 1)
        });
    // Flip a bit in custodian #3's signcryption (byte 7).
    cus_rec_req
        .custodian_recovery_outputs
        .get_mut(2)
        .map(|inner| {
            inner
                .backup_output
                .as_mut()
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

    // Decryption succeeds means that the recovered FHE private key is correct even with the tampered custodian outputs
    // from the quorum.
    kms_server.assert_shutdown().await;
    drop(kms_client);
    let (_kms_server, kms_client) = env.spawn_server_on_existing_material().await;
    let mut internal_client = env.create_internal_client(&dkg_param).await;
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

/// Test that FHE key material is present in the custodian backup vault
/// immediately after key generation (centralized mode).
#[tokio::test(flavor = "multi_thread")]
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
        Some(env.material_dir.path()),
    )
    .await;
    // Sleep briefly to allow backup to be written (since backup is done asynchronously after keygen)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
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
            node.signer_address = Some(SignerAddress(pk.address()));
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
    custodian_context_id: RequestId,
    mnemonics: Vec<String>,
    test_path: Option<&Path>,
) -> CustodianRecoveryRequest {
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
            )
            .unwrap();
        // Add the result from this custodian to the map of results to the correct operator
        cus_outputs.push(cur_out.try_into().unwrap());
    }
    CustodianRecoveryRequest {
        custodian_context_id: Some(custodian_context_id.into()),
        custodian_recovery_outputs: cus_outputs,
    }
}
