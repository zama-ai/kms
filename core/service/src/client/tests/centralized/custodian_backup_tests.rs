use crate::backup::custodian::Custodian;
use crate::backup::operator::InternalRecoveryRequest;
use crate::backup::seed_phrase::custodian_from_seed_phrase;
use crate::client::test_tools::centralized_custodian_handles;
#[cfg(feature = "insecure")]
use crate::client::tests::centralized::crs_gen_tests::run_crs_centralized;
use crate::client::tests::centralized::custodian_context_tests::run_new_cus_context;
use crate::client::tests::centralized::key_gen_tests::run_key_gen_centralized;
use crate::client::tests::centralized::public_decryption_tests::run_decryption_centralized;
use crate::consts::{SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::util::key_setup::test_tools::{purge_backup, read_backup_files};
use crate::util::key_setup::test_tools::{EncryptionConfig, TestingPlaintext};
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{read_versioned_at_request_id, StorageType};
use crate::{
    client::tests::common::TIME_TO_SLEEP_MS, cryptography::internal_crypto_types::WrappedDKGParams,
    engine::base::derive_request_id, util::key_setup::test_tools::purge_priv,
};
use aes_prng::AesRng;
use kms_grpc::kms::v1::{
    CustodianRecoveryInitRequest, CustodianRecoveryRequest, Empty, RecoveryRequest,
};
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{kms::v1::FheParameter, rpc_types::PrivDataType, RequestId};
use rand::SeedableRng;
use serial_test::serial;
use std::path::Path;
use tfhe::safe_serialization::safe_deserialize;
use threshold_fhe::execution::runtime::party::Role;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_auto_update_backups_central() {
    auto_update_backup(5, 2).await;
}

async fn auto_update_backup(amount_custodians: usize, threshold: u32) {
    let req_new_cus: RequestId = derive_request_id(&format!(
        "auto_update_backup_central_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, mut internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let _mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    // Check that signing key was backed up, since it will always be there
    let _non_custodian_backup = read_backup_files(
        1,
        test_path,
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;

    // Shut down the servers
    kms_server.assert_shutdown().await;
    drop(kms_client);
    drop(internal_client);

    // Purge backup
    purge_backup(test_path, 1).await;

    // Check that the backup is still there
    let (_kms_server, _kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let _reread_backup = read_backup_files(
        1,
        test_path,
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
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
    let param = FheParameter::Test;
    let dkg_param: WrappedDKGParams = param.into();
    let req_new_cus: RequestId = derive_request_id(&format!(
        "test_backup_after_crs_central_cus_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let crs_req: RequestId = derive_request_id(&format!(
        "test_backup_after_crs_central_crs_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());

    // Generate a new crs
    let (kms_server, mut kms_client, mut internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let _mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    run_crs_centralized(
        &mut kms_client,
        &internal_client,
        &crs_req,
        param,
        true,
        test_path,
    )
    .await;
    // Check that the new CRS was backed up
    let crss = read_backup_files(
        1,
        test_path,
        &req_new_cus,
        &crs_req,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await;
    // Check that the format is correct
    assert!(crss[0].priv_data_type == PrivDataType::CrsInfo);

    drop(kms_client);
    drop(internal_client);
    // Shut down the servers
    kms_server.assert_shutdown().await;
    // Check that the backup is still there and unmodified
    let (_kms_server, _kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let reread_crss = read_backup_files(
        1,
        test_path,
        &req_new_cus,
        &crs_req,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await;
    assert_eq!(reread_crss, crss);
}

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_decrypt_after_recovery_central() {
    decrypt_after_recovery(5, 2).await;
}

async fn decrypt_after_recovery(amount_custodians: usize, threshold: u32) {
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    let req_new_cus: RequestId =
        derive_request_id("test_decrypt_after_recovery_central_cus").unwrap();
    let key_id: RequestId = derive_request_id("test_decrypt_after_recovery_central_key").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());

    let (kms_server, mut kms_client, mut internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    run_key_gen_centralized(
        &mut kms_client,
        &internal_client,
        &key_id,
        FheParameter::Test,
        None,
        None,
        test_path,
    )
    .await;
    // Shut down the servers
    kms_server.assert_shutdown().await;
    drop(kms_client);
    drop(internal_client);

    // Read the private signing key for reference
    let priv_store = FileStorage::new(test_path, StorageType::PRIV, None).unwrap();
    let sig_key: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();

    // Purge the private storage to tests the backup
    purge_priv(test_path).await;

    // Reboot the servers
    let (kms_server, mut kms_client, internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    // Purge the private storage again to delete the signing key
    purge_priv(test_path).await;

    // Execute the backup restoring
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = kms_client
        .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
            overwrite_ephemeral_key: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let cus_rec_req = emulate_custodian(&mut rng, recovery_req_resp, mnemnonics, test_path).await;
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
        centralized_custodian_handles(&dkg_param, None, test_path).await;

    // Check the data is correctly recovered
    run_decryption_centralized(
        &kms_client,
        &mut internal_client,
        &key_id,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        1,
        test_path,
    )
    .await;
}

#[tokio::test]
#[tracing_test::traced_test]
#[serial]
async fn test_decrypt_after_recovery_centralized_negative() {
    decrypt_after_recovery_negative(5, 2).await;
    assert!(logs_contain(
        "Could not verify recovery validation material signature for custodian role 1"
    ));
    assert!(logs_contain(
        "Could not verify recovery validation material signature for custodian role 3"
    ));
}

async fn decrypt_after_recovery_negative(amount_custodians: usize, threshold: u32) {
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    let req_new_cus: RequestId =
        derive_request_id("test_decrypt_after_recovery_centralized_negative").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());

    let (kms_server, mut kms_client, mut internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;

    // Shut down the servers
    kms_server.assert_shutdown().await;
    drop(kms_client);
    drop(internal_client);

    // Read the private signing key for reference
    let priv_store = FileStorage::new(test_path, StorageType::PRIV, None).unwrap();
    let sig_key: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();

    // Purge the private storage to tests the backup
    purge_priv(test_path).await;

    // Reboot the servers
    let (_kms_server, mut kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    // Purge the private storage again to delete the signing key
    purge_priv(test_path).await;

    // Execute the backup restoring
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = kms_client
        .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
            overwrite_ephemeral_key: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let mut cus_rec_req =
        emulate_custodian(&mut rng, recovery_req_resp, mnemnonics, test_path).await;
    // Change a bit in two of the custodians contribution to the recover requests to make them invalid
    // First custodian 1
    cus_rec_req
        .custodian_recovery_outputs
        .get_mut(0)
        .unwrap()
        // Flip a bit in the 11th byte
        .ciphertext[11] ^= 1;
    // Then in custodian 3
    cus_rec_req
        .custodian_recovery_outputs
        .get_mut(2)
        .unwrap()
        // Flip a bit in the 7th byte
        .ciphertext[7] ^= 1;
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
        let internal_recovery_req: InternalRecoveryRequest =
            recovery_request.to_owned().try_into().unwrap();
        assert!(internal_recovery_req.is_valid(&verf_key).unwrap());
        let cur_cus_reenc = recovery_request.cts.get(&((cur_idx + 1) as u64)).unwrap();
        let cur_enc_key = safe_deserialize(
            std::io::Cursor::new(&recovery_request.enc_key),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let cur_out = custodian
            .verify_reencrypt(
                rng,
                &cur_cus_reenc.to_owned().into(),
                &verf_key,
                &cur_enc_key,
                backup_id.clone().try_into().unwrap(),
                Role::indexed_from_one(recovery_request.operator_role as usize),
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
