use crate::backup::custodian::Custodian;
use crate::backup::operator::InternalRecoveryRequest;
use crate::backup::seed_phrase::custodian_from_seed_phrase;
#[cfg(feature = "insecure")]
use crate::client::tests::centralized::crs_gen_tests::run_crs_centralized;
use crate::client::tests::centralized::custodian_context_tests::{
    backup_files, run_new_cus_context,
};
use crate::consts::{SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
use crate::cryptography::backup_pke::BackupPrivateKey;
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::util::key_setup::test_tools::purge;
use crate::util::key_setup::test_tools::{purge_backup, purge_recovery_info};
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{read_versioned_at_request_id, StorageType};
use crate::{
    client::tests::common::TIME_TO_SLEEP_MS,
    cryptography::{backup_pke::BackupCiphertext, internal_crypto_types::WrappedDKGParams},
    engine::base::derive_request_id,
    util::key_setup::test_tools::purge_priv,
};
use aes_prng::AesRng;
use kms_grpc::kms::v1::{CustodianRecoveryRequest, Empty, RecoveryRequest};
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{kms::v1::FheParameter, rpc_types::PrivDataType, RequestId};
use rand::SeedableRng;
use serial_test::serial;
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
    purge(None, None, None, &req_new_cus, 1).await;
    // Clean up backups to not interfere with test
    purge_backup(None, 1).await;
    purge_recovery_info(None, 1).await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, mut internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    let _mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    // Check that signing key was backed up, since it will always be there
    let _non_custodian_backup: BackupCiphertext = backup_files(
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;

    // Shut down the servers
    drop(kms_server);
    drop(kms_client);
    drop(internal_client);

    // Purge backup
    purge_backup(None, 1).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Check that the backup is still there
    let (_kms_server, _kms_client, _internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    let _reread_backup = backup_files(
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
    purge(None, None, None, &crs_req, 1).await;
    purge(None, None, None, &req_new_cus, 1).await;
    // Clean up backups to not interfere with test
    purge_backup(None, 1).await;
    purge_recovery_info(None, 1).await;

    // Generate a new crs
    let (_kms_server, mut kms_client, mut internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    let _mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    run_crs_centralized(&mut kms_client, &internal_client, &crs_req, param, true).await;
    // Check that the new CRS was backed up
    let crss = backup_files(&req_new_cus, &crs_req, &PrivDataType::CrsInfo.to_string()).await;
    // Check that the format is correct
    assert!(crss.priv_data_type == PrivDataType::CrsInfo);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Check that the backup is still there an unmodified
    let (_kms_server, _kms_client, _internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    let reread_crss =
        backup_files(&req_new_cus, &crs_req, &PrivDataType::CrsInfo.to_string()).await;
    assert_eq!(reread_crss, crss);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_decrypt_after_recovery_central() {
    decrypt_after_recovery(5, 2).await;
}

async fn decrypt_after_recovery(amount_custodians: usize, threshold: u32) {
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    let req_new_cus: RequestId = derive_request_id("test_decrypt_after_recovery_central").unwrap();

    // Clean up backups to not interfere with test
    purge_backup(None, 1).await;
    purge_recovery_info(None, 1).await;
    let (kms_server, mut kms_client, mut internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    let mnemnonics = run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;

    // Shut down the servers
    drop(kms_server);
    drop(kms_client);
    drop(internal_client);

    // Read the private signing key for reference
    let priv_store = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    let sig_key: PrivateSigKey = read_versioned_at_request_id(
        &priv_store,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();

    // Purge the private storage to tests the backup
    purge_priv(None, 1).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Reboot the servers
    let (_kms_server, mut kms_client, _internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    // Purge the private storage again to delete the signing key
    purge_priv(None, 1).await;

    // Execute the backup restoring
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = kms_client
        .custodian_recovery_init(tonic::Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner();
    let cus_rec_req = emulate_custodian(&mut rng, recovery_req_resp, mnemnonics).await;
    let _recovery_output = kms_client
        .custodian_backup_recovery(tonic::Request::new(cus_rec_req))
        .await
        .unwrap();
    let _restore_output = kms_client
        .backup_restore(tonic::Request::new(Empty {}))
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
    // Check the data is correctly recovered
    assert_eq!(sk, sig_key);
    purge_priv(None, 1).await;
}

async fn emulate_custodian(
    rng: &mut AesRng,
    recovery_request: RecoveryRequest,
    mnemonics: Vec<String>,
) -> CustodianRecoveryRequest {
    let backup_id = recovery_request.backup_id.clone().unwrap();
    let mut cus_outputs = Vec::new();
    for (cur_idx, cur_mnemonic) in mnemonics.iter().enumerate() {
        let custodian: Custodian<PrivateSigKey, BackupPrivateKey> =
            custodian_from_seed_phrase(cur_mnemonic, Role::indexed_from_zero(cur_idx)).unwrap();
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
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
