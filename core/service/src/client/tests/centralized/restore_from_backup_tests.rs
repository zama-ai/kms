use crate::{
    client::tests::centralized::{
        crs_gen_tests::crs_gen_centralized, key_gen_tests::key_gen_centralized,
        public_decryption_tests::decryption_centralized,
    },
    cryptography::internal_crypto_types::WrappedDKGParams,
    engine::base::derive_request_id,
    util::key_setup::test_tools::{purge, purge_backup, EncryptionConfig, TestingPlaintext},
    vault::storage::{
        delete_all_at_request_id, file::FileStorage, make_storage, StorageReader, StorageType,
    },
};
use kms_grpc::{
    kms::v1::{Empty, FheParameter},
    rpc_types::PrivDataType,
    RequestId,
};
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_central_dkg_backup() {
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();
    let key_id_1 = derive_request_id("default_insecure_central_dkg_backup-1").unwrap();
    let key_id_2 = derive_request_id("default_insecure_central_dkg_backup-2").unwrap();
    // Delete potentially old data
    purge(None, None, None, &key_id_1, 1).await;
    purge(None, None, None, &key_id_2, 1).await;
    purge_backup(None, 1).await;
    key_gen_centralized(&key_id_1, param, None, None).await;
    key_gen_centralized(&key_id_2, param, None, None).await;
    // Generated key, delete private storage
    let mut priv_storage: FileStorage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
    delete_all_at_request_id(&mut priv_storage, &key_id_2).await;

    // Now try to restore both keys
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, None).await;

    let req = Empty {};
    // send query
    match kms_client
        .restore_from_backup(tonic::Request::new(req))
        .await
    {
        Ok(res) => tracing::info!("Backup restore response: {res:?}"),
        Err(e) => {
            panic!("Error while restoring: {e}");
        }
    }

    drop(kms_server);
    drop(kms_client);
    drop(internal_client);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    decryption_centralized(
        &dkg_param.get_params_without_sns(),
        &key_id_1,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        1,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_central_autobackup_after_deletion() {
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();
    let key_id = derive_request_id("default_insecure_central_autobackup_after_deletion").unwrap();
    // Delete potentially old data
    purge(None, None, None, &key_id, 1).await;
    purge_backup(None, 1).await;
    key_gen_centralized(&key_id, param, None, None).await;
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Start the servers again
    let (_kms_server, _kms_client, _internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, None).await;
    // Check the storage
    let backup_storage = make_storage(None, StorageType::BACKUP, None, None, None).unwrap();
    // Validate that the backup is constructed again
    assert!(backup_storage
        .data_exists(&key_id, &PrivDataType::FhePrivateKey.to_string())
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_central_crs_backup() {
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();
    let req_id: RequestId =
        derive_request_id(&format!("default_insecure_central_crs_backup_{param:?}",)).unwrap();
    purge(None, None, None, &req_id, 1).await;
    purge_backup(None, 1).await;
    crs_gen_centralized(&req_id, param, true).await;

    // Generated crs, delete it from private storage
    let mut priv_storage: FileStorage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    delete_all_at_request_id(&mut priv_storage, &req_id).await;
    // Check that is has been removed
    assert!(!priv_storage
        .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
        .await
        .unwrap());

    // It will get auto-backed up at boot
    let (_kms_server, mut kms_client, _internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, None).await;

    let req = Empty {};
    // Now try to restore the crs
    let query_res = kms_client
        .restore_from_backup(tonic::Request::new(req))
        .await;
    match query_res {
        Ok(resp) => {
            tracing::info!("Backup restore response: {resp:?}");
        }
        Err(e) => {
            panic!("Error while restoring: {e}");
        }
    }

    let backup_storage: FileStorage = FileStorage::new(None, StorageType::BACKUP, None).unwrap();
    // Check the back up is still there
    assert!(backup_storage
        .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
        .await
        .unwrap());
    // Check that the file has been restored
    let priv_storage: FileStorage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    // Check the back up is still there
    assert!(priv_storage
        .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
        .await
        .unwrap());
}
