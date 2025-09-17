use crate::{
    client::tests::threshold::{common::threshold_handles, crs_gen_tests::run_crs},
    consts::DEFAULT_PARAM,
    cryptography::internal_crypto_types::WrappedDKGParams,
    engine::base::{derive_request_id, INSECURE_PREPROCESSING_ID},
    util::key_setup::test_tools::{
        purge, purge_backup, purge_priv, EncryptionConfig, TestingPlaintext,
    },
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
use threshold_fhe::execution::{endpoints::decryption::DecryptionMode, runtime::party::Role};
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_threshold_dkg_backup() {
    // NOTE: amount_parties must not be too high
    // because every party will load all the keys and each ServerKey is 1.5 GB
    // and each private key share is 1 GB. Using 7 parties fails on a 32 GB machine.
    let amount_parties = 4;
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let key_id_1: RequestId = derive_request_id(&format!(
        "default_insecure_threshold_dkg_backup_1{amount_parties}_{param:?}",
    ))
    .unwrap();
    let key_id_2: RequestId = derive_request_id(&format!(
        "default_insecure_threshold_dkg_backup_2{amount_parties}_{param:?}",
    ))
    .unwrap();

    let test_path = None;
    // Purge private to make the test run faster since there will be less data to back up.
    purge_priv(test_path).await;
    purge(test_path, test_path, test_path, &key_id_1, amount_parties).await;
    purge(test_path, test_path, test_path, &key_id_2, amount_parties).await;
    purge_backup(test_path, amount_parties).await;
    let (kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    let _keys_1 = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id_1,
        None,
        None,
        true,
    )
    .await;

    let _keys_2 = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id_2,
        None,
        None,
        true,
    )
    .await;

    // Generated key, delete private storage
    for i in 1..=amount_parties {
        let mut priv_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        delete_all_at_request_id(&mut priv_storage, &key_id_1).await;
        delete_all_at_request_id(&mut priv_storage, &key_id_2).await;
    }

    // Now try to restore both keys
    let mut resp_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        resp_tasks.spawn(async move {
            let req = Empty {};
            // send query
            cur_client
                .restore_from_backup(tonic::Request::new(req))
                .await
        });
    }
    while let Some(res) = resp_tasks.join_next().await {
        match res {
            Ok(res) => match res {
                Ok(resp) => {
                    tracing::info!("Backup restore response: {resp:?}");
                }
                Err(e) => {
                    panic!("Error while restoring: {e}");
                }
            },
            Err(e) => {
                panic!("Error while restoring: {e}");
            }
        }
    }
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
    drop(kms_clients);
    drop(internal_client);

    // And validate that we can still decrypt
    crate::client::tests::threshold::public_decryption_tests::decryption_threshold(
        DEFAULT_PARAM,
        &key_id_2,
        vec![TestingPlaintext::U8(42)],
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        1,
        amount_parties,
        None,
        Some(DecryptionMode::NoiseFloodSmall),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_threshold_autobackup_after_deletion() {
    // NOTE: amount_parties must not be too high
    // because every party will load all the keys and each ServerKey is 1.5 GB
    // and each private key share is 1 GB. Using 7 parties fails on a 32 GB machine.
    use crate::conf::FileStorage as FileStorageConf;
    use crate::conf::Storage as StorageConf;

    let amount_parties = 4;
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let key_id: RequestId = derive_request_id(&format!(
        "default_insecure_autobackup_after_deletion_{amount_parties}_{param:?}",
    ))
    .unwrap();
    let test_path = None;
    // Purge private to make the test run faster since there will be less data to back up.
    purge_priv(test_path).await;
    purge(test_path, test_path, test_path, &key_id, amount_parties).await;
    purge_backup(test_path, amount_parties).await;
    let (kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    let _keys = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        &INSECURE_PREPROCESSING_ID,
        &key_id,
        None,
        None,
        true,
    )
    .await;

    // Reboot the servers
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
    drop(kms_clients);
    drop(internal_client);

    // Start the servers again
    let (_kms_servers, _kms_clients, _internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;
    // Check the storage
    let vault_storage_option = test_path.map(|path| {
        StorageConf::File(FileStorageConf {
            path: path.to_path_buf(),
        })
    });
    for cur_party in 1..=amount_parties {
        let backup_storage = make_storage(
            vault_storage_option.clone(),
            StorageType::BACKUP,
            Some(Role::indexed_from_one(cur_party)),
            None,
            None,
        )
        .unwrap();
        // Validate that the backup is constructed again
        assert!(backup_storage
            .data_exists(&key_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .unwrap());
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_insecure_threshold_crs_backup() {
    let amount_parties = 4;
    let param = FheParameter::Default;
    let dkg_param: WrappedDKGParams = param.into();

    let req_id: RequestId = derive_request_id(&format!(
        "default_insecure_threshold_crs_backup_{amount_parties}_{param:?}",
    ))
    .unwrap();
    let test_path = None;
    purge(test_path, test_path, test_path, &req_id, amount_parties).await;
    purge_backup(test_path, amount_parties).await;
    let (_kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;
    run_crs(
        param,
        &kms_clients,
        &internal_client,
        true, // insecure execution
        &req_id,
        Some(16),
    )
    .await;
    // Generated crs, delete it from private storage
    for i in 1..=amount_parties {
        let mut priv_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        delete_all_at_request_id(&mut priv_storage, &req_id).await;
        // Check that is has been removed
        assert!(!priv_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
    }
    // Now try to restore
    let mut resp_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        resp_tasks.spawn(async move {
            let req = Empty {};
            // send query
            cur_client
                .restore_from_backup(tonic::Request::new(req))
                .await
        });
    }
    while let Some(res) = resp_tasks.join_next().await {
        match res {
            Ok(res) => match res {
                Ok(resp) => {
                    tracing::info!("Backup restore response: {resp:?}");
                }
                Err(e) => {
                    panic!("Error while restoring: {e}");
                }
            },
            Err(e) => {
                panic!("Error while joining threads: {e}");
            }
        }
    }
    for i in 1..=amount_parties {
        let backup_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::BACKUP,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        // Check the back up is still there
        assert!(backup_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
        // Check that the file has been restored
        let priv_storage: FileStorage = FileStorage::new(
            test_path,
            StorageType::PRIV,
            Some(Role::indexed_from_one(i)),
        )
        .unwrap();
        // Check the back up is still there
        assert!(priv_storage
            .data_exists(&req_id, &PrivDataType::CrsInfo.to_string())
            .await
            .unwrap());
    }
}
