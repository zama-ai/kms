use crate::backup::custodian::Custodian;
use crate::backup::operator::InternalRecoveryRequest;
use crate::backup::seed_phrase::custodian_from_seed_phrase;
#[cfg(feature = "insecure")]
use crate::client::tests::threshold::crs_gen_tests::run_crs;
use crate::client::tests::threshold::custodian_context_tests::backup_files;
use crate::client::tests::threshold::custodian_context_tests::run_new_cus_context;
use crate::consts::{SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
use crate::cryptography::backup_pke::BackupPrivateKey;
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::util::key_setup::test_tools::purge_pub;
use crate::util::key_setup::test_tools::{purge_backup, purge_recovery_info};
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{read_versioned_at_request_id, StorageType};
use crate::{
    client::tests::common::TIME_TO_SLEEP_MS,
    client::tests::threshold::common::threshold_handles_custodian_backup,
    cryptography::{backup_pke::BackupCiphertext, internal_crypto_types::WrappedDKGParams},
    engine::base::derive_request_id,
    util::key_setup::test_tools::purge_priv,
};
use aes_prng::AesRng;
use kms_grpc::kms::v1::{CustodianRecoveryRequest, Empty, RecoveryRequest};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{kms::v1::FheParameter, rpc_types::PrivDataType, RequestId};
use rand::SeedableRng;
use serial_test::serial;
use std::collections::HashMap;
use tfhe::safe_serialization::safe_deserialize;
use threshold_fhe::execution::runtime::party::Role;
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_auto_update_backups_threshold() {
    auto_update_backup(5, 2).await;
}

async fn auto_update_backup(amount_custodians: usize, threshold: u32) {
    let amount_parties = 4;
    let req_new_cus: RequestId = derive_request_id(&format!(
        "test_auto_update_backups_threshold_{amount_parties}_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let test_path = None;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_servers, kms_clients, mut internal_client) = threshold_handles_custodian_backup(
        *dkg_param,
        amount_parties,
        true,
        false,
        None,
        None,
        test_path,
    )
    .await;
    // Clean up backups to not interfere with test
    purge_backup(test_path, amount_parties).await;
    purge_recovery_info(test_path, amount_parties).await;
    let _mnemnonics = run_new_cus_context(
        &kms_clients,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    // Check that signing key was backed up, since it will always be there
    let initial_backup: Vec<BackupCiphertext> = backup_files(
        amount_parties,
        test_path,
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    assert_eq!(initial_backup.len(), amount_parties); // exactly one per party

    // Shut down the servers
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
    drop(kms_clients);
    drop(internal_client);

    // Purge backup
    purge_backup(test_path, amount_parties).await;
    // Check that the backup is still there an unmodified
    let (_kms_servers, _kms_clients, _internal_client) = threshold_handles_custodian_backup(
        *dkg_param,
        amount_parties,
        true,
        false,
        None,
        None,
        test_path,
    )
    .await;
    let _reread_backup: Vec<BackupCiphertext> = backup_files(
        amount_parties,
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
async fn test_backup_after_crs_threshold() {
    backup_after_crs(5, 2).await;
}

#[cfg(feature = "insecure")]
async fn backup_after_crs(amount_custodians: usize, threshold: u32) {
    let amount_parties = 4;
    let req_new_cus: RequestId = derive_request_id(&format!(
        "test_backup_after_crs_threshold_{amount_parties}_{amount_custodians}_{threshold}"
    ))
    .unwrap();
    let test_path = None;
    let crs_req: RequestId = derive_request_id(&format!(
        "test_backup_after_crs_threshold_{amount_parties}_{amount_custodians}_{threshold}"
    ))
    .unwrap();

    // Clean up backups to not interfere with test
    purge_backup(test_path, amount_parties).await;
    purge_recovery_info(test_path, amount_parties).await;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    // The threshold handle should only be started after the storage is purged
    // since the threshold parties will load the CRS from private storage
    let (kms_servers, kms_clients, mut internal_client) = threshold_handles_custodian_backup(
        *dkg_param,
        amount_parties,
        true,
        false,
        None,
        None,
        test_path,
    )
    .await;
    let _mnemnonics = run_new_cus_context(
        &kms_clients,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;

    // Generate a new crs
    run_crs(
        FheParameter::Test,
        &kms_clients,
        &internal_client,
        true,
        &crs_req,
        Some(16),
    )
    .await;
    // Check that the new CRS was backed up
    let crss: Vec<BackupCiphertext> = backup_files(
        amount_parties,
        test_path,
        &req_new_cus,
        &crs_req,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await;
    // Validate each backup
    assert_eq!(crss.len(), amount_parties);
    for i in 0..crss.len() - 1 {
        // Check that each is different since it is supposed to be secret shared
        assert!(crss[i] != crss[i + 1]);
        // Check that the format is correct
        assert!(crss[i].priv_data_type == PrivDataType::CrsInfo);
    }
    assert!(crss[crss.len() - 1].priv_data_type == PrivDataType::CrsInfo);

    // Shut down the servers
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
    drop(kms_clients);
    drop(internal_client);

    // Check that the backup is still there an unmodified
    let (_kms_servers, _kms_clients, _internal_client) = threshold_handles_custodian_backup(
        *dkg_param,
        amount_parties,
        true,
        false,
        None,
        None,
        test_path,
    )
    .await;
    let reread_crss: Vec<BackupCiphertext> = backup_files(
        amount_parties,
        test_path,
        &req_new_cus,
        &crs_req,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await;
    assert_eq!(crss.len(), amount_parties);
    for i in 0..amount_parties {
        assert!(reread_crss[i] == crss[i]);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_decrypt_after_recovery_threshold() {
    decrypt_after_recovery(5, 2).await;
}

async fn decrypt_after_recovery(amount_custodians: usize, threshold: u32) {
    let amount_parties = 4;
    let dkg_param: WrappedDKGParams = FheParameter::Test.into();
    let req_new_cus: RequestId = derive_request_id(&format!(
        "test_decrypt_after_recovery_threshold_{amount_parties}"
    ))
    .unwrap();
    let test_path = None;
    // Clean up backups to not interfere with test
    purge_backup(test_path, amount_parties).await;
    purge_recovery_info(test_path, amount_parties).await;

    let (kms_servers, kms_clients, mut internal_client) = threshold_handles_custodian_backup(
        *dkg_param,
        amount_parties,
        true,
        false,
        None,
        None,
        test_path,
    )
    .await;
    let mnemnonics = run_new_cus_context(
        &kms_clients,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;

    // Shut down the servers
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
    drop(kms_clients);
    drop(internal_client);

    let mut sig_keys = Vec::new();
    // Read the private signing keys for reference
    for i in 1..=amount_parties {
        let cur_role = Role::indexed_from_one(i);
        let cur_priv_store =
            FileStorage::new(test_path, StorageType::PRIV, Some(cur_role)).unwrap();
        let cur_sk: PrivateSigKey = read_versioned_at_request_id(
            &cur_priv_store,
            &SIGNING_KEY_ID,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        sig_keys.push(cur_sk);
    }
    // Purge the private storage to tests the backup
    purge_priv(test_path).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    // Reboot the servers
    let (_kms_servers, kms_clients, _internal_client) = threshold_handles_custodian_backup(
        *dkg_param,
        amount_parties,
        true,
        false,
        None,
        None,
        test_path,
    )
    .await;
    // Purge the private storage again to delete the signing key
    purge_priv(test_path).await;

    // Execute the backup restoring
    let mut rng = AesRng::seed_from_u64(13);
    let recovery_req_resp = run_custodian_recovery_init(&kms_clients).await;
    assert_eq!(recovery_req_resp.len(), amount_parties);
    let cus_out = emulate_custodian(&mut rng, test_path, recovery_req_resp, mnemnonics).await;
    let recovery_output = run_custodian_backup_recovery(&kms_clients, &cus_out).await;
    assert_eq!(recovery_output.len(), amount_parties);
    let res = run_restore_from_backup(&kms_clients).await;
    assert_eq!(res.len(), amount_parties);

    // Check that the key material is back
    for i in 1..=amount_parties {
        let cur_role = Role::indexed_from_one(i);
        let cur_priv_store =
            FileStorage::new(test_path, StorageType::PRIV, Some(cur_role)).unwrap();
        let cur_sk: PrivateSigKey = read_versioned_at_request_id(
            &cur_priv_store,
            &SIGNING_KEY_ID,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        // Check the data is correctly recovered
        assert_eq!(cur_sk, sig_keys[i - 1]);
    }
    // Purge to ensure no left over state
    purge_priv(test_path).await;
    purge_pub(test_path).await;
}

async fn run_custodian_recovery_init(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> Vec<RecoveryRequest> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        tasks_gen.spawn(async move {
            cur_client
                .custodian_recovery_init(tonic::Request::new(Empty {}))
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

async fn run_custodian_backup_recovery(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    req: &HashMap<usize, CustodianRecoveryRequest>,
) -> Vec<Empty> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        let req_clone = req.get(&(i as usize)).unwrap().to_owned();
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

async fn emulate_custodian(
    rng: &mut AesRng,
    test_path: Option<&std::path::Path>,
    recovery_requests: Vec<RecoveryRequest>,
    mnemonics: Vec<String>,
) -> HashMap<usize, CustodianRecoveryRequest> {
    let backup_id = recovery_requests[0].backup_id.clone().unwrap();
    let mut outputs_for_operators = HashMap::new();
    // Setup a map to contain the results for each operator role
    for idx in 1..=recovery_requests.len() {
        outputs_for_operators.insert(idx, Vec::new());
    }
    for (cur_idx, cur_mnemonic) in mnemonics.iter().enumerate() {
        let custodian: Custodian<PrivateSigKey, BackupPrivateKey> =
            custodian_from_seed_phrase(cur_mnemonic, Role::indexed_from_zero(cur_idx)).unwrap();
        for cur_recovery_req in &recovery_requests {
            let pub_storage = FileStorage::new(
                test_path,
                StorageType::PUB,
                Some(Role::indexed_from_one(
                    cur_recovery_req.operator_role as usize,
                )),
            )
            .unwrap();
            let cur_verf_key = read_versioned_at_request_id(
                &pub_storage,
                &SIGNING_KEY_ID,
                &PubDataType::VerfKey.to_string(),
            )
            .await
            .unwrap();
            let internal_recovery_req: InternalRecoveryRequest =
                cur_recovery_req.to_owned().try_into().unwrap();
            assert!(internal_recovery_req.is_valid(&cur_verf_key).unwrap());
            let cur_cus_reenc = cur_recovery_req.cts.get(&((cur_idx + 1) as u64)).unwrap();
            let cur_enc_key = safe_deserialize(
                std::io::Cursor::new(&cur_recovery_req.enc_key),
                SAFE_SER_SIZE_LIMIT,
            )
            .unwrap();
            let cur_out = custodian
                .verify_reencrypt(
                    rng,
                    &cur_cus_reenc.to_owned().into(),
                    &cur_verf_key,
                    &cur_enc_key,
                    backup_id.clone().try_into().unwrap(),
                    Role::indexed_from_one(cur_recovery_req.operator_role as usize),
                )
                .unwrap();
            // Add the result from this custodian to the map of results to the correct operator
            let cur_operator_res = outputs_for_operators
                .get_mut(&(cur_recovery_req.operator_role as usize))
                .unwrap();
            cur_operator_res.push(cur_out.try_into().unwrap());
        }
    }
    outputs_for_operators
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                CustodianRecoveryRequest {
                    custodian_context_id: Some(backup_id.clone()),
                    custodian_recovery_outputs: v,
                },
            )
        })
        .collect::<HashMap<usize, CustodianRecoveryRequest>>()
}
