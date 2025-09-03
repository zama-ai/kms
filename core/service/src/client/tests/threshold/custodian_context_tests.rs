use crate::client::client_wasm::Client;
use crate::client::tests::threshold::common::threshold_handles;
use crate::client::tests::threshold::common::threshold_handles_secretsharing_backup;
use crate::consts::KEY_PATH_PREFIX;
use crate::consts::SIGNING_KEY_ID;
use crate::cryptography::backup_pke::BackupCiphertext;
use crate::util::file_handling::safe_read_element_versioned;
use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
    util::key_setup::test_tools::purge,
};
use kms_grpc::kms::v1::{Empty, NewCustodianContextRequest};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::BackupDataType;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_new_custodian_context_threshold() {
    new_custodian_context(4, FheParameter::Test, 5, 2).await;
}

pub(crate) async fn new_custodian_context(
    amount_parties: usize,
    parameter: FheParameter,
    amount_custodians: usize,
    threshold: u32,
) {
    let req_new_cus: RequestId =
        derive_request_id(&format!("new_custodian_{amount_parties}")).unwrap();
    let req_new_cus2: RequestId =
        derive_request_id(&format!("new_custodian_2_{amount_parties}")).unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());
    ensure_testing_material_exists(test_path).await;
    let dkg_param: WrappedDKGParams = parameter.into();

    // The threshold handle should only be started after the storage is purged
    // since the threshold parties will load the CRS from private storage
    let (kms_servers, kms_clients, mut internal_client) = threshold_handles_secretsharing_backup(
        *dkg_param,
        amount_parties,
        true,
        None,
        None,
        test_path,
    )
    .await;
    // Check there is currently no backup
    assert!(!backup_exists(amount_parties, test_path).await);
    run_new_cus_context(
        &kms_clients,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    // Check that the files are backed up
    assert!(backup_exists(amount_parties, test_path).await);
    let first_sig_keys = backup_files(
        amount_parties,
        test_path,
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    // Validate that each backup is different since it is supposed to be secret shared
    for cur_idx in 1..first_sig_keys.len() {
        assert!(first_sig_keys[cur_idx] != first_sig_keys[0]);
    }
    // Generate a new custodian context
    run_new_cus_context(
        &kms_clients,
        &mut internal_client,
        &req_new_cus2,
        amount_custodians,
        threshold,
    )
    .await;
    let second_sig_keys = backup_files(
        amount_parties,
        test_path,
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    // Validate that each backup is different since it is supposed to be secret shared
    for cur_idx in 1..second_sig_keys.len() {
        assert!(second_sig_keys[cur_idx] != second_sig_keys[0]);
    }
    // Check that the backup is changed
    for cur_idx in 0..second_sig_keys.len() {
        assert!(second_sig_keys[cur_idx] != first_sig_keys[cur_idx]);
    }

    // Check that we can shut down and start again without updates changing
    // Shut down the servers
    drop(kms_servers);
    drop(kms_clients);
    drop(internal_client);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let (_kms_servers, _kms_clients, _internal_client) = threshold_handles_secretsharing_backup(
        *dkg_param,
        amount_parties,
        true,
        None,
        None,
        test_path,
    )
    .await;
    let reboot_sig_keys = backup_files(
        amount_parties,
        test_path,
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    for cur_idx in 0..reboot_sig_keys.len() {
        // Check that the backups are the same as the onces loaded before the reboot
        assert!(reboot_sig_keys[cur_idx] == second_sig_keys[cur_idx]);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_new_cus_context(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &mut Client,
    req_new_cus: &RequestId,
    amount_custodians: usize,
    threshold: u32,
) -> Vec<String> {
    let (new_cus_req, mnemonics) = internal_client
        .new_custodian_context_request(req_new_cus, amount_custodians, threshold)
        .unwrap();

    let responses = launch_new_cus(&new_cus_req, kms_clients).await;
    for response in responses {
        assert!(response.is_ok());
    }
    mnemonics
}

#[cfg(any(feature = "slow_tests", feature = "insecure"))]
async fn launch_new_cus(
    req: &NewCustodianContextRequest,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
    let amount_parties = kms_clients.len();
    let mut tasks_gen = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        let mut cur_client = kms_clients.get(&i).unwrap().clone();
        let req_clone = req.clone();
        tasks_gen.spawn(async move {
            cur_client
                .new_custodian_context(tonic::Request::new(req_clone))
                .await
        });
    }
    let mut responses_gen = Vec::new();
    while let Some(inner) = tasks_gen.join_next().await {
        let resp = inner.unwrap();
        responses_gen.push(resp);
    }
    assert_eq!(responses_gen.len(), amount_parties);
    responses_gen
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn threshold_new_custodian() {
    let amount_parties = 4;
    let param = FheParameter::Test;
    let dkg_param: WrappedDKGParams = param.into();

    let key_id: RequestId = derive_request_id(&format!(
        "default_insecure_autobackup_after_deletion_{amount_parties}_{param:?}",
    ))
    .unwrap();
    let test_path = None;

    purge(test_path, test_path, test_path, &key_id, amount_parties).await;
    let (_kms_servers, kms_clients, internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None).await;

    // Setup a custodian context before generating keys
    let _keys = crate::client::tests::threshold::key_gen_tests::run_threshold_keygen(
        param,
        &kms_clients,
        &internal_client,
        None,
        &key_id,
        None,
        None,
        true,
    )
    .await;
}

async fn backup_exists(amount_parties: usize, test_path: Option<&Path>) -> bool {
    let mut backup_exists = false;
    for cur_role in 1..=amount_parties {
        let base_path = base_backup_path(cur_role, test_path);
        println!("Checking path {:?}", base_path);
        let mut files = tokio::fs::read_dir(base_path).await.unwrap();
        if files.next_entry().await.unwrap().is_some() {
            backup_exists = true;
        }
    }
    backup_exists
}

pub(crate) async fn backup_files(
    amount_parties: usize,
    test_path: Option<&Path>,
    backup_id: &RequestId,
    file_req: &RequestId,
    data_type: &str,
) -> Vec<BackupCiphertext> {
    let mut files = Vec::new();
    for cur_role in 1..=amount_parties {
        let coerced_path = base_backup_path(cur_role, test_path)
            .join(backup_id.to_string())
            .join(BackupDataType::PrivData(data_type.try_into().unwrap()).to_string())
            .join(file_req.to_string());
        // Attempt to read the file
        if let Ok(file) = safe_read_element_versioned(coerced_path).await {
            files.push(file);
        }
    }
    files
}

fn base_backup_path(cur_role_idx: usize, test_path: Option<&Path>) -> PathBuf {
    match test_path {
        Some(p) => p,
        None => Path::new(KEY_PATH_PREFIX),
    }
    .join(format!("BACKUP-p{cur_role_idx}"))
}
