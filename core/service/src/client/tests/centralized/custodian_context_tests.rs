use crate::client::client_wasm::Client;
use crate::consts::KEY_PATH_PREFIX;
use crate::consts::SIGNING_KEY_ID;
use crate::cryptography::backup_pke::BackupCiphertext;
use crate::util::file_handling::safe_read_element_versioned;
use crate::util::key_setup::test_tools::purge_backup;
use crate::util::key_setup::test_tools::purge_recovery_info;
use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::BackupDataType;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;
use std::path::Path;
use tonic::transport::Channel;

#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_new_custodian_context_central() {
    new_custodian_context(FheParameter::Test, 5, 2).await;
}

pub(crate) async fn new_custodian_context(
    parameter: FheParameter,
    amount_custodians: usize,
    threshold: u32,
) {
    ensure_testing_material_exists(None).await;
    let req_new_cus: RequestId = derive_request_id("test_new_custodian_context_central").unwrap();
    let req_new_cus2: RequestId =
        derive_request_id("test_new_custodian_context_central_2").unwrap();
    purge_backup(None, 1).await;
    purge_recovery_info(None, 1).await;

    let dkg_param: WrappedDKGParams = parameter.into();
    // The threshold handle should only be started after the storage is purged
    // since the threshold parties will load the CRS from private storage
    let (kms_server, mut kms_client, mut internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    // Check there is currently no backup
    assert!(!backup_exists().await);
    run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    // Check that the files are backed up
    assert!(backup_exists().await);
    let first_sig_keys = backup_files(
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    // Generate a new custodian context
    run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus2,
        amount_custodians,
        threshold,
    )
    .await;
    let second_sig_keys = backup_files(
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    // Check that the backup is changed since we use randomized encryption
    assert!(second_sig_keys != first_sig_keys);

    // Check that we can shut down and start again without updates changing
    // Shut down the servers
    drop(kms_server);
    drop(kms_client);
    drop(internal_client);
    // Sleep to ensure the servers are properly shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let (_kms_server, _kms_client, _internal_client) =
        crate::client::test_tools::centralized_custodian_handles(&dkg_param, None).await;
    let reboot_sig_keys = backup_files(
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    // Check that the backups are the same as the onces loaded before the reboot
    assert!(reboot_sig_keys == second_sig_keys);
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_new_cus_context(
    kms_client: &mut CoreServiceEndpointClient<Channel>,
    internal_client: &mut Client,
    req_new_cus: &RequestId,
    amount_custodians: usize,
    threshold: u32,
) -> Vec<String> {
    let (new_cus_req, mnemonics) = internal_client
        .new_custodian_context_request(req_new_cus, amount_custodians, threshold)
        .unwrap();

    let response = kms_client
        .new_custodian_context(tonic::Request::new(new_cus_req))
        .await;
    assert!(response.is_ok());
    mnemonics
}

async fn backup_exists() -> bool {
    let base_path = Path::new(KEY_PATH_PREFIX).join("BACKUP");
    let mut files = tokio::fs::read_dir(base_path).await.unwrap();
    files.next_entry().await.unwrap().is_some()
}

pub(crate) async fn backup_files(
    backup_id: &RequestId,
    file_req: &RequestId,
    data_type: &str,
) -> BackupCiphertext {
    let coerced_path = Path::new(KEY_PATH_PREFIX)
        .join("BACKUP")
        .join(backup_id.to_string())
        .join(BackupDataType::PrivData(data_type.try_into().unwrap()).to_string())
        .join(file_req.to_string());
    // Attempt to read the file
    if let Ok(file) = safe_read_element_versioned(coerced_path.clone()).await {
        file
    } else {
        panic!("Failed to read backup file {:?}", coerced_path);
    }
}
