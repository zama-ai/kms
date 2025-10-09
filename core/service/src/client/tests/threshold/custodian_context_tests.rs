use crate::client::client_wasm::Client;
use crate::client::tests::threshold::common::threshold_handles_custodian_backup;
use crate::consts::SIGNING_KEY_ID;
use crate::util::key_setup::test_tools::backup_exists;
use crate::util::key_setup::test_tools::read_backup_files;
use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
};
use kms_grpc::kms::v1::{Empty, NewCustodianContextRequest};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;
use std::collections::HashMap;
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(7, 3)]
#[case(3, 1)]
#[serial]
async fn test_new_custodian_context_threshold(#[case] custodians: usize, #[case] threshold: u32) {
    new_custodian_context(4, FheParameter::Test, custodians, threshold).await;
}

async fn new_custodian_context(
    amount_parties: usize,
    parameter: FheParameter,
    amount_custodians: usize,
    threshold: u32,
) {
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());
    ensure_testing_material_exists(test_path).await;
    let req_new_cus: RequestId = derive_request_id(&format!(
        "test_new_custodian_context_threshold_{amount_parties}"
    ))
    .unwrap();
    let req_new_cus2: RequestId = derive_request_id(&format!(
        "test_new_custodian_context_threshold_2_{amount_parties}"
    ))
    .unwrap();
    let dkg_param: WrappedDKGParams = parameter.into();

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
    let first_sig_keys = read_backup_files(
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
    let second_sig_keys = read_backup_files(
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
    for (_, kms_server) in kms_servers {
        kms_server.assert_shutdown().await;
    }
    drop(kms_clients);
    drop(internal_client);
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
    let reboot_sig_keys = read_backup_files(
        amount_parties,
        test_path,
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    for cur_idx in 0..reboot_sig_keys.len() {
        // Check that the backups are the same as the ones loaded before the reboot
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
