use crate::client::client_wasm::Client;
use crate::client::test_tools::centralized_custodian_handles;
use crate::consts::SIGNING_KEY_ID;
use crate::util::key_setup::test_tools::backup_exists;
use crate::util::key_setup::test_tools::read_backup_files;
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;
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
    let req_new_cus: RequestId = derive_request_id("test_new_custodian_context_central").unwrap();
    let req_new_cus2: RequestId =
        derive_request_id("test_new_custodian_context_central_2").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = Some(temp_dir.path());

    let dkg_param: WrappedDKGParams = parameter.into();
    let (kms_server, mut kms_client, mut internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
    // Check that the files are backed up
    assert!(backup_exists(1, test_path).await);
    let first_sig_keys = read_backup_files(
        1,
        test_path,
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
    let second_sig_keys = read_backup_files(
        1,
        test_path,
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
    )
    .await;
    // Check that the backup is changed since we use randomized encryption
    assert!(second_sig_keys != first_sig_keys);

    // Check that we can shut down and start again without updates changing
    // Shut down the servers
    kms_server.assert_shutdown().await;
    drop(kms_client);
    drop(internal_client);
    let (_kms_server, _kms_client, _internal_client) =
        centralized_custodian_handles(&dkg_param, None, test_path).await;
    let reboot_sig_keys = read_backup_files(
        1,
        test_path,
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
