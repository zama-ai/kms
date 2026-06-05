use crate::client::client_wasm::Client;
use crate::consts::DEFAULT_MPC_CONTEXT;
use crate::consts::SIGNING_KEY_ID;
use crate::testing::setup::CentralizedTestEnv;
use crate::util::key_setup::test_tools::backup_exists;
use crate::util::key_setup::test_tools::read_custodian_backup_files;
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{RequestId, kms::v1::FheParameter};
use tonic::transport::Channel;

#[tokio::test(flavor = "multi_thread")]
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

    let dkg_param: WrappedDKGParams = parameter.into();
    let test_env = CentralizedTestEnv::builder()
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
    let test_path = Some(material_dir.path());
    run_new_cus_context(
        &mut kms_client,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;

    // Check that the files are backed up
    assert!(backup_exists(test_path, &[None]).await);
    let first_sig_keys = read_custodian_backup_files(
        test_path,
        &req_new_cus,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        &[None],
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

    let second_sig_keys = read_custodian_backup_files(
        test_path,
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        &[None],
    )
    .await;
    // Check that the backup is changed since we use randomized encryption
    assert!(second_sig_keys != first_sig_keys);

    // Check that we can shut down and start again without updates changing
    // Shut down the servers
    kms_server.assert_shutdown().await;
    drop(kms_client);
    drop(internal_client);
    let (_kms_server, _kms_client) = CentralizedTestEnv::builder()
        .with_custodian_keychain()
        .from_path(material_dir.path())
        .await
        .unwrap();
    let reboot_sig_keys = read_custodian_backup_files(
        test_path,
        &req_new_cus2,
        &SIGNING_KEY_ID,
        &PrivDataType::SigningKey.to_string(),
        &[None],
    )
    .await;
    // Check that the backups are the same as the onces loaded before the reboot
    assert!(reboot_sig_keys == second_sig_keys);
}

pub(crate) async fn run_new_cus_context(
    kms_client: &mut CoreServiceEndpointClient<Channel>,
    internal_client: &mut Client,
    req_new_cus: &RequestId,
    amount_custodians: usize,
    threshold: u32,
) -> Vec<String> {
    let (new_cus_req, mnemonics) = internal_client
        .new_custodian_context_request(
            req_new_cus,
            &DEFAULT_MPC_CONTEXT,
            amount_custodians,
            threshold,
        )
        .unwrap();

    let response = kms_client
        .new_custodian_context(tonic::Request::new(new_cus_req))
        .await;
    assert!(response.is_ok());
    mnemonics
}
