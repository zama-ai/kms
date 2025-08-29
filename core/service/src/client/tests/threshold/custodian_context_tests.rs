use crate::client::client_wasm::Client;
use crate::client::tests::{common::TIME_TO_SLEEP_MS, threshold::common::threshold_handles};
use crate::{
    cryptography::internal_crypto_types::WrappedDKGParams, engine::base::derive_request_id,
    util::key_setup::test_tools::purge,
};
use kms_grpc::kms::v1::{Empty, NewCustodianContextRequest};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::{kms::v1::FheParameter, RequestId};
use serial_test::serial;
use std::collections::HashMap;
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
    purge(None, None, None, &req_new_cus, amount_parties).await;

    let dkg_param: WrappedDKGParams = parameter.into();

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    // The threshold handle should only be started after the storage is purged
    // since the threshold parties will load the CRS from private storage
    // TODO add temp storage option so we don't backup everything from other tests
    let (_kms_servers, kms_clients, mut internal_client) =
        threshold_handles(*dkg_param, amount_parties, true, None, None, true).await;
    run_new_cus_context(
        &kms_clients,
        &mut internal_client,
        &req_new_cus,
        amount_custodians,
        threshold,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_new_cus_context(
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &mut Client,
    req_new_cus: &RequestId,
    amount_custodians: usize,
    threshold: u32,
) {
    let new_cus_req = internal_client
        .new_custodian_context_request(req_new_cus, amount_custodians, threshold)
        .unwrap();

    let responses = launch_new_cus(&new_cus_req, kms_clients).await;
    for response in responses {
        println!("response: {:?}", response);
        assert!(response.is_ok());
    }
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
        crate::client::tests::threshold::common::threshold_handles(
            *dkg_param,
            amount_parties,
            true,
            None,
            None,
            true,
        )
        .await;

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
