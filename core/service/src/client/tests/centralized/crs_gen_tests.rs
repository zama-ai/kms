use crate::client::client_wasm::Client;
use crate::engine::base::safe_serialize_hash_element_versioned;
use crate::vault::storage::{file::FileStorage, StorageType};
use crate::{
    client::tests::common::TIME_TO_SLEEP_MS,
    consts::TEST_PARAM,
    cryptography::internal_crypto_types::WrappedDKGParams,
    dummy_domain,
    engine::base::{derive_request_id, DSEP_PUBDATA_CRS},
    util::{key_setup::test_tools::purge, rate_limiter::RateLimiterConfig},
    vault::storage::StorageReader,
};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::solidity_types::CrsgenVerification;
use kms_grpc::{
    kms::v1::{Empty, FheParameter},
    rpc_types::PubDataType,
    RequestId,
};
use serial_test::serial;
use tfhe::zk::CompactPkeCrs;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;
use tonic::transport::Channel;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_crs_gen_manual() {
    let crs_req_id = derive_request_id("test_crs_gen_manual").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // TEST_PARAM uses V1 CRS
    crs_gen_centralized_manual(&TEST_PARAM, &crs_req_id, Some(FheParameter::Test)).await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_crs_gen_centralized() {
    let crs_req_id = derive_request_id("test_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // TEST_PARAM uses V1 CRS
    crs_gen_centralized(&crs_req_id, FheParameter::Test, false).await;
}

#[cfg(feature = "insecure")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_insecure_crs_gen_centralized() {
    let crs_req_id = derive_request_id("test_insecure_crs_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &crs_req_id, 1).await;
    // TEST_PARAM uses V1 CRS
    crs_gen_centralized(&crs_req_id, FheParameter::Test, true).await;
}

/// test centralized crs generation and do all the reading, processing and verification manually
async fn crs_gen_centralized_manual(
    dkg_params: &DKGParams,
    request_id: &RequestId,
    params: Option<FheParameter>,
) {
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(dkg_params, None).await;

    let max_num_bits = if params.unwrap() == FheParameter::Test {
        Some(1)
    } else {
        // The default is 2048 which is too slow for tests, so we switch to 256
        Some(256)
    };
    let domain = dummy_domain();
    let ceremony_req = internal_client
        .crs_gen_request(request_id, max_num_bits, params, &domain)
        .unwrap();

    let client_request_id = ceremony_req.request_id.clone().unwrap();

    // response is currently empty
    let gen_response = kms_client
        .crs_gen(tonic::Request::new(ceremony_req.clone()))
        .await
        .unwrap();
    assert_eq!(gen_response.into_inner(), Empty {});
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    // Check that we can retrieve the CRS under that request id
    let mut get_response = kms_client
        .get_crs_gen_result(tonic::Request::new(client_request_id.clone()))
        .await;
    while get_response.is_err() {
        // Sleep to give the server some time to complete CRS generation
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        get_response = kms_client
            .get_crs_gen_result(tonic::Request::new((*request_id).into()))
            .await;
    }

    let resp = get_response.unwrap().into_inner();
    let rvcd_req_id = resp.request_id.unwrap();

    // // check that the received request id matches the one we sent in the request
    assert_eq!(rvcd_req_id, client_request_id);

    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    // check that CRS signature is verified correctly for the current version
    let crs_unversioned: CompactPkeCrs = pub_storage
        .read_data(request_id, &PubDataType::CRS.to_string())
        .await
        .unwrap();

    let actual_digest =
        safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &crs_unversioned).unwrap();
    assert_eq!(actual_digest, resp.crs_digest);

    let max_num_bits = max_num_bits_from_crs(&crs_unversioned);

    // there should be exactly one server since we're in the centralized case
    assert_eq!(internal_client.server_identities.len(), 1);
    internal_client
        .verify_external_signature(
            &CrsgenVerification {
                crsId: alloy_primitives::U256::from_be_slice(request_id.as_bytes()),
                maxBitLength: alloy_primitives::U256::from_be_slice(&max_num_bits.to_be_bytes()),
                crsDigest: actual_digest.to_vec().into(),
            },
            &domain,
            &resp.external_signature,
        )
        .unwrap();

    kms_server.assert_shutdown().await;
}

/// test centralized crs generation via client interface
pub async fn crs_gen_centralized(crs_req_id: &RequestId, params: FheParameter, insecure: bool) {
    let dkg_param: WrappedDKGParams = params.into();
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 100,
        preproc: 1,
        keygen: 1,
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_param, Some(rate_limiter_conf)).await;
    run_crs_centralized(
        &mut kms_client,
        &internal_client,
        crs_req_id,
        params,
        insecure,
    )
    .await;
    kms_server.assert_shutdown().await;
}

pub(crate) async fn run_crs_centralized(
    kms_client: &mut CoreServiceEndpointClient<Channel>,
    internal_client: &Client,
    crs_req_id: &RequestId,
    params: FheParameter,
    insecure: bool,
) {
    let dkg_param: WrappedDKGParams = params.into();
    let max_num_bits = if params == FheParameter::Test {
        Some(1)
    } else {
        // The default is 2048 which is too slow for tests, so we switch to 256
        Some(256)
    };
    let domain = dummy_domain();
    let gen_req = internal_client
        .crs_gen_request(crs_req_id, max_num_bits, Some(params), &domain)
        .unwrap();

    tracing::debug!("making crs request, insecure? {insecure}");
    match insecure {
        true => {
            #[cfg(feature = "insecure")]
            {
                let gen_response = kms_client
                    .insecure_crs_gen(tonic::Request::new(gen_req.clone()))
                    .await
                    .unwrap();
                assert_eq!(gen_response.into_inner(), Empty {});
            }
            #[cfg(not(feature = "insecure"))]
            {
                panic!("cannot perform insecure central crs gen")
            }
        }
        false => {
            let gen_response = kms_client
                .crs_gen(tonic::Request::new(gen_req.clone()))
                .await
                .unwrap();
            assert_eq!(gen_response.into_inner(), Empty {});
        }
    };

    let mut response = Err(tonic::Status::not_found(""));
    let mut ctr = 0;
    while response.is_err() && ctr < 5 {
        response = kms_client
            .get_crs_gen_result(tonic::Request::new((*crs_req_id).into()))
            .await;
        ctr += 1;
    }
    let inner_resp = response.unwrap().into_inner();
    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    let pp = internal_client
        .process_get_crs_resp(&inner_resp, &domain, &pub_storage)
        .await
        .unwrap()
        .unwrap();

    // Validate the CRS as a sanity check
    crate::client::crs_gen::tests::verify_pp(&dkg_param, &pp);
}
