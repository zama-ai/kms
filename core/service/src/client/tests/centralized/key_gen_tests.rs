use crate::client::client_wasm::Client;
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_tools::purge;
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::StorageReader;
use crate::vault::storage::{file::FileStorage, StorageType};
use alloy_dyn_abi::Eip712Domain;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::{Empty, FheParameter, KeySetAddedInfo, KeySetConfig, KeySetType};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::{ContextId, RequestId};
use serial_test::serial;
use std::path::Path;
use std::str::FromStr;
use tfhe::prelude::Tagged;
use tonic::transport::Channel;

use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_key_gen_centralized() {
    let request_id = derive_request_id("test_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, &request_id, 1).await;
    key_gen_centralized(&request_id, FheParameter::Test, None, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_decompression_key_gen_centralized() {
    let request_id_1 = derive_request_id("test_key_gen_centralized-1").unwrap();
    let request_id_2 = derive_request_id("test_key_gen_centralized-2").unwrap();
    let request_id_3 = derive_request_id("test_decompression_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, &request_id_1, 1).await;
    purge(None, None, &request_id_2, 1).await;
    purge(None, None, &request_id_3, 1).await;

    key_gen_centralized(&request_id_1, FheParameter::Default, None, None).await;
    key_gen_centralized(&request_id_2, FheParameter::Default, None, None).await;

    key_gen_centralized(
        &request_id_3,
        FheParameter::Default,
        Some(KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        }),
        Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: Some(request_id_1.into()),
            to_keyset_id_decompression_only: Some(request_id_2.into()),
        }),
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_key_gen_centralized() {
    let request_id = derive_request_id("default_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, &request_id, 1).await;
    key_gen_centralized(&request_id, FheParameter::Default, None, None).await;
}

#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_decompression_key_gen_centralized() {
    let request_id_1 = derive_request_id("default_key_gen_centralized-1").unwrap();
    let request_id_2 = derive_request_id("default_key_gen_centralized-2").unwrap();
    let request_id_3 = derive_request_id("default_decompression_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, &request_id_1, 1).await;
    purge(None, None, &request_id_2, 1).await;
    purge(None, None, &request_id_3, 1).await;

    key_gen_centralized(&request_id_1, FheParameter::Default, None, None).await;
    key_gen_centralized(&request_id_2, FheParameter::Default, None, None).await;

    key_gen_centralized(
        &request_id_3,
        FheParameter::Default,
        Some(KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        }),
        Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: Some(request_id_1.into()),
            to_keyset_id_decompression_only: Some(request_id_2.into()),
        }),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn preproc_centralized(
    preproc_id: &RequestId,
    params: FheParameter,
    context_id: Option<&ContextId>,
    epoch_id: Option<&EpochId>,
    keyset_config: Option<KeySetConfig>,
    domain: &Eip712Domain,
    kms_client: &mut CoreServiceEndpointClient<Channel>,
    internal_client: &Client,
) {
    let preproc_req = internal_client
        .preproc_request(
            preproc_id,
            Some(params),
            context_id,
            epoch_id,
            keyset_config,
            domain,
        )
        .unwrap();
    let preproc_response = kms_client
        .key_gen_preproc(tonic::Request::new(preproc_req.clone()))
        .await
        .unwrap();
    assert_eq!(preproc_response.into_inner(), Empty {});

    let mut response = kms_client
        .get_key_gen_preproc_result(tonic::Request::new((*preproc_id).into()))
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete preprocessing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        response = kms_client
            .get_key_gen_preproc_result(tonic::Request::new((*preproc_id).into()))
            .await;
    }
    let inner_resp = response.unwrap().into_inner();
    assert_eq!(inner_resp.preprocessing_id, Some((*preproc_id).into()));
}

pub(crate) async fn key_gen_centralized(
    request_id: &RequestId,
    params: FheParameter,
    keyset_config: Option<KeySetConfig>,
    keyset_added_info: Option<KeySetAddedInfo>,
) {
    let dkg_params: WrappedDKGParams = params.into();

    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100 * 3, // Multiply by 3 to account for the decompression key generation case
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 1,
        preproc: 1,
        keygen: 100,
        reshare: 1,
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_params, Some(rate_limiter_conf)).await;
    run_key_gen_centralized(
        &mut kms_client,
        &internal_client,
        request_id,
        params,
        keyset_config,
        keyset_added_info,
        None,
    )
    .await;
    kms_server.assert_shutdown().await;
}

pub async fn run_key_gen_centralized(
    kms_client: &mut CoreServiceEndpointClient<Channel>,
    internal_client: &Client,
    key_req_id: &RequestId,
    params: FheParameter,
    keyset_config: Option<KeySetConfig>,
    keyset_added_info: Option<KeySetAddedInfo>,
    test_path: Option<&Path>,
) {
    let preproc_id = derive_request_id(&format!("preproc-for-request{}", key_req_id)).unwrap();
    let domain = dummy_domain();
    preproc_centralized(
        &preproc_id,
        params,
        None,
        None,
        keyset_config,
        &domain,
        kms_client,
        internal_client,
    )
    .await;

    let gen_req = internal_client
        .key_gen_request(
            key_req_id,
            &preproc_id,
            None,
            None,
            Some(params),
            keyset_config,
            keyset_added_info.clone(),
            domain.clone(),
        )
        .unwrap();
    let gen_response = kms_client
        .key_gen(tonic::Request::new(gen_req.clone()))
        .await
        .unwrap();
    assert_eq!(gen_response.into_inner(), Empty {});
    let mut response = kms_client
        .get_key_gen_result(tonic::Request::new((*key_req_id).into()))
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete key generation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        response = kms_client
            .get_key_gen_result(tonic::Request::new((*key_req_id).into()))
            .await;
    }
    let inner_resp = response.unwrap().into_inner();
    let pub_storage = FileStorage::new(test_path, StorageType::PUB, None).unwrap();
    let priv_storage = FileStorage::new(test_path, StorageType::PRIV, None).unwrap();

    let inner_config = keyset_config.unwrap_or_default();
    let keyset_type = KeySetType::try_from(inner_config.keyset_type).unwrap();

    let domain_clone = domain.clone();
    let basic_checks = async |resp: &kms_grpc::kms::v1::KeyGenResult| {
        let req_id = resp.request_id.clone().unwrap();
        let (server_key, public_key) = internal_client
            .retrieve_server_key_and_public_key(
                &preproc_id,
                key_req_id,
                resp,
                &domain_clone,
                &pub_storage,
            )
            .await
            .unwrap()
            .unwrap();

        // read the client key
        let handle: crate::engine::base::KmsFheKeyHandles = priv_storage
            .read_data(
                &req_id.clone().try_into().unwrap(),
                &PrivDataType::FhePrivateKey.to_string(),
            )
            .await
            .unwrap();
        let client_key = handle.client_key;

        let tag: tfhe::Tag = RequestId::try_from(&req_id).unwrap().into();
        assert_eq!(&tag, client_key.tag());
        assert_eq!(&tag, public_key.tag());
        assert_eq!(&tag, server_key.tag());

        crate::client::key_gen::tests::check_conformance(server_key, client_key);
    };

    match keyset_type {
        KeySetType::Standard => {
            basic_checks(&inner_resp).await;
        }
        KeySetType::DecompressionOnly => {
            // setup storage
            let keyid_1 = RequestId::from_str(
                keyset_added_info
                    .clone()
                    .unwrap()
                    .from_keyset_id_decompression_only
                    .as_ref()
                    .unwrap()
                    .request_id
                    .as_str(),
            )
            .unwrap();
            let keyid_2 = RequestId::from_str(
                keyset_added_info
                    .unwrap()
                    .to_keyset_id_decompression_only
                    .as_ref()
                    .unwrap()
                    .request_id
                    .as_str(),
            )
            .unwrap();
            let handles_1: crate::engine::base::KmsFheKeyHandles = priv_storage
                .read_data(&keyid_1, &PrivDataType::FhePrivateKey.to_string())
                .await
                .unwrap();
            let handles_2: crate::engine::base::KmsFheKeyHandles = priv_storage
                .read_data(&keyid_2, &PrivDataType::FhePrivateKey.to_string())
                .await
                .unwrap();

            // get the client key 1 and client key 2
            let client_key_1 = handles_1.client_key;
            let client_key_2 = handles_2.client_key;

            // get the server key 1
            let server_key_1: tfhe::ServerKey = internal_client
                .get_key(&keyid_1, PubDataType::ServerKey, &pub_storage)
                .await
                .unwrap();

            // get decompression key
            let decompression_key = internal_client
                .retrieve_decompression_key(&inner_resp, &pub_storage)
                .await
                .unwrap()
                .unwrap()
                .into_raw_parts();
            run_decompression_test(
                &client_key_1,
                &client_key_2,
                Some(&server_key_1),
                decompression_key,
            );
        }
    }
}
