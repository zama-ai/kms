use crate::client::tests::common::TIME_TO_SLEEP_MS;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_CENTRAL_KEY_ID;
use crate::consts::TEST_CENTRAL_KEY_ID;
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
use crate::dummy_domain;
use crate::engine::base::{derive_request_id, CENTRALIZED_DUMMY_PREPROCESSING_ID};
use crate::util::key_setup::test_tools::purge;
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::StorageReader;
use crate::vault::storage::{file::FileStorage, StorageType};
use kms_grpc::kms::v1::{Empty, FheParameter, KeySetAddedInfo, KeySetConfig, KeySetType};
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::RequestId;
use serial_test::serial;
use std::str::FromStr;

use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_key_gen_centralized() {
    let request_id = derive_request_id("test_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &request_id, 1).await;
    key_gen_centralized(&request_id, FheParameter::Test, None, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_decompression_key_gen_centralized() {
    let request_id_1 = derive_request_id("test_key_gen_centralized-1").unwrap();
    let request_id_2 = derive_request_id("test_key_gen_centralized-2").unwrap();
    let request_id_3 = derive_request_id("test_decompression_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &request_id_1, 1).await;
    purge(None, None, None, &request_id_2, 1).await;
    purge(None, None, None, &request_id_3, 1).await;

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
            base_keyset_id_for_sns_compression_key: None,
        }),
    )
    .await;
}

// TODO(2674)
// test centralized sns compression keygen using the testing parameters
// this test will use an existing base key stored under the key ID `TEST_CENTRAL_KEY_ID`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_sns_compression_key_gen_centralized() {
    let request_id = derive_request_id("test_sns_compression_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &request_id, 1).await;
    key_gen_centralized(
        &request_id,
        FheParameter::Test,
        None,
        Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
            base_keyset_id_for_sns_compression_key: Some((*TEST_CENTRAL_KEY_ID).into()),
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
    purge(None, None, None, &request_id, 1).await;
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
    purge(None, None, None, &request_id_1, 1).await;
    purge(None, None, None, &request_id_2, 1).await;
    purge(None, None, None, &request_id_3, 1).await;

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
            base_keyset_id_for_sns_compression_key: None,
        }),
    )
    .await;
}

// TODO(2674)
// test centralized sns compression keygen using the default parameters
// this test will use an existing base key stored under the key ID `DEFAULT_CENTRAL_KEY_ID`
#[cfg(feature = "slow_tests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_sns_compression_key_gen_centralized() {
    let request_id = derive_request_id("default_sns_compression_key_gen_centralized").unwrap();
    // Delete potentially old data
    purge(None, None, None, &request_id, 1).await;
    key_gen_centralized(
        &request_id,
        FheParameter::Test,
        None,
        Some(KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
            base_keyset_id_for_sns_compression_key: Some((*DEFAULT_CENTRAL_KEY_ID).into()),
        }),
    )
    .await;
}

async fn key_gen_centralized(
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
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, mut kms_client, internal_client) =
        crate::client::test_tools::centralized_handles(&dkg_params, Some(rate_limiter_conf)).await;

    let domain = dummy_domain();
    let gen_req = internal_client
        .key_gen_request(
            request_id,
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
        .get_key_gen_result(tonic::Request::new((*request_id).into()))
        .await;
    while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable {
        // Sleep to give the server some time to complete key generation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        response = kms_client
            .get_key_gen_result(tonic::Request::new((*request_id).into()))
            .await;
    }
    let inner_resp = response.unwrap().into_inner();
    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();

    let inner_config = keyset_config.unwrap_or_default();
    let keyset_type = KeySetType::try_from(inner_config.keyset_type).unwrap();

    let domain_clone = domain.clone();
    let basic_checks = async |resp: &kms_grpc::kms::v1::KeyGenResult| {
        let req_id = resp.request_id.clone().unwrap();
        let preproc_id = &CENTRALIZED_DUMMY_PREPROCESSING_ID;
        let (server_key, _public_key) = internal_client
            .retrieve_server_key_and_public_key(
                preproc_id,
                request_id,
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
                &req_id.try_into().unwrap(),
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .unwrap();
        let client_key = handle.client_key;

        crate::client::key_gen::tests::check_conformance(server_key, client_key);
    };

    match keyset_type {
        KeySetType::Standard => {
            basic_checks(&inner_resp).await;
        }
        KeySetType::AddSnsCompressionKey => {
            basic_checks(&inner_resp).await;

            // check that the integer server key are the same, before and after the sns compression key gen
            let new_keyset_id: RequestId = keyset_added_info
                .clone()
                .unwrap()
                .base_keyset_id_for_sns_compression_key
                .unwrap()
                .try_into()
                .unwrap();
            crate::client::key_gen::tests::identical_keys_except_sns_compression_from_storage(
                &internal_client,
                &pub_storage,
                request_id,
                &new_keyset_id,
            )
            .await;
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
                .read_data(&keyid_1, &PrivDataType::FheKeyInfo.to_string())
                .await
                .unwrap();
            let handles_2: crate::engine::base::KmsFheKeyHandles = priv_storage
                .read_data(&keyid_2, &PrivDataType::FheKeyInfo.to_string())
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

    kms_server.assert_shutdown().await;
}
