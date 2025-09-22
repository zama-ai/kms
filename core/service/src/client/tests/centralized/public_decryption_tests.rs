use crate::client::client_wasm::Client;
use crate::client::test_tools::centralized_handles;
use crate::client::tests::common::{assert_plaintext, TIME_TO_SLEEP_MS};
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_CENTRAL_KEY_ID;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_PARAM;
use crate::consts::TEST_CENTRAL_KEY_ID;
use crate::consts::TEST_PARAM;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext,
};
use kms_grpc::kms::v1::{Empty, TypedCiphertext};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::RequestId;
use serial_test::serial;
use std::path::Path;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::task::JoinSet;
use tonic::transport::Channel;

#[tokio::test]
#[serial]
async fn test_decryption_central() {
    decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        vec![
            TestingPlaintext::U8(42),
            TestingPlaintext::U32(9876),
            TestingPlaintext::U16(420),
            TestingPlaintext::Bool(true),
        ],
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        3, // 3 parallel requests
    )
    .await;
}

#[tokio::test]
#[serial]
async fn test_decryption_central_no_decompression() {
    decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        vec![
            TestingPlaintext::U8(42),
            TestingPlaintext::U32(9876),
            TestingPlaintext::U16(420),
            TestingPlaintext::Bool(true),
        ],
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        3, // 3 parallel requests
    )
    .await;
}

#[tokio::test]
#[serial]
async fn test_decryption_central_precompute_sns() {
    decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        vec![
            TestingPlaintext::U8(42),
            TestingPlaintext::U32(9876),
            TestingPlaintext::U16(420),
            TestingPlaintext::Bool(true),
            TestingPlaintext::U80((1u128 << 80) - 1),
        ],
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        3, // 3 parallel requests
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 4)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_decryption_centralized(
    #[case] msgs: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
) {
    decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        msgs,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 4)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_decryption_centralized_precompute_sns(
    #[case] msgs: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
) {
    decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        msgs,
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        parallelism,
    )
    .await;
}

pub(crate) async fn decryption_centralized(
    dkg_params: &DKGParams,
    key_id: &RequestId,
    msgs: Vec<TestingPlaintext>,
    encryption_config: EncryptionConfig,
    parallelism: usize,
) {
    assert!(parallelism > 0);
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, kms_client, mut internal_client) = centralized_handles(dkg_params, None).await;
    run_decryption_centralized(
        &kms_client,
        &mut internal_client,
        key_id,
        msgs,
        encryption_config,
        parallelism,
        None,
    )
    .await;
    kms_server.assert_shutdown().await;
}

pub(crate) async fn run_decryption_centralized(
    kms_client: &CoreServiceEndpointClient<Channel>,
    internal_client: &mut Client,
    key_id: &RequestId,
    msgs: Vec<TestingPlaintext>,
    encryption_config: EncryptionConfig,
    parallelism: usize,
    test_path: Option<&Path>,
) {
    let mut cts = Vec::new();
    for (i, msg) in msgs.clone().into_iter().enumerate() {
        let (ct, ct_format, fhe_type) =
            compute_cipher_from_stored_key(test_path, msg, key_id, 1, encryption_config).await;
        let ctt = TypedCiphertext {
            ciphertext: ct,
            fhe_type: fhe_type as i32,
            ciphertext_format: ct_format.into(),
            external_handle: i.to_be_bytes().to_vec(),
        };
        cts.push(ctt);
    }
    // build parallel requests
    let reqs: Vec<_> = (0..parallelism)
        .map(|j: usize| {
            let request_id = derive_request_id(&format!("TEST_DEC_ID_{key_id}_{j}")).unwrap();
            internal_client
                .public_decryption_request(cts.clone(), &dummy_domain(), &request_id, key_id)
                .unwrap()
        })
        .collect();

    // send all decryption requests simultaneously
    let mut req_tasks = JoinSet::new();
    for j in 0..parallelism {
        let req_cloned = reqs.get(j).unwrap().clone();
        let mut cur_client = kms_client.clone();
        req_tasks.spawn(async move {
            cur_client
                .public_decrypt(tonic::Request::new(req_cloned))
                .await
        });
    }

    // collect request task responses
    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(req_response_vec.len(), parallelism);

    // check that initial request responses are all Empty
    for rr in req_response_vec {
        assert_eq!(rr, Empty {});
    }

    // query for decryption responses
    let mut resp_tasks = JoinSet::new();
    for req in &reqs {
        let req_id_clone = req.request_id.as_ref().unwrap().clone();
        let mut cur_client = kms_client.clone();
        resp_tasks.spawn(async move {
            // Sleep initially to give the server some time to complete the decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            // send query
            let mut response = cur_client
                .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                .await;

            // retry counter
            let mut ctr = 0_u64;

            // retry while decryption is not finished, wait between retries and only up to a maximum number of retries
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                // we may wait up to 50s for tests (include slow profiles), for big ciphertexts
                if ctr >= 1000 {
                    panic!("timeout while waiting for decryption result");
                }
                ctr += 1;
                response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
            }

            // we have a valid response or some error happened, return this
            (req_id_clone, response.unwrap().into_inner())
        });
    }

    // collect decryption outputs
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        resp_response_vec.push(resp.unwrap());
    }

    // go through all requests and check the corresponding responses
    for req in &reqs {
        let req_id = req.request_id.as_ref().unwrap();
        let responses: Vec<_> = resp_response_vec
            .iter()
            .filter_map(|resp| {
                if resp.0 == *req_id {
                    Some(resp.1.clone())
                } else {
                    None
                }
            })
            .collect();

        // we only have single response per request in the centralized case
        assert_eq!(responses.len(), 1);

        let received_plaintexts = internal_client
            .process_decryption_resp(Some(req.clone()), &responses, 1)
            .unwrap();

        // we need 1 plaintext for each ciphertext in the batch
        assert_eq!(received_plaintexts.len(), msgs.len());

        // check that the plaintexts are correct
        for (i, plaintext) in received_plaintexts.iter().enumerate() {
            assert_plaintext(&msgs[i], plaintext);
        }
    }
}
