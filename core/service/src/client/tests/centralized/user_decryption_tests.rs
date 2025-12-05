use crate::client::client_wasm::ServerIdentities;
use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::client::user_decryption_wasm::ParsedUserDecryptionRequest;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_CENTRAL_KEY_ID;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_PARAM;
use crate::consts::TEST_CENTRAL_KEY_ID;
use crate::consts::TEST_PARAM;
use crate::cryptography::encryption::PkeSchemeType;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext,
};
use kms_grpc::kms::v1::{Empty, TypedCiphertext};
use kms_grpc::rpc_types::protobuf_to_alloy_domain;
use kms_grpc::RequestId;
use serial_test::serial;
use std::collections::HashMap;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::task::JoinSet;

#[rstest::rstest]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_centralized(#[values(true, false)] secure: bool) {
    user_decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        false,
        false,
        TestingPlaintext::U8(48),
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        4,
        secure,
    )
    .await;
}

#[rstest::rstest]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_centralized_precompute_sns(
    #[values(true, false)] secure: bool,
    #[values(true, false)] compression: bool,
) {
    user_decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        false,
        false,
        TestingPlaintext::U8(48),
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        4,
        secure,
    )
    .await;
}

#[rstest::rstest]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_centralized_precompute_sns_legacy(
    #[values(true, false)] secure: bool,
    #[values(true, false)] compression: bool,
) {
    user_decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        false,
        true,
        TestingPlaintext::U8(48),
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        4,
        secure,
    )
    .await;
}

// The transcripts only need to be 4 parties, it's used for js tests
#[cfg(feature = "wasm_tests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_user_decryption_centralized_and_write_transcript() {
    user_decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        true,
        false,
        TestingPlaintext::U8(48),
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        1, // wasm tests are single-threaded
        true,
    )
    .await;
}

#[cfg(feature = "wasm_tests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn test_user_decryption_centralized_and_write_transcript_legacy() {
    user_decryption_centralized(
        &TEST_PARAM,
        &TEST_CENTRAL_KEY_ID,
        true,
        true,
        TestingPlaintext::U8(48),
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        1, // wasm tests are single-threaded
        true,
    )
    .await;
}

// Only need to run once for the transcript
#[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_centralized_and_write_transcript() {
    let msg = TestingPlaintext::U8(u8::MAX);
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        true,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        1, // wasm tests are single-threaded
        true,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_centralized(#[values(true, false)] secure: bool) {
    let msg = TestingPlaintext::U8(u8::MAX);
    let parallelism = 1;
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_centralized_no_compression(#[values(true, false)] secure: bool) {
    let msg = TestingPlaintext::U8(u8::MAX);
    let parallelism = 1;
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        parallelism,
        secure,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_centralized_precompute_sns(
    #[values(true, false)] secure: bool,
    #[values(true, false)] compression: bool,
) {
    let msg = TestingPlaintext::U8(u8::MAX);
    let parallelism = 1;
    user_decryption_centralized(
        &DEFAULT_PARAM,
        &DEFAULT_CENTRAL_KEY_ID,
        false,
        false,
        msg,
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        parallelism,
        secure,
    )
    .await;
}

/// Note that the `legacy` argument is used to determine whether to use the legacy
/// user decryption request, i.e using MlKem1024 and bincode2 serialization.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn user_decryption_centralized(
    dkg_params: &DKGParams,
    key_id: &RequestId,
    _write_transcript: bool,
    legacy: bool,
    msg: TestingPlaintext,
    enc_config: EncryptionConfig,
    parallelism: usize,
    secure: bool,
) {
    assert!(parallelism > 0);
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (kms_server, kms_client, mut internal_client) =
        crate::client::test_tools::centralized_handles(dkg_params, None).await;
    let (ct, ct_format, fhe_type) =
        compute_cipher_from_stored_key(None, msg, key_id, None, enc_config).await;

    // The following lines are used to generate integration test-code with javascript for test `new client` in test.js
    // println!(
    //     "Client PK {:?}",
    //     internal_client.client_pk.pk.to_sec1_bytes()
    // );
    // for key in internal_client.server_pks.keys() {
    //     println!("Server PK {:?}", key.pk.to_sec1_bytes());
    // }

    // build parallel requests
    let reqs: Vec<_> = (0..parallelism)
        .map(|j| {
            let typed_ciphertexts = vec![TypedCiphertext {
                ciphertext: ct.clone(),
                fhe_type: fhe_type as i32,
                ciphertext_format: ct_format.into(),
                external_handle: j.to_be_bytes().to_vec(),
            }];
            let request_id = derive_request_id(&format!("TEST_USER_DECRYPT_ID_{j}")).unwrap();

            // This is the legacy version of the user decryption request
            // where the encryption key is MlKem1024 serialized using bincode2.
            // The normal version [Self::user_decryption_request] uses MlKem512 uses safe serialization.
            if legacy {
                internal_client
                    .user_decryption_request(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        key_id,
                        None,
                        PkeSchemeType::MlKem1024,
                    )
                    .unwrap()
            } else {
                internal_client
                    .user_decryption_request(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        key_id,
                        None,
                        PkeSchemeType::MlKem512,
                    )
                    .unwrap()
            }
        })
        .collect();

    // send all user decryption requests simultaneously
    let mut req_tasks = JoinSet::new();
    for j in 0..parallelism {
        let req_cloned = reqs.get(j).unwrap().0.clone();
        let mut cur_client = kms_client.clone();
        req_tasks.spawn(async move {
            cur_client
                .user_decrypt(tonic::Request::new(req_cloned))
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

    // query for user decryption responses
    let mut resp_tasks = JoinSet::new();
    for req in &reqs {
        let req_id_clone = req.0.request_id.as_ref().unwrap().clone();
        let mut cur_client = kms_client.clone();
        resp_tasks.spawn(async move {
            // Sleep initially to give the server some time to complete the user decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            // send query
            let mut response = cur_client
                .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                .await;

            // retry counter
            let mut ctr = 0_u64;

            // retry while user decryption is not finished, wait between retries and only up to a maximum number of retries
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                // we may wait up to 50s for tests (include slow profiles), for big ciphertexts
                if ctr >= 1000 {
                    panic!("timeout while waiting for user deccryption result");
                }
                ctr += 1;
                response = cur_client
                    .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
            }

            // we have a valid response or some error happened, return this
            (req_id_clone, response.unwrap().into_inner())
        });
    }

    // collect user deccryption outputs
    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        resp_response_vec.push(resp.unwrap());
    }

    #[cfg(feature = "wasm_tests")]
    {
        assert_eq!(parallelism, 1);
        if _write_transcript {
            // We write a plaintext/ciphertext to file as a workaround
            // for tfhe encryption on the wasm side since it cannot
            // be instantiated easily without a seeder and we don't
            // want to introduce extra npm dependency.

            use kms_grpc::kms::v1::TypedPlaintext;
            use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;

            use crate::{
                client::user_decryption_wasm::TestingUserDecryptionTranscript,
                util::file_handling::write_element,
            };
            let transcript = TestingUserDecryptionTranscript {
                server_addrs: internal_client.get_server_addrs(),
                client_address: internal_client.client_address,
                client_sk: internal_client.client_sk.clone(),
                degree: 0,
                params: internal_client.params,
                fhe_types: vec![msg.fhe_type() as i32],
                pts: vec![TypedPlaintext::from(msg).bytes.clone()],
                cts: reqs[0]
                    .0
                    .typed_ciphertexts
                    .iter()
                    .map(|typed_ct| typed_ct.ciphertext.clone())
                    .collect::<Vec<_>>(),
                request: Some(reqs[0].clone().0),
                eph_sk: reqs[0].clone().2,
                eph_pk: reqs[0].clone().1,
                agg_resp: vec![resp_response_vec.first().unwrap().1.clone()],
            };

            let path_prefix = if *dkg_params != PARAMS_TEST_BK_SNS {
                if legacy {
                    crate::consts::DEFAULT_CENTRAL_WASM_TRANSCRIPT_LEGACY_PATH
                } else {
                    crate::consts::DEFAULT_CENTRAL_WASM_TRANSCRIPT_PATH
                }
            } else if legacy {
                crate::consts::TEST_CENTRAL_WASM_TRANSCRIPT_LEGACY_PATH
            } else {
                crate::consts::TEST_CENTRAL_WASM_TRANSCRIPT_PATH
            };
            let path = format!("{}.{}", path_prefix, msg.bits());
            write_element(&path, &transcript).await.unwrap();
        }
    }

    // go through all requests and check the corresponding responses
    for req in &reqs {
        let (req, enc_pk, enc_sk) = req;
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
        let inner_response = responses.first().unwrap();
        let responses = vec![inner_response.clone()];

        let eip712_domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap()).unwrap();
        let client_request = ParsedUserDecryptionRequest::try_from(req).unwrap();
        let plaintexts = if secure {
            internal_client
                .process_user_decryption_resp(
                    &client_request,
                    &eip712_domain,
                    &responses,
                    enc_pk,
                    enc_sk,
                )
                .unwrap()
        } else {
            internal_client.server_identities =
                    // one dummy address is needed to force insecure_process_user_decryption_resp
                    // in the centralized mode
                    ServerIdentities::Addrs(HashMap::from_iter([(1, alloy_primitives::address!(
                        "d8da6bf26964af9d7eed9e03e53415d37aa96045"
                    ))]));
            internal_client
                .insecure_process_user_decryption_resp(&responses, enc_pk, enc_sk)
                .unwrap()
        };

        for plaintext in plaintexts {
            crate::client::tests::common::assert_plaintext(&msg, &plaintext);
        }
    }

    kms_server.assert_shutdown().await;
}
