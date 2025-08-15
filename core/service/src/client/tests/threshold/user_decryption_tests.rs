use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::client::tests::threshold::common::threshold_handles;
use crate::client::Client;
#[cfg(feature = "wasm_tests")]
use crate::client::TestingUserDecryptionTranscript;
use crate::client::{ParsedUserDecryptionRequest, ServerIdentities};
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_PARAM;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_THRESHOLD_KEY_ID_4P;
use crate::consts::TEST_PARAM;
use crate::consts::TEST_THRESHOLD_KEY_ID_10P;
use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::cryptography::internal_crypto_types::{UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::engine::validation::DSEP_USER_DECRYPTION;
#[cfg(feature = "wasm_tests")]
use crate::util::file_handling::write_element;
#[cfg(feature = "wasm_tests")]
use crate::util::key_setup::max_threshold;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext,
};
use crate::vault::storage::crypto_material::get_core_signing_key;
use crate::vault::storage::{file::FileStorage, StorageType};
#[cfg(feature = "wasm_tests")]
use kms_grpc::kms::v1::TypedPlaintext;
use kms_grpc::kms::v1::{TypedCiphertext, UserDecryptionRequest, UserDecryptionResponse};
use kms_grpc::rpc_types::protobuf_to_alloy_domain;
use kms_grpc::RequestId;
use serial_test::serial;
use std::collections::{hash_map::Entry, HashMap};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "wasm_tests")]
use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
use tokio::task::JoinSet;

#[rstest::rstest]
#[case(true, TestingPlaintext::U32(42), 10, &TEST_THRESHOLD_KEY_ID_10P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::Bool(true), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U8(88), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(false, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U80((1u128 << 80) - 1), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
#[case(false, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_threshold(
    #[case] secure: bool,
    #[case] pt: TestingPlaintext,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] decryption_mode: DecryptionMode,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        false,
        false,
        pt,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1,
        secure,
        amount_parties,
        None,
        None,
        Some(decryption_mode),
    )
    .await;
}

#[rstest::rstest]
#[case(TestingPlaintext::U32(u32::MAX), &TEST_THRESHOLD_KEY_ID_4P, vec![1])]
#[case(TestingPlaintext::U32(u32::MAX), &TEST_THRESHOLD_KEY_ID_4P, vec![4])]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_threshold_malicious(
    #[case] pt: TestingPlaintext,
    #[case] key_id: &RequestId,
    #[case] malicious_set: Vec<u32>,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        false,
        false,
        pt,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1,    // parallelism
        true, // secure
        4,    // no. of parties
        None,
        Some(malicious_set),
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[should_panic]
async fn test_user_decryption_threshold_malicious_failure() {
    // should panic because the malicious set is too big
    user_decryption_threshold(
        TEST_PARAM,
        &TEST_THRESHOLD_KEY_ID_4P,
        false,
        false,
        TestingPlaintext::U32(u32::MAX),
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1,    // parallelism
        true, // secure
        4,    // no. of parties
        None,
        Some(vec![1, 4]),
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[should_panic]
async fn test_user_decryption_threshold_all_malicious_failure() {
    // should panic because the malicious set is too big
    user_decryption_threshold(
        TEST_PARAM,
        &TEST_THRESHOLD_KEY_ID_4P,
        false,
        false,
        TestingPlaintext::U16(u16::MAX),
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1,    // parallelism
        true, // secure
        4,    // no. of parties
        None,
        Some(vec![1, 2, 3, 4]), // all parties are malicious
        None,
    )
    .await;
}

#[rstest::rstest]
#[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_threshold_precompute_sns(
    #[case] secure: bool,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] decryption_mode: DecryptionMode,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        false,
        false,
        TestingPlaintext::U8(42),
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        4,
        secure,
        amount_parties,
        None,
        None,
        Some(decryption_mode),
    )
    .await;
}

#[rstest::rstest]
#[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_threshold_precompute_sns_legacy(
    #[case] secure: bool,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] decryption_mode: DecryptionMode,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        false,
        true,
        TestingPlaintext::U8(42),
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        4,
        secure,
        amount_parties,
        None,
        None,
        Some(decryption_mode),
    )
    .await;
}

#[cfg(feature = "wasm_tests")]
#[rstest::rstest]
#[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P)]
#[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_threshold_and_write_transcript(
    #[case] secure: bool,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        true,
        false,
        TestingPlaintext::U8(42),
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1,
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "wasm_tests")]
#[rstest::rstest]
#[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_user_decryption_threshold_and_write_transcript_legacy(
    #[case] secure: bool,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        true,
        true,
        TestingPlaintext::U8(42),
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1,
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

// The transcripts only need to be 4 parties, it's used for js tests
#[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_threshold_and_write_transcript(
    #[case] msg: TestingPlaintext,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true, false)] secure: bool,
) {
    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        true,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        1, // wasm tests are single-threaded
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::Bool(true), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_threshold(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true)] secure: bool,
) {
    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_user_decryption_threshold_precompute_sns(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true)] secure: bool,
) {
    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: false,
            precompute_sns: true,
        },
        parallelism,
        secure,
        amount_parties,
        None,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_user_decryption_threshold_with_crash(
    #[case] msg: TestingPlaintext,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] party_ids_to_crash: Option<Vec<usize>>,
    #[case] key_id: &RequestId,
    #[values(true, false)] secure: bool,
) {
    user_decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        false,
        false,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        secure,
        amount_parties,
        party_ids_to_crash,
        None,
        None,
    )
    .await;
}

/// Note that the `legacy` argument is used to determine whether to use the legacy
/// user decryption request, created using [Client::user_decryption_request_legacy] or the current one.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn user_decryption_threshold(
    dkg_params: DKGParams,
    key_id: &RequestId,
    _write_transcript: bool,
    legacy: bool,
    msg: TestingPlaintext,
    enc_config: EncryptionConfig,
    parallelism: usize,
    secure: bool,
    amount_parties: usize,
    party_ids_to_crash: Option<Vec<usize>>,
    malicious_parties: Option<Vec<u32>>,
    decryption_mode: Option<DecryptionMode>,
) {
    assert!(parallelism > 0);
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, mut kms_clients, mut internal_client) =
        threshold_handles(dkg_params, amount_parties, true, None, decryption_mode).await;
    let (ct, ct_format, fhe_type) =
        compute_cipher_from_stored_key(None, msg, key_id, enc_config).await;

    // make requests
    let reqs: Vec<_> = (0..parallelism)
        .map(|j| {
            let request_id = derive_request_id(&format!("TEST_USER_DECRYPT_ID_{j}")).unwrap();
            let typed_ciphertexts = vec![TypedCiphertext {
                ciphertext: ct.clone(),
                fhe_type: fhe_type as i32,
                ciphertext_format: ct_format.into(),
                external_handle: j.to_be_bytes().to_vec(),
            }];
            let (req, enc_pk, enc_sk) = if legacy {
                internal_client
                    .user_decryption_request_legacy(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        &key_id.to_string().try_into().unwrap(),
                    )
                    .unwrap()
            } else {
                internal_client
                    .user_decryption_request(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        &key_id.to_string().try_into().unwrap(),
                    )
                    .unwrap()
            };
            (req, enc_pk, enc_sk)
        })
        .collect();
    // Either send the request, or crash the party if it's in
    // party_ids_to_crash
    let mut req_tasks = JoinSet::new();
    let party_ids_to_crash = party_ids_to_crash.unwrap_or_default();
    for j in 0..parallelism {
        for i in 1..=amount_parties as u32 {
            if party_ids_to_crash.contains(&(i as usize)) {
                // After the first "parallel" iteration the party is already crashed
                if j > 0 {
                    continue;
                }
                let server_handle = kms_servers.remove(&i).unwrap();
                server_handle.assert_shutdown().await;
                let _kms_client = kms_clients.remove(&i).unwrap();
            } else {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_clone = reqs.get(j).as_ref().unwrap().0.clone();
                req_tasks.spawn(async move {
                    cur_client
                        .user_decrypt(tonic::Request::new(req_clone))
                        .await
                });
            }
        }
    }
    let mut req_response_vec = Vec::new();
    while let Some(resp) = req_tasks.join_next().await {
        req_response_vec.push(resp.unwrap().unwrap().into_inner());
    }
    assert_eq!(
        req_response_vec.len(),
        (amount_parties - party_ids_to_crash.len()) * parallelism
    );

    let mut resp_tasks = JoinSet::new();
    for j in 0..parallelism {
        for i in 1..=amount_parties as u32 {
            if party_ids_to_crash.contains(&(i as usize)) {
                continue;
            }
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_id_clone = reqs.get(j).as_ref().unwrap().0.clone().request_id.unwrap();
            let bits = msg.bits() as u64;
            resp_tasks.spawn(async move {
                // Sleep to give the server some time to complete user decryption
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    100 * bits * parallelism as u64,
                ))
                .await;
                let mut response = cur_client
                    .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;

                let mut ctr = 0u64;
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    // wait for 4*bits ms before the next query, but at least 100ms and at most 1s.
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        4 * bits.clamp(100, 1000),
                    ))
                    .await;
                    // do at most 600 retries (stop after max. 10 minutes for large types)
                    if ctr >= 600 {
                        panic!("timeout while waiting for user decryption");
                    }
                    ctr += 1;
                    response = cur_client
                        .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                (req_id_clone, response)
            });
        }
    }
    let mut response_map: HashMap<RequestId, Vec<UserDecryptionResponse>> = HashMap::new();
    while let Some(res) = resp_tasks.join_next().await {
        let res = res.unwrap();
        tracing::info!("Client got a response from {}", res.0.request_id);
        let (req_id, resp) = res;
        if let Entry::Vacant(e) = response_map.entry(req_id.clone().into()) {
            e.insert(vec![resp.unwrap().into_inner()]);
        } else {
            response_map
                .get_mut(&req_id.into())
                .unwrap()
                .push(resp.unwrap().into_inner());
        }
    }

    #[cfg(feature = "wasm_tests")]
    {
        assert_eq!(parallelism, 1);
        // Compute threshold < amount_parties/3
        let threshold = max_threshold(amount_parties);
        if _write_transcript {
            // We write a plaintext/ciphertext to file as a workaround
            // for tfhe encryption on the wasm side since it cannot
            // be instantiated easily without a seeder and we don't
            // want to introduce extra npm dependency.

            // Observe there should only be one element in `response_map`
            let agg_resp = response_map.values().last().unwrap().clone();

            let transcript = TestingUserDecryptionTranscript {
                server_addrs: internal_client.get_server_addrs(),
                client_address: internal_client.client_address,
                client_sk: internal_client.client_sk.clone(),
                degree: threshold as u32,
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
                agg_resp,
            };
            let path_prefix = if dkg_params != PARAMS_TEST_BK_SNS {
                if legacy {
                    crate::consts::DEFAULT_THRESHOLD_WASM_TRANSCRIPT_LEGACY_PATH
                } else {
                    crate::consts::DEFAULT_THRESHOLD_WASM_TRANSCRIPT_PATH
                }
            } else if legacy {
                crate::consts::TEST_THRESHOLD_WASM_TRANSCRIPT_LEGACY_PATH
            } else {
                crate::consts::TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
            };
            let path = format!("{}.{}", path_prefix, msg.bits());
            write_element(&path, &transcript).await.unwrap();
        }
    }

    let server_private_keys = get_server_private_keys(amount_parties).await;

    process_batch_threshold_user_decryption(
        &mut internal_client,
        msg,
        secure,
        amount_parties,
        malicious_parties,
        party_ids_to_crash,
        reqs,
        response_map,
        server_private_keys,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn process_batch_threshold_user_decryption(
    internal_client: &mut Client,
    msg: TestingPlaintext,
    secure: bool,
    amount_parties: usize,
    malicious_parties: Option<Vec<u32>>,
    party_ids_to_crash: Vec<usize>,
    reqs: Vec<(
        UserDecryptionRequest,
        UnifiedPublicEncKey,
        UnifiedPrivateEncKey,
    )>,
    response_map: HashMap<RequestId, Vec<UserDecryptionResponse>>,
    server_private_keys: HashMap<u32, PrivateSigKey>,
) {
    for req in &reqs {
        let (req, enc_pk, enc_sk) = req;
        let request_id = req
            .request_id
            .clone()
            .expect("Retrieving request_id failed");
        let mut responses = response_map
            .get(&request_id.into())
            .expect("Retrieving responses failed")
            .clone();
        let domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap())
            .expect("Retrieving domain failed");
        let client_req = ParsedUserDecryptionRequest::try_from(req)
            .expect("Parsing UserDecryptionRequest failed");
        let threshold = responses.first().unwrap().payload.as_ref().unwrap().degree as usize;
        // NOTE: throw away one response and it should still work.
        let plaintexts = if secure {
            // test with one fewer response if we haven't crashed too many parties already
            let result_from_dropped_response = if threshold > party_ids_to_crash.len() {
                Some(
                    internal_client
                        .process_user_decryption_resp(
                            &client_req,
                            &domain,
                            &responses[1..],
                            enc_pk,
                            enc_sk,
                        )
                        .unwrap(),
                )
            } else {
                None
            };

            // modify the responses if there are malicious parties
            // note that we also need to sign the modified payload
            responses.iter_mut().for_each(|resp| {
                if let Some(payload) = &mut resp.payload {
                    if let Some(mal_parties) = &malicious_parties {
                        if mal_parties.contains(&payload.party_id) {
                            let orig_party_id = payload.party_id;
                            // Modify the party ID maliciously
                            if payload.party_id == 1 {
                                payload.party_id = amount_parties as u32;
                            } else {
                                payload.party_id -= 1;
                            }
                            let sig_payload_vec = bc2wrap::serialize(&payload).unwrap();
                            let sig = crate::cryptography::signcryption::internal_sign(
                                &DSEP_USER_DECRYPTION,
                                &sig_payload_vec,
                                &server_private_keys[&orig_party_id],
                            )
                            .unwrap();
                            resp.signature = sig.sig.to_vec();
                        }
                    }
                }
            });

            // test with all responses, some may be malicious
            let final_result = internal_client
                .process_user_decryption_resp(&client_req, &domain, &responses, enc_pk, enc_sk)
                .unwrap();

            if let Some(res) = result_from_dropped_response {
                assert_eq!(res, final_result)
            }
            final_result
        } else {
            // insecure processing
            internal_client.server_identities = ServerIdentities::Addrs(HashMap::new());
            // test with one fewer response if we haven't crashed too many parties already
            let result_from_dropped_response = if threshold > party_ids_to_crash.len() {
                Some(
                    internal_client
                        .insecure_process_user_decryption_resp(&responses[1..], enc_pk, enc_sk)
                        .unwrap(),
                )
            } else {
                None
            };

            // test with all responses
            let final_result = internal_client
                .insecure_process_user_decryption_resp(&responses, enc_pk, enc_sk)
                .unwrap();
            if let Some(res) = result_from_dropped_response {
                assert_eq!(res, final_result)
            }
            final_result
        };
        for plaintext in plaintexts {
            crate::client::tests::common::assert_plaintext(&msg, &plaintext);
        }
    }
}

async fn get_server_private_keys(amount_parties: usize) -> HashMap<u32, PrivateSigKey> {
    let mut server_private_keys = HashMap::new();
    for i in 1..=amount_parties {
        let priv_storage =
            FileStorage::new(None, StorageType::PRIV, Some(Role::indexed_from_one(i))).unwrap();
        let sk = get_core_signing_key(&priv_storage)
            .await
            .inspect_err(|e| {
                tracing::error!("signing key hashmap is not exactly 1, {}", e);
            })
            .unwrap();
        server_private_keys.insert(i as u32, sk);
    }
    server_private_keys
}
