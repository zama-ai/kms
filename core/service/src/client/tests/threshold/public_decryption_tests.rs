use crate::client::tests::common::TIME_TO_SLEEP_MS;
use crate::client::tests::threshold::common::threshold_handles;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_PARAM;
#[cfg(feature = "slow_tests")]
use crate::consts::DEFAULT_THRESHOLD_KEY_ID_4P;
use crate::consts::TEST_PARAM;
use crate::consts::TEST_THRESHOLD_KEY_ID_10P;
use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
use crate::dummy_domain;
use crate::engine::base::derive_request_id;
use crate::util::key_setup::max_threshold;
use crate::util::key_setup::test_tools::{
    compute_cipher_from_stored_key, EncryptionConfig, TestingPlaintext,
};
use crate::util::rate_limiter::RateLimiterConfig;
use kms_grpc::kms::v1::TypedCiphertext;
use kms_grpc::RequestId;
use serial_test::serial;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(10, &TEST_THRESHOLD_KEY_ID_10P, DecryptionMode::NoiseFloodSmall)]
#[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
#[serial]
async fn test_decryption_threshold_no_decompression(
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] decryption_mode: DecryptionMode,
) {
    decryption_threshold(
        TEST_PARAM,
        key_id,
        vec![
            TestingPlaintext::U8(u8::MAX),
            TestingPlaintext::U8(2),
            TestingPlaintext::U16(444),
        ],
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        1,
        amount_parties,
        None,
        Some(decryption_mode),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(10, &TEST_THRESHOLD_KEY_ID_10P, DecryptionMode::NoiseFloodSmall)]
#[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
#[serial]
async fn test_decryption_threshold(
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] decryption_mode: DecryptionMode,
) {
    decryption_threshold(
        TEST_PARAM,
        key_id,
        vec![
            TestingPlaintext::U8(u8::MAX),
            TestingPlaintext::U8(2),
            TestingPlaintext::U16(444),
        ],
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        2,
        amount_parties,
        None,
        Some(decryption_mode),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[rstest::rstest]
#[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[serial]
async fn test_decryption_threshold_precompute_sns(
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[case] decryption_mode: DecryptionMode,
    #[values(true, false)] compression: bool,
) {
    decryption_threshold(
        TEST_PARAM,
        key_id,
        vec![
            TestingPlaintext::U8(u8::MAX),
            TestingPlaintext::U8(2),
            TestingPlaintext::U16(444),
        ],
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        2,
        amount_parties,
        None,
        Some(decryption_mode),
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::Bool(true), TestingPlaintext::U8(u8::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_decryption_threshold(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        amount_parties,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_decryption_threshold_precompute_sns(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
    #[values(true, false)] compression: bool,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression,
            precompute_sns: true,
        },
        parallelism,
        amount_parties,
        None,
        None,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[rstest::rstest]
#[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn default_decryption_threshold_with_crash(
    #[case] msg: Vec<TestingPlaintext>,
    #[case] parallelism: usize,
    #[case] amount_parties: usize,
    #[case] party_ids_to_crash: Option<Vec<usize>>,
    #[case] key_id: &RequestId,
) {
    decryption_threshold(
        DEFAULT_PARAM,
        key_id,
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: false,
        },
        parallelism,
        amount_parties,
        party_ids_to_crash,
        None,
    )
    .await;
}

#[expect(clippy::too_many_arguments)]
pub async fn decryption_threshold(
    dkg_params: DKGParams,
    key_id: &RequestId,
    msgs: Vec<TestingPlaintext>,
    enc_config: EncryptionConfig,
    parallelism: usize,
    amount_parties: usize,
    party_ids_to_crash: Option<Vec<usize>>,
    decryption_mode: Option<DecryptionMode>,
) {
    assert!(parallelism > 0);
    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100 * parallelism,
        pub_decrypt: 100,
        user_decrypt: 1,
        crsgen: 1,
        preproc: 1,
        keygen: 1,
    };
    let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
        dkg_params,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        decryption_mode,
        false,
    )
    .await;
    let mut cts = Vec::new();
    let mut bits = 0;
    for (i, msg) in msgs.clone().into_iter().enumerate() {
        let (ct, ct_format, fhe_type) =
            compute_cipher_from_stored_key(None, msg, key_id, enc_config).await;
        let ctt = TypedCiphertext {
            ciphertext: ct,
            fhe_type: fhe_type as i32,
            ciphertext_format: ct_format.into(),
            external_handle: i.to_be_bytes().to_vec(),
        };
        cts.push(ctt);
        bits += msg.bits() as u64;
    }

    // make parallel requests by calling [decrypt] in a thread
    let mut req_tasks = JoinSet::new();
    let reqs: Vec<_> = (0..parallelism)
        .map(|j| {
            let request_id = derive_request_id(&format!("TEST_DEC_ID_{j}")).unwrap();

            internal_client
                .public_decryption_request(cts.clone(), &dummy_domain(), &request_id, key_id)
                .unwrap()
        })
        .collect();

    // Either send the request, or crash the party if it's in
    // party_ids_to_crash
    let party_ids_to_crash = party_ids_to_crash.unwrap_or_default();
    for i in 1..=amount_parties as u32 {
        if party_ids_to_crash.contains(&(i as usize)) {
            let server_handle = kms_servers.remove(&i).unwrap();
            server_handle.assert_shutdown().await;
            let _kms_client = kms_clients.remove(&i).unwrap();
        } else {
            for j in 0..parallelism {
                let req_cloned = reqs.get(j).unwrap().clone();
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                req_tasks.spawn(async move {
                    cur_client
                        .public_decrypt(tonic::Request::new(req_cloned))
                        .await
                });
            }
        }
    }

    let mut req_response_vec = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        req_response_vec.push(inner.unwrap().unwrap().into_inner());
    }
    assert_eq!(
        req_response_vec.len(),
        (amount_parties - party_ids_to_crash.len()) * parallelism
    );

    // get all responses
    let mut resp_tasks = JoinSet::new();
    for i in 1..=amount_parties as u32 {
        if party_ids_to_crash.contains(&(i as usize)) {
            continue;
        }
        for req in &reqs {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_id_clone = req.request_id.as_ref().unwrap().clone();
            resp_tasks.spawn(async move {
                // Sleep to give the server some time to complete decryption
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    100 * bits * parallelism as u64,
                ))
                .await;

                let mut response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
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
                        panic!("timeout while waiting for decryption");
                    }
                    ctr += 1;
                    response = cur_client
                        .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }
                (req_id_clone, response.unwrap().into_inner())
            });
        }
    }

    let mut resp_response_vec = Vec::new();
    while let Some(resp) = resp_tasks.join_next().await {
        resp_response_vec.push(resp.unwrap());
    }

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
        // Compute threshold < amount_parties/3
        let threshold = max_threshold(amount_parties);
        let min_count_agree = (threshold + 1) as u32;
        let received_plaintexts = internal_client
            .process_decryption_resp(Some(req.clone()), &responses, min_count_agree)
            .unwrap();

        // we need 1 plaintext for each ciphertext in the batch
        assert_eq!(received_plaintexts.len(), msgs.len());

        // check that the plaintexts are correct
        for (i, plaintext) in received_plaintexts.iter().enumerate() {
            crate::client::tests::common::assert_plaintext(&msgs[i], plaintext);
        }
    }
}
