use crate::client::client_wasm::{Client, ServerIdentities};
use crate::client::tests::common::{PollConfig, retrying_poll};
use crate::client::user_decryption_wasm::ParsedUserDecryptionRequest;
#[cfg(feature = "wasm_tests")]
use crate::client::user_decryption_wasm::TestingUserDecryptionTranscript;
use crate::consts::DEFAULT_PARAM;
use crate::consts::DEFAULT_THRESHOLD_KEY_ID_4P;
use crate::consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, TEST_PARAM};
use crate::consts::{PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, TEST_THRESHOLD_KEY_ID_4P};
use crate::cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::cryptography::signatures::{PrivateSigKey, internal_sign};
use crate::cryptography::signcryption::{
    SigncryptFHEPlaintext, UnifiedSigncryptionKey, insecure_decrypt_ignoring_signature,
};
use crate::cryptography::signing::identity::NodeSigningIdentity;
use crate::dummy_domain;
use crate::engine::base::{derive_request_id, sign_user_decryption_result};
use crate::engine::validation::DSEP_USER_DECRYPTION;
use crate::testing::prelude::{
    ServerHandle, TestMaterialGuard, TestMaterialSpec, ThresholdTestEnv,
};
use crate::util::key_setup::max_threshold;
use crate::util::key_setup::test_tools::{
    EncryptionConfig, TestingPlaintext, compute_cipher_from_stored_key,
};
use crate::vault::storage::crypto_material::get_core_signing_identity;
use crate::vault::storage::{StorageType, file::FileStorage};
use kms_grpc::RequestId;
use kms_grpc::kms::v1::{
    TypedCiphertext, TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse,
};
use kms_grpc::rpc_types::protobuf_to_alloy_domain;
use rand::SeedableRng;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::sync::Arc;
use threshold_execution::endpoints::decryption::DecryptionMode;
use threshold_execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "wasm_tests")]
use threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
use threshold_types::rng::AesRng;
use threshold_types::role::Role;
use tokio::task::JoinSet;

#[rstest::rstest]
#[case(true, TestingPlaintext::Bool(true), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U8(88), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(false, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U64(64), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(true, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
#[case(false, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
#[tokio::test(flavor = "multi_thread")]
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
        pt,
        EncryptionConfig {
            compression: true,
            // BitDecSmall explicitly exercises the small-ciphertext path.
            precompute_sns: !matches!(decryption_mode, DecryptionMode::BitDecSmall),
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
#[case(TestingPlaintext::U32(u32::MAX), &TEST_THRESHOLD_KEY_ID_4P, vec![Role::indexed_from_one(1)])]
#[case(TestingPlaintext::U32(u32::MAX), &TEST_THRESHOLD_KEY_ID_4P, vec![Role::indexed_from_one(4)])]
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_malicious(
    #[case] pt: TestingPlaintext,
    #[case] key_id: &RequestId,
    #[case] malicious_set: Vec<Role>,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        false,
        pt,
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        1,    // parallelism
        true, // secure
        4,    // no. of parties
        None,
        Some(HashSet::from_iter(malicious_set.into_iter())),
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic]
async fn test_user_decryption_threshold_malicious_failure() {
    // should panic because the malicious set is too big
    user_decryption_threshold(
        TEST_PARAM,
        &TEST_THRESHOLD_KEY_ID_4P,
        false,
        TestingPlaintext::U32(u32::MAX),
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        1,    // parallelism
        true, // secure
        4,    // no. of parties
        None,
        Some(
            [1, 4]
                .iter()
                .map(|id| Role::indexed_from_one(*id as usize))
                .collect(),
        ),
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic]
async fn test_user_decryption_threshold_all_malicious_failure() {
    // should panic because the malicious set is too big
    user_decryption_threshold(
        TEST_PARAM,
        &TEST_THRESHOLD_KEY_ID_4P,
        false,
        TestingPlaintext::U16(u16::MAX),
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        1,    // parallelism
        true, // secure
        4,    // no. of parties
        None,
        Some(
            [1, 2, 3, 4]
                .iter()
                .map(|id| Role::indexed_from_one(*id as usize))
                .collect(),
        ), // all parties are malicious
        None,
    )
    .await;
}

#[rstest::rstest]
#[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
#[tokio::test(flavor = "multi_thread")]
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
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_no_compression(#[values(true, false)] secure: bool) {
    user_decryption_threshold(
        TEST_PARAM,
        &TEST_THRESHOLD_KEY_ID_4P,
        false,
        TestingPlaintext::U8(u8::MAX),
        EncryptionConfig {
            compression: false,
            precompute_sns: false,
        },
        1,
        secure,
        4,
        None,
        None,
        None,
    )
    .await;
}

/// Checks that every party fails a user decryption of an oversized garbage ciphertext with an
/// error instead of a crash, and that the parties still serve user decryptions afterward.
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_largecipher() {
    let amount_parties = 4;
    let env = ThresholdTestEnv::builder()
        .with_test_name("user_decryption_threshold_largecipher")
        .with_party_count(amount_parties)
        .with_threshold(max_threshold(amount_parties) as u8)
        .with_material_spec(TestMaterialSpec::threshold_basic(amount_parties))
        .with_prss()
        .build()
        .await
        .unwrap();
    let mut internal_client = env.create_internal_client(&TEST_PARAM, None).await.unwrap();
    let (kms_clients, _kms_servers, material_path, _guards) = env.into_parts();

    let decrypt = async |req: &UserDecryptionRequest| {
        let mut out = Vec::new();
        for (party, client) in &kms_clients {
            let mut client = client.clone();
            let result = match client.user_decrypt(tonic::Request::new(req.clone())).await {
                Ok(_) => retrying_poll(
                    client,
                    req.request_id.clone().unwrap(),
                    "user decryption result",
                    PollConfig::long_poll_config(),
                    |c, r| Box::pin(async move { c.get_user_decryption_result(r).await }),
                )
                .await
                .map(|resp| resp.into_inner()),
                Err(status) => Err(status),
            };
            out.push((*party, result));
        }
        out
    };

    let garbage_ct = TypedCiphertext {
        ciphertext: vec![1_u8; 100000].into(),
        fhe_type: tfhe::FheTypes::Uint32 as i32,
        ciphertext_format: kms_grpc::kms::v1::CiphertextFormat::default().into(),
        external_handle: vec![123],
    };
    let (garbage_req, _, _) = internal_client
        .user_decryption_request(
            &dummy_domain(),
            vec![garbage_ct],
            &derive_request_id("TEST_USER_DECRYPT_LARGECIPHER").unwrap(),
            &TEST_THRESHOLD_KEY_ID_4P,
            None,
            None,
            &[],
        )
        .unwrap();
    for (party, result) in decrypt(&garbage_req).await {
        let status = result.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::Internal,
            "party {party}: unexpected status for an oversized ciphertext: {status:?}"
        );
    }

    let msg = TestingPlaintext::U8(42);
    let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
        Some(&material_path),
        msg,
        &TEST_THRESHOLD_KEY_ID_4P,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
    )
    .await;
    let valid_ct = TypedCiphertext {
        ciphertext: ct.into(),
        fhe_type: fhe_type as i32,
        ciphertext_format: ct_format.into(),
        external_handle: vec![124],
    };
    let valid_req_id = derive_request_id("TEST_USER_DECRYPT_AFTER_LARGECIPHER").unwrap();
    let valid_req = internal_client
        .user_decryption_request(
            &dummy_domain(),
            vec![valid_ct],
            &valid_req_id,
            &TEST_THRESHOLD_KEY_ID_4P,
            None,
            None,
            &[],
        )
        .unwrap();
    let responses = decrypt(&valid_req.0)
        .await
        .into_iter()
        .map(|(_, result)| result.unwrap())
        .collect();
    process_batch_threshold_user_decryption(
        &mut internal_client,
        msg,
        true,
        amount_parties,
        None,
        HashSet::new(),
        vec![valid_req],
        HashMap::from([(valid_req_id, responses)]),
        get_server_private_keys(amount_parties, &material_path).await,
    )
    .await;
}

/// Checks that a single valid response does not decrypt for a client that knows all four
/// parties, on both the secure and the insecure path.
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_single_response_fails() {
    let msg = TestingPlaintext::U8(42);
    let fx = UserDecryptionResponses::collect("user_decryption_single_response", msg).await;
    assert_eq!(fx.client.server_identities.len(), 4);
    for plaintext in fx.process(None, &fx.responses).unwrap() {
        crate::client::tests::common::assert_plaintext(&msg, &plaintext);
    }

    for resp in &fx.responses {
        let party_id = resp.payload.as_ref().unwrap().party_id;
        let single = std::slice::from_ref(resp);
        assert!(
            fx.process(None, single).is_err(),
            "a single response from party {party_id} must not decrypt"
        );
        assert!(
            fx.client
                .insecure_process_user_decryption_resp(&fx.enc_sk, single)
                .is_err(),
            "a single response from party {party_id} must not decrypt on the insecure path"
        );
    }
}

/// Checks that a client with one server identity and one response uses threshold decoding.
///
/// The response comes from party 1 of a 4-party cluster, so it carries a degree-1 share. The
/// secure path expects degree 0 from one server identity and rejects the response. The
/// insecure path cannot reconstruct a degree-1 sharing from one share.
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_one_identity_one_response_fails() {
    let msg = TestingPlaintext::U8(42);
    let mut fx =
        UserDecryptionResponses::collect("user_decryption_one_identity_one_response", msg).await;
    match &mut fx.client.server_identities {
        ServerIdentities::Pks(pks) => pks.retain(|id, _| *id == 1),
        ServerIdentities::Addrs(addrs) => addrs.retain(|id, _| *id == 1),
    }
    assert_eq!(fx.client.server_identities.len(), 1);
    let party_1 = std::slice::from_ref(&fx.responses[0]);
    assert_eq!(party_1[0].payload.as_ref().unwrap().party_id, 1);

    for threshold in [None, Some(0)] {
        assert!(
            fx.process(threshold, party_1).is_err(),
            "one response must not decrypt for a one-identity client (threshold {threshold:?})"
        );
    }
    assert!(
        fx.client
            .insecure_process_user_decryption_resp(&fx.enc_sk, party_1)
            .is_err(),
        "one response must not decrypt on the insecure path for a one-identity client"
    );
}

/// Checks that a response which signcrypts the plaintext itself is not a valid threshold share.
///
/// Party 3's response is sealed and signed again with party 3's own signing identity, so only
/// the encoding inside the signcryption differs from an honest response. Three accepted
/// responses out of four are the minimum for reconstruction with `t = 1`. Responses from
/// parties 1 and 2 plus the forged response from party 3 therefore decrypt only if the
/// client accepts the forged response.
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_rejects_plaintext_encoding() {
    let msg = TestingPlaintext::U8(42);
    let fx = UserDecryptionResponses::collect("user_decryption_plaintext_encoding", msg).await;
    let identities = get_server_signing_identities(4, &fx.material_path).await;
    let party_3 = &fx.responses[2];
    assert_eq!(party_3.payload.as_ref().unwrap().party_id, 3);

    // Control: sealing the original share again gives a response that the client accepts.
    let resealed_share = fx.reseal(party_3, &identities[&3], |share| share.bytes.clone());
    let control = [
        fx.responses[0].clone(),
        fx.responses[1].clone(),
        resealed_share,
    ];
    for plaintext in fx.process(None, &control).unwrap() {
        crate::client::tests::common::assert_plaintext(&msg, &plaintext);
    }

    // The plaintext encoding: the signcryption carries the plaintext bytes instead of a
    // serialized share vector.
    let plaintext_bytes = TypedPlaintext::from(msg).bytes.clone();
    let resealed_plaintext = fx.reseal(party_3, &identities[&3], |_| plaintext_bytes.clone());
    let forged = [
        fx.responses[0].clone(),
        fx.responses[1].clone(),
        resealed_plaintext,
    ];
    // Two accepted responses leave two faulty ones, which is more than `t = 1`.
    let err = fx.process(None, &forged).unwrap_err();
    assert!(
        err.to_string()
            .contains("Too many faulty user decryption responses: 2 > t=1"),
        "a response that encodes the plaintext directly must not count as a threshold share: {err}"
    );
}

#[cfg(feature = "wasm_tests")]
#[rstest::rstest]
#[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P)]
#[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
async fn test_user_decryption_threshold_and_write_transcript(
    #[case] secure: bool,
    #[case] amount_parties: usize,
    #[case] key_id: &RequestId,
) {
    user_decryption_threshold(
        TEST_PARAM,
        key_id,
        true,
        TestingPlaintext::U8(42),
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
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
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
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

#[rstest::rstest]
#[case(TestingPlaintext::Bool(true), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
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
        msg,
        EncryptionConfig {
            compression: true,
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

#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread")]
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

#[rstest::rstest]
#[case(TestingPlaintext::U8(u8::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
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
        msg,
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        parallelism,
        secure,
        amount_parties,
        party_ids_to_crash.map(|party_ids| {
            party_ids
                .iter()
                .map(|id| Role::indexed_from_zero(*id))
                .collect()
        }),
        None,
        None,
    )
    .await;
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn user_decryption_threshold(
    dkg_params: DKGParams,
    key_id: &RequestId,
    _write_transcript: bool,
    msg: TestingPlaintext,
    enc_config: EncryptionConfig,
    parallelism: usize,
    secure: bool,
    amount_parties: usize,
    party_ids_to_crash: Option<HashSet<Role>>,
    malicious_parties: Option<HashSet<Role>>,
    decryption_mode: Option<DecryptionMode>,
) {
    assert!(parallelism > 0);

    // Spec: pre-gen FHE keys for `key_id` plus signing. The default epoch (PRSS) comes from
    // the fixture with the key shares. Material type follows the DKG params.
    let spec = if dkg_params == TEST_PARAM {
        TestMaterialSpec::threshold_basic(amount_parties)
    } else {
        TestMaterialSpec::threshold_default(amount_parties)
    };

    let mut builder = ThresholdTestEnv::builder()
        .with_test_name(format!("user_decryption_threshold_{amount_parties}p"))
        .with_party_count(amount_parties)
        .with_threshold(max_threshold(amount_parties) as u8)
        .with_material_spec(spec)
        .with_prss();
    if let Some(mode) = decryption_mode {
        builder = builder.with_decryption_mode(mode);
    }
    let env = builder
        .build()
        .await
        .expect("ThresholdTestEnv setup failed");

    let mut internal_client = env
        .create_internal_client(&dkg_params, decryption_mode)
        .await
        .expect("create_internal_client failed");
    let (mut kms_clients, mut kms_servers, material_path, _guards) = env.into_parts();

    let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
        Some(&material_path),
        msg,
        key_id,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
        enc_config,
    )
    .await;

    // make requests
    let reqs: Vec<_> = (0..parallelism)
        .map(|j| {
            let request_id = derive_request_id(&format!("TEST_USER_DECRYPT_ID_{j}")).unwrap();
            let typed_ciphertexts = vec![TypedCiphertext {
                ciphertext: ct.clone().into(),
                fhe_type: fhe_type as i32,
                ciphertext_format: ct_format.into(),
                external_handle: j.to_be_bytes().to_vec(),
            }];
            let (req, enc_pk, enc_sk) = internal_client
                .user_decryption_request(
                    &dummy_domain(),
                    typed_ciphertexts,
                    &request_id,
                    &key_id.to_string().try_into().unwrap(),
                    None,
                    None,
                    &[],
                )
                .unwrap();

            (req, enc_pk, enc_sk)
        })
        .collect();
    // Either send the request, or crash the party if it's in
    // party_ids_to_crash
    let mut req_tasks = JoinSet::new();
    let party_ids_to_crash = party_ids_to_crash.unwrap_or_default();
    for j in 0..parallelism {
        for i in 1..=amount_parties as u32 {
            if party_ids_to_crash.contains(&Role::indexed_from_one(i as usize)) {
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
            if party_ids_to_crash.contains(&Role::indexed_from_one(i as usize)) {
                continue;
            }
            let cur_client = kms_clients.get(&i).unwrap().clone();
            let req_id_clone = reqs.get(j).as_ref().unwrap().0.clone().request_id.unwrap();
            resp_tasks.spawn(async move {
                let response = retrying_poll(
                    cur_client,
                    req_id_clone.clone(),
                    "user decryption result",
                    PollConfig::default(),
                    |client, request| {
                        Box::pin(async move { client.get_user_decryption_result(request).await })
                    },
                )
                .await;

                (req_id_clone, response)
            });
        }
    }
    let mut response_map: HashMap<RequestId, Vec<UserDecryptionResponse>> = HashMap::new();
    while let Some(res) = resp_tasks.join_next().await {
        let res = res.unwrap();
        tracing::info!("Client got a response from {}", res.0.request_id);
        let (req_id, resp) = res;
        if let Entry::Vacant(e) = response_map.entry(req_id.clone().try_into().unwrap()) {
            e.insert(vec![resp.unwrap().into_inner()]);
        } else {
            response_map
                .get_mut(&req_id.try_into().unwrap())
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
                    .map(|typed_ct| typed_ct.ciphertext.to_vec())
                    .collect::<Vec<_>>(),
                request: Some(reqs[0].clone().0),
                eph_sk: reqs[0].clone().2,
                eph_pk: reqs[0].clone().1,
                agg_resp,
            };
            let path_prefix = if dkg_params != PARAMS_TEST_BK_SNS {
                crate::consts::DEFAULT_THRESHOLD_WASM_TRANSCRIPT_PATH
            } else {
                crate::consts::TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
            };
            let path = format!("{}.{}.json", path_prefix, msg.bits());
            transcript.write_stable_test_vector_json(&path).unwrap();
        }
    }

    let server_private_keys = get_server_private_keys(amount_parties, &material_path).await;

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

#[expect(clippy::too_many_arguments)]
async fn process_batch_threshold_user_decryption(
    internal_client: &mut Client,
    msg: TestingPlaintext,
    secure: bool,
    amount_parties: usize,
    malicious_parties: Option<HashSet<Role>>,
    party_ids_to_crash: HashSet<Role>,
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
            .get(&request_id.try_into().unwrap())
            .expect("Retrieving responses failed")
            .clone();
        let domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap())
            .expect("Retrieving domain failed");
        let client_req = ParsedUserDecryptionRequest::try_from(req)
            .expect("Parsing UserDecryptionRequest failed");
        let threshold = responses.first().unwrap().payload.as_ref().unwrap().degree as usize;
        // NOTE: throw away one response and it should still work.
        let plaintexts = if secure {
            // Every response must echo the request's extra data. Validation rejects each
            // tampered response on its own and reports only that too few responses remain, so
            // the batch error does not name the extra-data mismatch.
            let bad_extra_data_resps: Vec<_> = responses
                .iter()
                .cloned()
                .map(|mut resp| {
                    resp.extra_data = vec![42];
                    resp
                })
                .collect();
            assert!(
                internal_client
                    .process_user_decryption_resp(
                        &client_req,
                        &domain,
                        enc_pk,
                        enc_sk,
                        None,
                        &bad_extra_data_resps,
                    )
                    .is_err(),
                "responses with tampered extra data must be rejected"
            );

            // test with one fewer response if we haven't crashed too many parties already
            let result_from_dropped_response = if threshold > party_ids_to_crash.len() {
                Some(
                    internal_client
                        .process_user_decryption_resp(
                            &client_req,
                            &domain,
                            enc_pk,
                            enc_sk,
                            None,
                            &responses[1..],
                        )
                        .unwrap(),
                )
            } else {
                None
            };

            // modify the responses if there are malicious parties
            // note that we also need to sign the modified payload
            responses.iter_mut().for_each(|resp| {
                if let Some(payload) = &mut resp.payload
                    && let Some(mal_parties) = &malicious_parties
                    && mal_parties.contains(&Role::indexed_from_one(payload.party_id as usize))
                {
                    let orig_party_id = payload.party_id;
                    // Modify the party ID maliciously
                    if payload.party_id == 1 {
                        payload.party_id = amount_parties as u32;
                    } else {
                        payload.party_id -= 1;
                    }
                    let sig_payload_vec = bc2wrap::serialize(&payload).unwrap();
                    let sig = internal_sign(
                        &DSEP_USER_DECRYPTION,
                        &sig_payload_vec,
                        &server_private_keys[&orig_party_id],
                    )
                    .unwrap();
                    // Remove in 0.16 TODO(0.16)
                    resp.signature = sig.to_bytes();
                    resp.signatures = kms_grpc::rpc_types::ecdsa_signatures(sig.to_bytes());
                }
            });

            // test with all responses, some may be malicious
            let final_result = internal_client
                .process_user_decryption_resp(
                    &client_req,
                    &domain,
                    enc_pk,
                    enc_sk,
                    None,
                    &responses,
                )
                .unwrap();

            if let Some(res) = result_from_dropped_response {
                assert_eq!(res, final_result)
            }
            final_result
        } else {
            // insecure processing
            // test with one fewer response if we haven't crashed too many parties already
            let result_from_dropped_response = if threshold > party_ids_to_crash.len() {
                Some(
                    internal_client
                        .insecure_process_user_decryption_resp(enc_sk, &responses[1..])
                        .unwrap(),
                )
            } else {
                None
            };

            // test with all responses
            let final_result = internal_client
                .insecure_process_user_decryption_resp(enc_sk, &responses)
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

async fn get_server_private_keys(
    amount_parties: usize,
    material_path: &std::path::Path,
) -> HashMap<u32, PrivateSigKey> {
    get_server_signing_identities(amount_parties, material_path)
        .await
        .into_iter()
        .map(|(party_id, identity)| (party_id, identity.ecdsa().clone()))
        .collect()
}

/// Returns the signing identity of each party, keyed by the one-based party ID.
async fn get_server_signing_identities(
    amount_parties: usize,
    material_path: &std::path::Path,
) -> HashMap<u32, NodeSigningIdentity> {
    let storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let mut identities = HashMap::new();
    for (i, prefix) in storage_prefixes.iter().enumerate() {
        // Read from the per-test isolated material path populated by the builder.
        let priv_storage =
            FileStorage::new(Some(material_path), StorageType::PRIV, prefix.as_deref()).unwrap();
        let identity = get_core_signing_identity(&priv_storage)
            .await
            .inspect_err(|e| {
                tracing::error!("signing key hashmap is not exactly 1, {}", e);
            })
            .unwrap();
        identities.insert(i as u32 + 1, identity);
    }
    identities
}

/// One user decryption request of a `u8` ciphertext, answered by every party of the default
/// 4-party cluster.
struct UserDecryptionResponses {
    client: Client,
    request: UserDecryptionRequest,
    enc_pk: UnifiedPublicEncKey,
    enc_sk: UnifiedPrivateEncKey,
    /// One response per party, sorted by party ID.
    responses: Vec<UserDecryptionResponse>,
    material_path: std::path::PathBuf,
    // The servers and the material directory must outlive the test body.
    _servers: HashMap<u32, ServerHandle>,
    _guards: TestMaterialGuard,
}

impl UserDecryptionResponses {
    /// Starts the cluster, encrypts `msg` and collects the user decryption response of every party.
    async fn collect(test_name: &str, msg: TestingPlaintext) -> Self {
        let amount_parties = 4;
        let env = ThresholdTestEnv::builder()
            .with_test_name(test_name)
            .with_party_count(amount_parties)
            .with_threshold(max_threshold(amount_parties) as u8)
            .with_material_spec(TestMaterialSpec::threshold_basic(amount_parties))
            .with_prss()
            .build()
            .await
            .unwrap();
        let mut client = env.create_internal_client(&TEST_PARAM, None).await.unwrap();
        let (kms_clients, servers, material_path, guards) = env.into_parts();

        let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
            Some(&material_path),
            msg,
            &TEST_THRESHOLD_KEY_ID_4P,
            PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
            EncryptionConfig {
                compression: true,
                precompute_sns: true,
            },
        )
        .await;
        let typed_ct = TypedCiphertext {
            ciphertext: ct.into(),
            fhe_type: fhe_type as i32,
            ciphertext_format: ct_format.into(),
            external_handle: vec![42],
        };
        let request_id = derive_request_id(&format!("TEST_USER_DECRYPT_{test_name}")).unwrap();
        let (request, enc_pk, enc_sk) = client
            .user_decryption_request(
                &dummy_domain(),
                vec![typed_ct],
                &request_id,
                &TEST_THRESHOLD_KEY_ID_4P,
                None,
                None,
                &[],
            )
            .unwrap();

        let mut responses = Vec::with_capacity(amount_parties);
        for kms_client in kms_clients.values() {
            let mut kms_client = kms_client.clone();
            kms_client
                .user_decrypt(tonic::Request::new(request.clone()))
                .await
                .unwrap();
            let resp = retrying_poll(
                kms_client,
                request.request_id.clone().unwrap(),
                "user decryption result",
                PollConfig::default(),
                |c, r| Box::pin(async move { c.get_user_decryption_result(r).await }),
            )
            .await
            .unwrap()
            .into_inner();
            responses.push(resp);
        }
        responses.sort_by_key(|resp| resp.payload.as_ref().unwrap().party_id);

        Self {
            client,
            request,
            enc_pk,
            enc_sk,
            responses,
            material_path,
            _servers: servers,
            _guards: guards,
        }
    }

    /// Runs the secure response processing of the client on `responses`.
    fn process(
        &self,
        threshold: Option<usize>,
        responses: &[UserDecryptionResponse],
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let domain = protobuf_to_alloy_domain(self.request.domain.as_ref().unwrap()).unwrap();
        let client_req = ParsedUserDecryptionRequest::try_from(&self.request).unwrap();
        self.client.process_user_decryption_resp(
            &client_req,
            &domain,
            &self.enc_pk,
            &self.enc_sk,
            threshold,
            responses,
        )
    }

    /// Returns `resp` with each signcryption replaced by a signcryption of `encode(share)`, where
    /// `share` is the original inner plaintext of that signcryption.
    ///
    /// `identity` seals and signs the result the same way a party seals and signs its own
    /// response, so the result is authentic for the party that owns `identity`.
    fn reseal(
        &self,
        resp: &UserDecryptionResponse,
        identity: &NodeSigningIdentity,
        encode: impl Fn(&TypedPlaintext) -> Vec<u8>,
    ) -> UserDecryptionResponse {
        let mut rng = AesRng::seed_from_u64(42);
        let sealer = UnifiedSigncryptionKey::new(
            Arc::new(identity.clone()),
            self.enc_pk.clone(),
            self.client.client_address.to_vec(),
        );
        let mut payload = resp.payload.clone().unwrap();
        for ct in payload.signcrypted_ciphertexts.iter_mut() {
            let share =
                insecure_decrypt_ignoring_signature(&ct.signcrypted_ciphertext, &self.enc_sk)
                    .unwrap();
            ct.signcrypted_ciphertext = sealer
                .signcrypt_plaintext(
                    &mut rng,
                    &DSEP_USER_DECRYPTION,
                    &encode(&share),
                    ct.fhe_type().unwrap(),
                    &payload.digest,
                )
                .unwrap()
                .payload;
        }

        let domain = protobuf_to_alloy_domain(self.request.domain.as_ref().unwrap()).unwrap();
        let client_req = ParsedUserDecryptionRequest::try_from(&self.request).unwrap();
        let signed = sign_user_decryption_result(
            identity,
            client_req.signing_schemes(),
            payload,
            &self.request.enc_key,
            resp.extra_data.clone(),
            &domain,
        )
        .unwrap();
        UserDecryptionResponse {
            signature: signed.signature,
            signatures: signed.signatures,
            external_signature: signed.external_signature,
            payload: Some(signed.payload),
            extra_data: signed.extra_data,
        }
    }
}
