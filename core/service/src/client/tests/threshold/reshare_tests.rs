use std::collections::HashMap;

use kms_grpc::{
    kms::v1::{FheParameter, KeyGenResult, ResharingResultResponse},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    RequestId,
};
use serial_test::serial;
use threshold_fhe::execution::{
    runtime::party::Role, tfhe_internals::private_keysets::PrivateKeySet,
};
use tokio::task::JoinSet;
use tonic::{transport::Channel, Response, Status};
use tracing_test::traced_test;

use crate::{
    client::{
        client_wasm::Client,
        tests::{
            common::TIME_TO_SLEEP_MS,
            threshold::{
                common::threshold_handles,
                key_gen_tests::{
                    run_preproc, run_threshold_keygen, verify_keygen_responses, TestKeyGenResult,
                },
                public_decryption_tests::run_decryption_threshold,
            },
        },
    },
    consts::{PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL},
    cryptography::internal_crypto_types::WrappedDKGParams,
    dummy_domain,
    engine::{base::derive_request_id, threshold::service::ThresholdFheKeys},
    util::{
        key_setup::test_tools::{purge, EncryptionConfig, TestingPlaintext},
        rate_limiter::RateLimiterConfig,
    },
};

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[traced_test]
async fn test_reshare() {
    reshare(4, FheParameter::Test, None).await;
}

pub(crate) async fn reshare(
    amount_parties: usize,
    parameters: FheParameter,
    party_ids_to_crash: Option<Vec<usize>>,
) {
    let req_preproc: RequestId =
        derive_request_id(&format!("full_dkg_preproc_{amount_parties}_{parameters:?}")).unwrap();
    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    purge(
        None,
        None,
        &req_preproc,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;

    let req_key: RequestId =
        derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameters:?}")).unwrap();
    purge(
        None,
        None,
        &req_key,
        pub_storage_prefixes,
        priv_storage_prefixes,
    )
    .await;

    let dkg_param: WrappedDKGParams = parameters.into();
    // Preproc should use all the tokens in the bucket,
    // then they're returned to the bucket before keygen starts.
    // If something is wrong with the rate limiter logic
    // then the keygen step should fail since there are not enough tokens.
    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100 * 2,
        pub_decrypt: 1,
        user_decrypt: 1,
        crsgen: 1,
        preproc: 100,
        keygen: 100,
        reshare: 1,
    };

    tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
    let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
        *dkg_param,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        None,
    )
    .await;

    let expected_num_parties_crashed = party_ids_to_crash.as_ref().map_or(0, |v| v.len());

    // Run a regular DKG to have something to reshare
    run_preproc(
        amount_parties,
        parameters,
        &kms_clients,
        &internal_client,
        &req_preproc,
        None,
        expected_num_parties_crashed,
        None,
    )
    .await;

    let (keyset, all_private_keys) = run_threshold_keygen(
        parameters,
        &kms_clients,
        &internal_client,
        &req_preproc,
        &req_key,
        None,
        false,
        None,
        expected_num_parties_crashed,
    )
    .await;

    let (client_key, public_key, server_key) = keyset.get_standard();

    // Run the reshare

    let (reshared_keyset, reshared_all_private_keys) = run_reshare(
        amount_parties,
        parameters,
        &kms_clients,
        &internal_client,
        &derive_request_id(&format!("reshare_{amount_parties}_{parameters:?}")).unwrap(),
        &req_preproc,
        &req_key,
    )
    .await;

    // Assert that the two keysets are identical (since this is only the public material here)
    let (reshared_client_key, reshared_public_key, reshared_server_key) =
        reshared_keyset.get_standard();

    // Check equality via serialization
    assert_eq!(
        bc2wrap::serialize(&reshared_client_key).unwrap(),
        bc2wrap::serialize(&client_key).unwrap()
    );
    assert_eq!(
        bc2wrap::serialize(&reshared_public_key).unwrap(),
        bc2wrap::serialize(&public_key).unwrap()
    );
    assert_eq!(
        bc2wrap::serialize(&reshared_server_key).unwrap(),
        bc2wrap::serialize(&server_key).unwrap()
    );

    // Make sure the private keys ARE NOT the same
    let all_private_keys = all_private_keys.unwrap();

    assert_eq!(all_private_keys.len(), amount_parties);
    assert_eq!(reshared_all_private_keys.len(), amount_parties);

    for (party, keys) in all_private_keys.into_iter() {
        let reshared_keys = reshared_all_private_keys.get(&party).unwrap();
        let private_keys = keys.private_keys;
        let reshared_private_keys = &reshared_keys.private_keys;

        let PrivateKeySet {
            lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share,
            glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe,
            parameters,
        } = private_keys.as_ref().clone();

        let PrivateKeySet {
            lwe_encryption_secret_key_share: reshared_lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share: reshared_lwe_compute_secret_key_share,
            glwe_secret_key_share: reshared_glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe: reshared_glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression: reshared_glwe_secret_key_share_compression,
            glwe_sns_compression_key_as_lwe: reshared_glwe_sns_compression_key_as_lwe,
            parameters: reshared_parameters,
        } = reshared_private_keys.as_ref().clone();

        // Assert parameters are the same
        assert_eq!(parameters, reshared_parameters);
        // Assert none of the keys is similar
        assert_ne!(
            lwe_encryption_secret_key_share,
            reshared_lwe_encryption_secret_key_share
        );
        assert_ne!(
            lwe_compute_secret_key_share,
            reshared_lwe_compute_secret_key_share
        );
        assert_ne!(glwe_secret_key_share, reshared_glwe_secret_key_share);
        if glwe_secret_key_share_sns_as_lwe.is_some() {
            assert_ne!(
                glwe_secret_key_share_sns_as_lwe,
                reshared_glwe_secret_key_share_sns_as_lwe
            );
        }
        if glwe_secret_key_share_compression.is_some() {
            assert_ne!(
                glwe_secret_key_share_compression,
                reshared_glwe_secret_key_share_compression
            );
        }
        if glwe_sns_compression_key_as_lwe.is_some() {
            assert_ne!(
                glwe_sns_compression_key_as_lwe,
                reshared_glwe_sns_compression_key_as_lwe
            );
        }
    }

    // Run a DDec
    run_decryption_threshold(
        amount_parties,
        &mut kms_servers,
        &mut kms_clients,
        &mut internal_client,
        &req_key,
        None,
        vec![TestingPlaintext::U8(u8::MAX)],
        EncryptionConfig {
            compression: true,
            precompute_sns: true,
        },
        None,
        1,
        None,
    )
    .await;
}

async fn run_reshare(
    amount_parties: usize,
    parameters: FheParameter,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    reshare_request_id: &RequestId,
    preproc_req_id: &RequestId,
    keygen_req_id: &RequestId,
) -> (TestKeyGenResult, HashMap<Role, ThresholdFheKeys>) {
    let domain = dummy_domain();

    let reshare_request = internal_client
        .reshare_request(
            reshare_request_id,
            keygen_req_id,
            preproc_req_id,
            Some(parameters),
            &domain,
        )
        .unwrap();

    // Execute reshare
    let mut tasks_reshare = JoinSet::new();
    for (_, cur_client) in kms_clients.iter() {
        let req = reshare_request.clone();
        let mut client = cur_client.clone();
        tasks_reshare.spawn(async move { client.initiate_resharing(req).await });
    }

    tasks_reshare.join_all().await.into_iter().for_each(|res| {
        assert!(res.is_ok());
    });

    let responses = poll_reshare_result(reshare_request_id, kms_clients, 50).await;

    assert_eq!(responses.len(), amount_parties);

    // Transform the reshare response to its equivalent keygen response
    let responses_as_dkg = responses
        .into_iter()
        .map(|(idx, _, response)| {
            (
                idx,
                response.map(|response| {
                    let response = response.into_inner();
                    Response::new(KeyGenResult {
                        request_id: response.key_id.clone(),
                        preprocessing_id: response.preprocessing_id.clone(),
                        key_digests: response.key_digests.clone(),
                        external_signature: response.external_signature.clone(),
                    })
                }),
            )
        })
        .collect::<Vec<_>>();

    let out = verify_keygen_responses(
        responses_as_dkg,
        None,
        internal_client,
        preproc_req_id,
        keygen_req_id,
        &domain,
        amount_parties,
    )
    .await
    .expect("Failed to verify reshare responses");

    let (client_key, _, server_key) = out.0.clone().get_standard();
    crate::client::key_gen::tests::check_conformance(server_key, client_key);
    out
}

async fn poll_reshare_result(
    reshare_request_id: &RequestId,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    max_iter: usize,
) -> Vec<(
    u32,
    RequestId,
    Result<Response<ResharingResultResponse>, Status>,
)> {
    let mut resp_tasks = JoinSet::new();

    for (idx, client) in kms_clients.iter() {
        let mut client = client.clone();

        let reshare_request_id = *reshare_request_id;
        let idx = *idx;
        resp_tasks.spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut response = client
                .get_resharing_result(tonic::Request::new(reshare_request_id.into()))
                .await;

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if ctr >= max_iter {
                    panic!("timeout while waiting for resharing after {max_iter} retries");
                }
                ctr += 1;
                response = client
                    .get_resharing_result(tonic::Request::new(reshare_request_id.into()))
                    .await;
            }
            (idx, reshare_request_id, response)
        });
    }

    resp_tasks.join_all().await
}
