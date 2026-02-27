use std::collections::HashMap;

use itertools::Itertools;
use kms_grpc::{
    identifiers::EpochId,
    kms::v1::{EpochResultResponse, FheParameter, KeyGenResult, KeyInfo, PreviousEpochInfo},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::{alloy_to_protobuf_domain, PubDataType},
    ContextId, RequestId,
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
            common::standard_keygen_config,
            threshold::{
                common::threshold_handles,
                key_gen_tests::{
                    run_preproc, run_threshold_keygen, verify_keygen_responses, TestKeyGenResult,
                },
                public_decryption_tests::run_decryption_threshold,
            },
        },
    },
    consts::{
        DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
    },
    cryptography::internal_crypto_types::WrappedDKGParams,
    dummy_domain,
    engine::{
        base::{derive_request_id, safe_serialize_hash_element_versioned, DSEP_PUBDATA_KEY},
        threshold::service::ThresholdFheKeys,
    },
    util::{
        key_setup::test_tools::{purge, EncryptionConfig, TestingPlaintext},
        rate_limiter::RateLimiterConfig,
    },
};

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[traced_test]
async fn test_new_epoch_with_reshare() {
    new_epoch_with_reshare(4, 3, FheParameter::Test, None).await;
}

pub(crate) async fn new_epoch_with_reshare(
    amount_parties: usize,
    num_keys: usize,
    parameters: FheParameter,
    party_ids_to_crash: Option<Vec<usize>>,
) {
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
        new_epoch: 1,
    };
    // Need to purge before creating the clients
    let mut preproc_ids = Vec::new();
    let mut key_ids = Vec::new();
    for key_id in 0..num_keys {
        let preproc_req_id: RequestId = derive_request_id(&format!(
            "full_dkg_preproc_{amount_parties}_{key_id}_{parameters:?}"
        ))
        .unwrap();
        let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
        let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
        purge(
            None,
            None,
            &preproc_req_id,
            pub_storage_prefixes,
            priv_storage_prefixes,
        )
        .await;

        preproc_ids.push(preproc_req_id);

        let key_req_id: RequestId = derive_request_id(&format!(
            "full_dkg_key_{amount_parties}_{key_id}_{parameters:?}"
        ))
        .unwrap();
        purge(
            None,
            None,
            &key_req_id,
            pub_storage_prefixes,
            priv_storage_prefixes,
        )
        .await;
        key_ids.push(key_req_id);
    }

    let new_epoch_id: EpochId =
        derive_request_id(&format!("new_epoch_id__{amount_parties}_{parameters:?}"))
            .unwrap()
            .into();
    purge(
        None,
        None,
        &new_epoch_id.into(),
        &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties],
        &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties],
    )
    .await;
    // Setting run_prss to true to
    // to create the default context and epoch with its PRSS init
    let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
        *dkg_param,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        None,
    )
    .await;

    let mut keys_info = Vec::new();
    let mut keysets = Vec::new();
    for (preproc_req_id, key_req_id) in preproc_ids.iter().zip(key_ids.iter()) {
        let expected_num_parties_crashed = party_ids_to_crash.as_ref().map_or(0, |v| v.len());

        // Run a regular DKG to have something to reshare
        run_preproc(
            amount_parties,
            parameters,
            &kms_clients,
            &internal_client,
            preproc_req_id,
            None,
            expected_num_parties_crashed,
            None,
        )
        .await;

        let (keyset_config, keyset_added_info) = standard_keygen_config();
        let (keyset, all_private_keys) = run_threshold_keygen(
            parameters,
            &kms_clients,
            &internal_client,
            preproc_req_id,
            key_req_id,
            keyset_config,
            keyset_added_info,
            false,
            None,
            expected_num_parties_crashed,
        )
        .await;

        let (client_key, public_key, server_key) = keyset.get_standard();

        // compute the key digests
        let server_key_digest =
            safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &server_key).unwrap();
        let public_key_digest =
            safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &public_key).unwrap();
        keys_info.push(KeyInfo {
            key_id: Some((*key_req_id).into()),
            preproc_id: Some((*preproc_req_id).into()),
            key_parameters: parameters.into(),
            key_digests: vec![
                kms_grpc::kms::v1::KeyDigest {
                    key_type: PubDataType::ServerKey.to_string(),
                    digest: server_key_digest,
                },
                kms_grpc::kms::v1::KeyDigest {
                    key_type: PubDataType::PublicKey.to_string(),
                    digest: public_key_digest,
                },
            ],
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
        });
        keysets.push((
            key_req_id,
            client_key,
            public_key,
            server_key,
            all_private_keys,
        ));
    }

    assert_eq!(keys_info.len(), num_keys);
    let previous_epoch = Some(PreviousEpochInfo {
        context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
        epoch_id: Some((*DEFAULT_EPOCH_ID).into()),
        keys_info,
    });

    // Create the new epoch and reshare from previous one
    // Note: Context hasn't changed, still using default
    // (effectively doing same set resharing, except we don't use the specialized impl anymore)
    let new_context_id = *DEFAULT_MPC_CONTEXT;

    //let (reshared_keyset, reshared_all_private_keys) =

    let new_epoch_outputs = run_new_epoch(
        amount_parties,
        &kms_clients,
        &internal_client,
        new_context_id,
        new_epoch_id,
        previous_epoch,
    )
    .await
    .unwrap();

    for (
        (reshared_keyset, reshared_all_private_keys),
        (key_req_id, client_key, public_key, server_key, all_private_keys),
    ) in new_epoch_outputs.into_iter().zip_eq(keysets.into_iter())
    {
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

        // Run a DDec with the new context id
        run_decryption_threshold(
            amount_parties,
            &mut kms_servers,
            &mut kms_clients,
            &mut internal_client,
            None,
            key_req_id,
            Some(&new_context_id),
            vec![TestingPlaintext::U8(u8::MAX)],
            EncryptionConfig {
                compression: true,
                precompute_sns: true,
            },
            None,
            1,
            None,
            false, // compressed_keys
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_new_epoch(
    amount_parties: usize,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    internal_client: &Client,
    new_context_id: ContextId,
    new_epoch_id: EpochId,
    previous_epoch: Option<PreviousEpochInfo>,
) -> Option<Vec<(TestKeyGenResult, HashMap<Role, ThresholdFheKeys>)>> {
    let num_keys = previous_epoch
        .as_ref()
        .map_or(0, |epoch| epoch.keys_info.len());
    let reshare_request = internal_client
        .new_epoch_request(&new_context_id, &new_epoch_id, previous_epoch.clone())
        .unwrap();

    // Execute reshare
    let mut tasks_reshare = JoinSet::new();
    for (_, cur_client) in kms_clients.iter() {
        let req = reshare_request.clone();
        let mut client = cur_client.clone();
        tasks_reshare.spawn(async move { client.new_mpc_epoch(req).await });
    }

    if let Some(previous_epoch) = previous_epoch {
        tasks_reshare.join_all().await.into_iter().for_each(|res| {
            assert!(res.is_ok(), "Reshare party failed: {:?}", res.err());
        });

        let new_epoch_id: RequestId = new_epoch_id.into();
        let responses = poll_new_epoch_result(&new_epoch_id, kms_clients, 50).await;

        assert_eq!(responses.len(), amount_parties);

        // Transform the reshare response to its equivalent keygen response
        let responses_as_dkg = responses
            .into_iter()
            .map(|(party_idx, _, response)| {
                (
                    party_idx,
                    response.map(|response| {
                        response
                            .into_inner()
                            .reshare_responses
                            .into_iter()
                            .map(|response| KeyGenResult {
                                request_id: response.key_id.clone(),
                                preprocessing_id: response.preprocessing_id.clone(),
                                key_digests: response.key_digests.clone(),
                                external_signature: response.external_signature.clone(),
                            })
                            .collect::<Vec<_>>()
                    }),
                )
            })
            .collect::<Vec<_>>();

        // Transform from Vec(party_idx, Vec<KGResult>) to Vec<Vec<(party_idx, KGResult)>>
        // to verify keys one by one
        let responses_as_dkg = (0..num_keys)
            .map(|key_idx| {
                responses_as_dkg
                    .iter()
                    .map(|(party_idx, kg_results)| {
                        (
                            *party_idx,
                            kg_results
                                .as_ref()
                                .map(|kg_results| {
                                    Response::new(
                                        kg_results
                                            .iter()
                                            .find(|kg_result| {
                                                kg_result.request_id
                                                    == previous_epoch.keys_info[key_idx].key_id
                                            })
                                            .unwrap_or_else(|| panic!("Each party should have a response for the key {}",
                                                key_idx))
                                            .clone(),
                                    )
                                })
                                .map_err(|e| e.clone()),
                        )
                    })
                    .collect_vec()
            })
            .collect_vec();

        assert_eq!(responses_as_dkg.len(), num_keys);

        let mut outs = Vec::new();
        for (key_info, responses) in previous_epoch
            .keys_info
            .into_iter()
            .zip_eq(responses_as_dkg.into_iter())
        {
            let KeyInfo {
                key_id,
                preproc_id,
                key_parameters: _,
                key_digests: _,
                domain: _,
            } = key_info;

            let preproc_id = preproc_id.as_ref().unwrap().try_into().unwrap();
            let key_id = key_id.as_ref().unwrap().try_into().unwrap();
            let out = verify_keygen_responses(
                responses,
                None,
                internal_client,
                &preproc_id,
                &key_id,
                &dummy_domain(),
                amount_parties,
                Some(new_epoch_id.into()),
                false, // compressed
            )
            .await
            .expect("Failed to verify reshare responses");

            let (client_key, _, server_key) = out.0.clone().get_standard();
            crate::client::key_gen::tests::check_conformance(server_key, client_key);
            outs.push(out);
        }
        Some(outs)
    } else {
        None
    }
}

async fn poll_new_epoch_result(
    new_epoch_id: &RequestId,
    kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    max_iter: usize,
) -> Vec<(
    u32,
    RequestId,
    Result<Response<EpochResultResponse>, Status>,
)> {
    let mut resp_tasks = JoinSet::new();

    for (party_idx, client) in kms_clients.iter() {
        let mut client = client.clone();

        let reshare_request_id = *new_epoch_id;
        let party_idx = *party_idx;
        resp_tasks.spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut response = client
                .get_epoch_result(tonic::Request::new(reshare_request_id.into()))
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
                    .get_epoch_result(tonic::Request::new(reshare_request_id.into()))
                    .await;
            }
            (party_idx, reshare_request_id, response)
        });
    }

    resp_tasks.join_all().await
}
