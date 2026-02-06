use aes_prng::AesRng;
use kms_grpc::{rpc_types::PubDataType, RequestId};
use rand::SeedableRng;
use threshold_fhe::execution::{
    endpoints::decryption::DecryptionMode, tfhe_internals::parameters::DKGParams,
};
use tokio::task::JoinSet;

use crate::{
    client::tests::threshold::{
        common::threshold_handles,
        public_decryption_tests::{
            run_decryption_threshold, run_decryption_threshold_optionally_fail,
        },
    },
    consts::{
        DEFAULT_MPC_CONTEXT, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, SIGNING_KEY_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID_4P,
    },
    cryptography::signatures::PublicSigKey,
    util::{
        key_setup::test_tools::{EncryptionConfig, TestingPlaintext},
        rate_limiter::RateLimiterConfig,
    },
    vault::storage::{
        file::FileStorage, read_context_at_id, read_versioned_at_request_id, StorageType,
    },
};

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn test_context_switch_4p() {
    do_context_switch(TEST_PARAM, 4, None).await;
}

async fn do_context_switch(
    dkg_params: DKGParams,
    amount_parties: usize,
    decryption_mode: Option<DecryptionMode>,
) {
    // 1. setup the threshold handles
    // 2. do a context switch
    // 3. verify that the context switch was successful by doing a decryption
    // 4. delete the context
    // 5. verify that the context is deleted and decryption should fail
    // 6. decrypt with the old context to verify it's still there

    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 100,
        user_decrypt: 1,
        crsgen: 1,
        preproc: 1,
        keygen: 1,
        new_epoch: 1,
    };
    let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
        dkg_params,
        amount_parties,
        true,
        Some(rate_limiter_conf),
        decryption_mode,
    )
    .await;

    // There is already a previous context by default.
    //
    // NOTE: once we remove the default context (zama-ai/kms-internal/issues/2758),
    // we need to change this test to create a new context first before switching contexts.
    let previous_epoch_id = *DEFAULT_MPC_CONTEXT;

    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let all_private_storage = priv_storage_prefixes
        .iter()
        .map(|prefix| FileStorage::new(None, StorageType::PRIV, prefix.as_deref()).unwrap())
        .collect::<Vec<_>>();

    let all_public_storage = pub_storage_prefixes
        .iter()
        .map(|prefix| FileStorage::new(None, StorageType::PUB, prefix.as_deref()).unwrap())
        .collect::<Vec<_>>();

    let previous_epoch = read_context_at_id(&all_private_storage[0], &previous_epoch_id)
        .await
        .unwrap();
    println!("previous context: {:?}", previous_epoch);

    let new_context = {
        let mut new_context = previous_epoch.clone();
        let mut rng = AesRng::seed_from_u64(78);
        let context_id = RequestId::new_random(&mut rng);
        new_context.context_id = context_id.into();

        // note that there's no verification key during initialization of the default context
        // so the new context must use the correct verification keys
        assert_eq!(new_context.mpc_nodes.len(), 4);
        for node in new_context.mpc_nodes.iter_mut() {
            let pk: PublicSigKey = read_versioned_at_request_id(
                &all_public_storage[node.party_id as usize - 1],
                &SIGNING_KEY_ID,
                &PubDataType::VerfKey.to_string(),
            )
            .await
            .unwrap();
            node.verification_key = Some(pk);
        }
        new_context
    };
    let new_context_id = *new_context.context_id();
    println!("got new context: {:?}", new_context);

    {
        let req = internal_client
            .new_mpc_context_request(new_context)
            .unwrap();

        let mut req_tasks = JoinSet::new();
        for (_, client) in kms_clients.iter() {
            let req_clone = req.clone();
            let mut client = client.clone();
            req_tasks.spawn(async move { client.new_mpc_context(req_clone).await });
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), kms_clients.len());
    }

    // run a decryption test
    let enc_config = EncryptionConfig {
        compression: true,
        precompute_sns: true,
    };
    let key_id = &TEST_THRESHOLD_KEY_ID_4P;
    run_decryption_threshold(
        amount_parties,
        &mut kms_servers,
        &mut kms_clients,
        &mut internal_client,
        key_id,
        Some(&new_context_id),
        vec![TestingPlaintext::Bool(true)],
        enc_config,
        None,
        1,
        None,
        false, // compressed_keys
    )
    .await;

    // delete the new context
    {
        let req = internal_client
            .destroy_mpc_context_request(&new_context_id)
            .unwrap();

        let mut req_tasks = JoinSet::new();
        for (_, client) in kms_clients.iter() {
            let req_clone = req.clone();
            let mut client = client.clone();
            req_tasks.spawn(async move { client.destroy_mpc_context(req_clone).await });
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), kms_clients.len());
    }

    // run the request again with the new context ID (which is deleted)
    // this should fail.
    run_decryption_threshold_optionally_fail(
        amount_parties,
        &mut kms_servers,
        &mut kms_clients,
        &mut internal_client,
        key_id,
        Some(&new_context_id),
        vec![TestingPlaintext::Bool(false); 2],
        enc_config,
        None,
        1,
        None,
        true,
        false, // compressed_keys
    )
    .await;

    // running the request with the old context ID should still work
    run_decryption_threshold(
        amount_parties,
        &mut kms_servers,
        &mut kms_clients,
        &mut internal_client,
        key_id,
        Some(&previous_epoch_id),
        vec![TestingPlaintext::Bool(false); 3],
        enc_config,
        None,
        1,
        None,
        false, // compressed_keys
    )
    .await;

    for (_, server) in kms_servers {
        server.assert_shutdown().await;
    }
}
