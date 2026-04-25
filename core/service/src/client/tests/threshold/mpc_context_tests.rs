use aes_prng::AesRng;
use kms_grpc::{RequestId, rpc_types::PubDataType};
use rand::SeedableRng;
use tokio::task::JoinSet;

use crate::{
    client::tests::threshold::public_decryption_tests::{
        run_decryption_threshold, run_decryption_threshold_optionally_fail,
    },
    consts::{
        DEFAULT_MPC_CONTEXT, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, SIGNING_KEY_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID_4P,
    },
    cryptography::signatures::PublicSigKey,
    testing::prelude::{TestMaterialSpec, ThresholdTestEnv},
    util::{
        key_setup::test_tools::{EncryptionConfig, TestingPlaintext},
        rate_limiter::RateLimiterConfig,
    },
    vault::storage::{
        StorageType, file::FileStorage, read_context_at_id, read_versioned_at_request_id,
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_context_switch_4p() -> anyhow::Result<()> {
    // 1. setup the threshold handles
    // 2. do a context switch
    // 3. verify that the context switch was successful by doing a decryption
    // 4. delete the context
    // 5. verify that the context is deleted and decryption should fail
    // 6. decrypt with the old context to verify it's still there

    let amount_parties = 4;

    let rate_limiter_conf = RateLimiterConfig {
        bucket_size: 100,
        pub_decrypt: 100,
        user_decrypt: 1,
        crsgen: 1,
        preproc: 1,
        keygen: 1,
        new_epoch: 1,
    };

    // Decrypts a real ciphertext, so needs the full threshold-basic set
    // (client/signing/server-signing/FHE/PRSS).
    let spec = TestMaterialSpec::threshold_basic(amount_parties);

    let env = ThresholdTestEnv::builder()
        .with_test_name("context_switch_4p")
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(spec)
        .with_rate_limiter(rate_limiter_conf)
        .with_prss()
        .force_isolated()
        .build()
        .await?;

    let mut internal_client = env.create_internal_client(&TEST_PARAM, None).await?;
    let (mut kms_clients, mut kms_servers, material_path, _guards) = env.into_parts();

    // There is already a previous context by default.
    //
    // NOTE: once we remove the default context (zama-ai/kms-internal/issues/2758),
    // we need to change this test to create a new context first before switching contexts.
    let previous_epoch_id = *DEFAULT_MPC_CONTEXT;

    let pub_storage_prefixes = &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let priv_storage_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..amount_parties];
    let all_private_storage = priv_storage_prefixes
        .iter()
        .map(|prefix| {
            FileStorage::new(Some(&material_path), StorageType::PRIV, prefix.as_deref()).unwrap()
        })
        .collect::<Vec<_>>();

    let all_public_storage = pub_storage_prefixes
        .iter()
        .map(|prefix| {
            FileStorage::new(Some(&material_path), StorageType::PUB, prefix.as_deref()).unwrap()
        })
        .collect::<Vec<_>>();

    let previous_epoch = read_context_at_id(&all_private_storage[0], &previous_epoch_id).await?;
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
            .await?;
            node.verification_key = Some(pk);
        }
        new_context
    };
    let new_context_id = *new_context.context_id();
    println!("got new context: {:?}", new_context);

    {
        let req = internal_client.new_mpc_context_request(new_context)?;

        let mut req_tasks = JoinSet::new();
        for (_, client) in kms_clients.iter() {
            let req_clone = req.clone();
            let mut client = client.clone();
            req_tasks.spawn(async move { client.new_mpc_context(req_clone).await });
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner??.into_inner());
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
        None,
        key_id,
        Some(&new_context_id),
        vec![TestingPlaintext::Bool(true)],
        enc_config,
        None,
        1,
        Some(&material_path),
        false, // compressed_keys
    )
    .await;

    // delete the new context
    {
        let req = internal_client.destroy_mpc_context_request(&new_context_id)?;

        let mut req_tasks = JoinSet::new();
        for (_, client) in kms_clients.iter() {
            let req_clone = req.clone();
            let mut client = client.clone();
            req_tasks.spawn(async move { client.destroy_mpc_context(req_clone).await });
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner??.into_inner());
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
        None,
        key_id,
        Some(&new_context_id),
        vec![TestingPlaintext::Bool(false); 2],
        enc_config,
        None,
        1,
        Some(&material_path),
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
        None,
        key_id,
        Some(&previous_epoch_id),
        vec![TestingPlaintext::Bool(false); 3],
        enc_config,
        None,
        1,
        Some(&material_path),
        false, // compressed_keys
    )
    .await;

    for (_, server) in kms_servers {
        server.assert_shutdown().await;
    }

    Ok(())
}
