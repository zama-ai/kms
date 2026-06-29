use aes_prng::AesRng;
use kms_grpc::{
    RequestId,
    kms::v1::DestroyMpcContextRequest,
    rpc_types::{PrivDataType, PubDataType},
};
use rand::SeedableRng;
use threshold_execution::{
    endpoints::decryption::DecryptionMode, tfhe_internals::parameters::DKGParams,
};
use tokio::task::JoinSet;

use crate::{
    client::tests::threshold::public_decryption_tests::{
        run_decryption_threshold, run_decryption_threshold_optionally_fail,
    },
    consts::{
        DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, SIGNING_KEY_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID_4P,
    },
    cryptography::signatures::PublicSigKey,
    engine::context::SignerAddress,
    testing::prelude::{TestMaterialSpec, ThresholdTestEnv},
    util::{
        key_setup::test_tools::{EncryptionConfig, TestingPlaintext},
        rate_limiter::RateLimiterConfig,
    },
    vault::storage::{
        StorageReader, StorageReaderExt, StorageType, file::FileStorage, read_context_at_id,
        read_versioned_at_request_id, store_versioned_at_request_and_epoch_id, tests::TestType,
    },
};

#[tokio::test(flavor = "multi_thread")]
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

    // Decrypts a real ciphertext, so needs the full threshold-basic set
    // (client/signing/server-signing/FHE/PRSS).
    let spec = TestMaterialSpec::threshold_basic(amount_parties);

    let mut builder = ThresholdTestEnv::builder()
        .with_test_name(format!("context_switch_{amount_parties}p"))
        .with_party_count(amount_parties)
        .with_threshold(1)
        .with_material_spec(spec)
        .with_rate_limiter(rate_limiter_conf)
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
            node.signer_address = Some(SignerAddress(pk.address()));
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
        for client in kms_clients.values() {
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
        None,
        key_id,
        Some(&new_context_id),
        vec![TestingPlaintext::Bool(true)],
        enc_config,
        None,
        1,
        Some(&material_path),
    )
    .await;

    // delete the new context
    {
        // This context was created without an epoch transition of its own (decryption above reused
        // the existing key/epoch), so it has no associated epochs to remove.
        let req = internal_client
            .destroy_mpc_context_request(&new_context_id, &[])
            .unwrap();

        let mut req_tasks = JoinSet::new();
        for client in kms_clients.values() {
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
        None,
        key_id,
        Some(&new_context_id),
        vec![TestingPlaintext::Bool(false); 2],
        enc_config,
        None,
        1,
        Some(&material_path),
        true,
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
    )
    .await;

    for (_, server) in kms_servers {
        server.assert_shutdown().await;
    }
}

// `DestroyMpcContext` with a non-empty `epoch_ids` erases the epoch's private data on every party, over real gRPC.
#[tokio::test]
async fn test_destroy_context_erases_epoch_data_4p() {
    let party_count = 4;
    let env = ThresholdTestEnv::builder()
        .with_test_name("destroy_context_erases_epoch_data_4p".to_string())
        .with_party_count(party_count)
        .with_threshold(1)
        .with_material_spec(TestMaterialSpec::threshold_signing_only(party_count))
        .with_prss()
        .build()
        .await
        .expect("ThresholdTestEnv setup failed");
    let (kms_clients, kms_servers, material_path, _guards) = env.into_parts();

    let priv_prefixes = &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..party_count];
    let default_context = *DEFAULT_MPC_CONTEXT;
    let epoch_id = *DEFAULT_EPOCH_ID;
    let epoch_req_id: RequestId = epoch_id.into();
    let data_id = RequestId::from_bytes([7u8; 32]);
    let fhe_key_info = PrivDataType::FheKeyInfo.to_string();
    let prss_type = PrivDataType::PrssSetupCombined.to_string();

    // Seed dummy private data under the default epoch for every party.
    for prefix in priv_prefixes {
        let mut storage =
            FileStorage::new(Some(&material_path), StorageType::PRIV, prefix.as_deref()).unwrap();
        store_versioned_at_request_and_epoch_id(
            &mut storage,
            &data_id,
            &epoch_id,
            &TestType { i: 42 },
            &fhe_key_info,
        )
        .await
        .unwrap();
        // Sanity: the data we just wrote is present before destruction.
        assert!(
            storage
                .all_data_ids_at_epoch(&epoch_id, &fhe_key_info)
                .await
                .unwrap()
                .contains(&data_id)
        );
    }

    // Destroy the default context together with the default epoch's ID over gRPC.
    let mut destroy_tasks = JoinSet::new();
    for client in kms_clients.values() {
        let mut client = client.clone();
        let req = DestroyMpcContextRequest {
            context_id: Some(default_context.into()),
            epoch_ids: vec![epoch_id.into()],
        };
        destroy_tasks.spawn(async move { client.destroy_mpc_context(req).await });
    }
    destroy_tasks.join_all().await.into_iter().for_each(|res| {
        assert!(res.is_ok(), "DestroyMpcContext failed: {:?}", res.err());
    });

    // Every party has had the epoch's private data and PRSS erased, and the context is gone.
    for prefix in priv_prefixes {
        let storage =
            FileStorage::new(Some(&material_path), StorageType::PRIV, prefix.as_deref()).unwrap();

        let ids = storage
            .all_data_ids_at_epoch(&epoch_id, &fhe_key_info)
            .await
            .unwrap();
        assert!(
            ids.is_empty(),
            "epoch key shares must be erased for {prefix:?}"
        );

        assert!(
            !storage
                .data_exists(&epoch_req_id, &prss_type)
                .await
                .unwrap(),
            "epoch PRSS must be erased for {prefix:?}"
        );

        read_context_at_id(&storage, &default_context)
            .await
            .unwrap_err();
    }

    for (_, server) in kms_servers {
        server.assert_shutdown().await;
    }
}
