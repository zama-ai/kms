use super::*;
use crate::vault::storage::test_support::{
    StorageEntry, StorageEvent, StorageOp, StorageOutcome, assert_same_events,
};

/// Threshold storage pairs `PublicKey` with `FheKeyInfo` and `CRS` with `CrsInfo`.
/// `PublicKey` and `CRS` have no epoch, so all epochs for an ID share them. Resharing writes only
/// the new epoch's `FheKeyInfo` and `CrsInfo`. Failed resharing must not touch either public half.
///
/// This is a regression test for a bug found during a devnet deployment on 0.14.x. It covers
/// both successful rollback and failed rollback. A failed rollback must retain the durable
/// epoch marker and in-memory epoch registration so cleanup can be retried.
async fn run_failed_reshare_storage_test(fail_rollback: bool) {
    let mut rng = AesRng::seed_from_u64(45);
    let epoch_manager = make_epoch_manager::<EmptyPrss>(&mut rng).await;
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        FailingRamStorage::new(),
        FailingRamStorage::new(),
        None,
        HashMap::new(),
    );

    let new_epoch_id = EpochId::new_random(&mut rng);
    let keeper_epoch_id = *DEFAULT_EPOCH_ID;
    let key_id = derive_request_id("reshared_key").unwrap();
    let preproc_id = derive_request_id("reshared_key_preproc").unwrap();
    let crs_id = derive_request_id("reshared_crs").unwrap();
    let unrelated_id = derive_request_id("unrelated_material").unwrap();

    let epoch_data = dummy_epoch_data(*DEFAULT_MPC_CONTEXT);
    epoch_manager
        .session_maker
        .add_epoch(keeper_epoch_id, epoch_data.clone())
        .await;
    epoch_manager
        .session_maker
        .add_epoch(new_epoch_id, epoch_data.clone())
        .await;

    {
        let public_storage = crypto_storage.inner.get_public_storage();
        let mut guard = public_storage.lock().await;
        for public_type in PubDataType::iter().filter(|data_type| *data_type != PubDataType::CRS) {
            store_versioned_at_request_id(
                &mut (*guard),
                &key_id,
                &TestType { i: 7 },
                &public_type.to_string(),
            )
            .await
            .unwrap();
        }
        store_versioned_at_request_id(
            &mut (*guard),
            &crs_id,
            &TestType { i: 8 },
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();
        for public_type in [PubDataType::PublicKey, PubDataType::CRS] {
            store_versioned_at_request_id(
                &mut (*guard),
                &unrelated_id,
                &TestType { i: 9 },
                &public_type.to_string(),
            )
            .await
            .unwrap();
        }
    }

    {
        let private_storage = crypto_storage.get_private_storage();
        let mut guard = private_storage.lock().await;
        for (data_id, epoch_id, data_type, value) in [
            (key_id, keeper_epoch_id, PrivDataType::FheKeyInfo, 10),
            (crs_id, keeper_epoch_id, PrivDataType::CrsInfo, 11),
            (unrelated_id, keeper_epoch_id, PrivDataType::FheKeyInfo, 12),
        ] {
            store_versioned_at_request_and_epoch_id(
                &mut (*guard),
                &data_id,
                &epoch_id,
                &TestType { i: value },
                &data_type.to_string(),
            )
            .await
            .unwrap();
        }
        store_versioned_at_request_and_epoch_id(
            &mut (*guard),
            &unrelated_id,
            &EpochId::new_random(&mut rng),
            &TestType { i: 13 },
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut (*guard),
            &keeper_epoch_id.into(),
            &epoch_data,
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut (*guard),
            &new_epoch_id.into(),
            &epoch_data,
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
    }

    let new_fhe_key_info = StorageEntry::new(
        key_id,
        Some(new_epoch_id),
        PrivDataType::FheKeyInfo.to_string(),
    );
    let new_crs_info = StorageEntry::new(
        crs_id,
        Some(new_epoch_id),
        PrivDataType::CrsInfo.to_string(),
    );
    let new_epoch_data = StorageEntry::new(
        new_epoch_id.into(),
        None,
        PrivDataType::EpochData.to_string(),
    );

    let public_before;
    {
        let public_storage = crypto_storage.inner.get_public_storage();
        let mut guard = public_storage.lock().await;
        guard.clear_events();
        public_before = guard.state();
    }
    let private_before;
    {
        let private_storage = crypto_storage.get_private_storage();
        let mut guard = private_storage.lock().await;
        guard.clear_events();
        guard.set_fail_store_at(new_fhe_key_info.clone());
        if fail_rollback {
            guard.set_fail_delete_at(new_crs_info.clone());
        }
        private_before = guard.state();
    }

    let (_keyset, compressed_keyset) =
        gen_key_set(crate::consts::TEST_PARAM, tfhe::Tag::default(), &mut rng).unwrap();
    let params = crate::consts::TEST_PARAM;
    let config = tfhe::ConfigBuilder::with_custom_parameters(params.classic_pbs())
        .use_dedicated_compact_public_key_parameters(params.dedicated_pk_params().unwrap())
        .build();
    let crs = CompactPkeCrs::from_config(config, 2048).unwrap();

    let mut previous_epoch = make_verified_previous_epoch(
        keeper_epoch_id,
        &key_id,
        &preproc_id,
        crate::consts::TEST_PARAM,
    );
    previous_epoch.crs_info.push(VerifiedCrsInfo {
        crs_id,
        crs_digest: vec![],
    });

    let sk = epoch_manager.base_kms.sig_key().unwrap();
    let res = RealThresholdEpochManager::<
        FailingRamStorage,
        FailingRamStorage,
        EmptyPrss,
        SecureReshareSecretKeys,
    >::store_reshared_keys(
        &crypto_storage,
        &epoch_manager.session_maker,
        &sk,
        &[SigningSchemeType::Ecdsa256k1],
        new_epoch_id,
        vec![],
        &previous_epoch,
        vec![VerifiedPublicMaterial::Compressed(compressed_keyset)],
        vec![PrivateKeySet::init_dummy(crate::consts::TEST_PARAM)],
        &dummy_domain(),
        vec![crs],
    )
    .await;
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("Failed to store all reshared keys for new epoch")
    );

    {
        let public_storage = crypto_storage.inner.get_public_storage();
        let guard = public_storage.lock().await;
        assert_eq!(guard.state(), public_before);
        assert!(
            guard.events().is_empty(),
            "failed resharing must not touch public storage: {:?}",
            guard.events()
        );
    }

    {
        let private_storage = crypto_storage.get_private_storage();
        let guard = private_storage.lock().await;
        // The reshare stores CrsInfo, fails on FheKeyInfo, and then rolls the new epoch back.
        // A failed CrsInfo delete retains the epoch marker so cleanup can run again.
        let mut expected_events = vec![
            StorageEvent::new(
                new_fhe_key_info.clone(),
                StorageOp::Store,
                StorageOutcome::FailedBeforeMutation,
            ),
            StorageEvent::new(
                new_crs_info.clone(),
                StorageOp::Store,
                StorageOutcome::Created,
            ),
        ];

        let mut expected_state = private_before.clone();
        if fail_rollback {
            expected_events.push(StorageEvent::new(
                new_crs_info.clone(),
                StorageOp::Delete,
                StorageOutcome::FailedBeforeMutation,
            ));
            let mut state_without_failed_cleanup = guard.state();
            state_without_failed_cleanup.remove(&new_crs_info);
            assert_eq!(state_without_failed_cleanup, expected_state);
            assert!(guard.state().contains_key(&new_epoch_data));
        } else {
            expected_events.push(StorageEvent::new(
                new_crs_info.clone(),
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ));
            expected_events.push(StorageEvent::new(
                new_epoch_data.clone(),
                StorageOp::Delete,
                StorageOutcome::Deleted,
            ));
            expected_state.remove(&new_epoch_data);
            assert_eq!(guard.state(), expected_state);
        }

        assert_same_events(guard.events(), &expected_events);
    }

    assert_eq!(
        epoch_manager
            .session_maker
            .epoch_exists(&new_epoch_id)
            .await,
        fail_rollback,
        "the failed epoch must remain registered only when cleanup needs a retry"
    );
    assert!(
        epoch_manager
            .session_maker
            .epoch_exists(&keeper_epoch_id)
            .await
    );
}

#[rstest::rstest]
#[case::only_removes_new_epoch_private_material(false)]
#[case::cleanup_failure_keeps_retry_state(true)]
#[tokio::test]
async fn failed_reshare(#[case] fail_rollback: bool) {
    run_failed_reshare_storage_test(fail_rollback).await;
}
