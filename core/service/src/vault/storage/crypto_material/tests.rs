use crate::{
    consts::DEFAULT_EPOCH_ID,
    cryptography::signatures::gen_sig_keys,
    dummy_domain,
    engine::base::{KeyGenMetadata, derive_request_id},
};
use aes_prng::AesRng;
use kms_grpc::{
    EpochId, RequestId,
    rpc_types::{PrivDataType, PubDataType},
};
use observability::metrics_names::OP_CRS_GEN_REQUEST;
use rand::SeedableRng;
use std::collections::HashMap;
use std::sync::Arc;
use tfhe::{CompactPublicKey, ConfigBuilder, ServerKey, shortint::ClassicPBSParameters};
use tfhe::{core_crypto::prelude::NormalizedHammingWeightBound, xof_key_set::CompressedXofKeySet};
use threshold_execution::tfhe_internals::{
    parameters::DKGParams,
    public_keysets::FhePubKeySet,
    test_feature::{gen_uncompressed_key_set, keygen_all_party_shares_from_keyset},
};
use tokio::sync::{Mutex, RwLock};

use crate::{
    consts::TEST_PARAM,
    engine::{
        base::KmsFheKeyHandles,
        centralized::central_kms::async_generate_crs,
        threshold::service::{PublicKeyMaterial, ThresholdFheKeys},
    },
    util::meta_store::MetaStore,
    vault::storage::{
        StorageReader, StorageReaderExt,
        crypto_material::{
            CentralizedCryptoMaterialStorage, CryptoMaterialStorage, ThresholdCryptoMaterialStorage,
        },
        ram::{FailingRamStorage, RamStorage},
        store_versioned_at_request_id,
    },
};

fn dummy_info() -> KeyGenMetadata {
    let req_id = derive_request_id("dummy_info").unwrap();
    KeyGenMetadata::new(req_id, req_id, HashMap::new(), vec![])
}

#[tokio::test]
async fn write_crs() {
    // write the CRS, first try with storage that are functional
    // then try to write into a failing storage and expect an error
    let pub_storage = Arc::new(Mutex::new(FailingRamStorage::new(100)));
    let crypto_storage = CryptoMaterialStorage {
        public_storage: pub_storage.clone(),
        private_storage: Arc::new(Mutex::new(RamStorage::new())),
        backup_vault: None,
    };

    let mut rng = AesRng::seed_from_u64(100);
    let crs_id = RequestId::new_random(&mut rng);
    let domain = dummy_domain();
    let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
    let (pp, crs_info) =
        async_generate_crs(&sig_sk, TEST_PARAM, Some(1), domain, vec![], &crs_id, rng)
            .await
            .unwrap();
    let req_id = derive_request_id("write_crs").unwrap();
    let default_epoch_id = *DEFAULT_EPOCH_ID;

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // writing to an empty meta store should fail
    let result = crypto_storage
        .write_crs_with_meta_store(
            &req_id,
            &default_epoch_id,
            pp.clone(),
            crs_info.clone(),
            meta_store.clone(),
            OP_CRS_GEN_REQUEST,
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains(&format!(
            "Error while updating meta store for {req_id}: request is missing"
        )),
        "expected meta-store update failure when empty, got: {err}"
    );
    {
        let guard = pub_storage.lock().await;
        let crs_exists = guard
            .data_exists(&req_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        assert!(!crs_exists, "CRS should be purged after meta-store failure");
    }
    {
        let guard = crypto_storage.private_storage.lock().await;
        let crs_info_exists = guard
            .data_exists_at_epoch(
                &req_id,
                &default_epoch_id,
                &PrivDataType::CrsInfo.to_string(),
            )
            .await
            .unwrap();
        assert!(
            !crs_info_exists,
            "CRS metadata should be purged after meta-store failure"
        );
    }

    // update the meta store and we should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_crs_with_meta_store(
            &req_id,
            &default_epoch_id,
            pp.clone(),
            crs_info.clone(),
            meta_store.clone(),
            OP_CRS_GEN_REQUEST,
        )
        .await;
    assert!(result.is_ok(), "expected success: {result:?}");

    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    let result = crypto_storage
        .write_crs_with_meta_store(
            &req_id,
            &default_epoch_id,
            pp.clone(),
            crs_info.clone(),
            meta_store.clone(),
            OP_CRS_GEN_REQUEST,
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating meta store"),
        "expected meta-store conflict on double write, got: {err}"
    );
    assert!(
        err.contains("request is already completed"),
        "expected meta-store conflict on double write, got: {err}"
    );
    {
        let guard = pub_storage.lock().await;
        let crs_exists = guard
            .data_exists(&req_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        assert!(
            crs_exists,
            "Already-committed CRS should remain after duplicate-write conflict"
        );
    }

    // writing on a failed storage device should fail
    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }
    let new_req_id = derive_request_id("write_crs_2").unwrap();
    {
        let mut guard = meta_store.write().await;
        guard.insert(&new_req_id).unwrap();
    }
    let result = crypto_storage
        .write_crs_with_meta_store(
            &new_req_id,
            &default_epoch_id,
            pp,
            crs_info,
            meta_store.clone(),
            OP_CRS_GEN_REQUEST,
        )
        .await;
    let err = result.unwrap_err().to_string();
    // Successful purging since there is actually nothing to purge
    assert!(
        err.contains("successfully purged dangling CRS material and updated meta store"),
        "expected underlying storage failure, got: {err}"
    );

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
        assert!(guard.exists(&new_req_id));
    }
}

#[tokio::test]
async fn read_public_key() {
    // it doens't matter if we use centralized or threshold
    // the public key reading logic is the same
    let crypto_storage = CentralizedCryptoMaterialStorage::new(
        FailingRamStorage::new(100),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let pub_storage = crypto_storage.inner.public_storage.clone();

    let pbs_params: ClassicPBSParameters = TEST_PARAM
        .get_params_basics_handle()
        .to_classic_pbs_parameters();
    let config = ConfigBuilder::with_custom_parameters(pbs_params);
    let client_key = tfhe::ClientKey::generate(config);
    let public_key = CompactPublicKey::new(&client_key);

    let req_id = derive_request_id("read_keys").unwrap();
    {
        let pub_storage = pub_storage.clone();
        let mut s = pub_storage.lock().await;
        store_versioned_at_request_id(
            &mut (*s),
            &req_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }

    // reading the public key without cache should succeed
    let _pk = crypto_storage.inner.read_cloned_pk(&req_id).await.unwrap();
}

#[tokio::test]
async fn write_central_keys() {
    let param = TEST_PARAM;
    let crypto_storage = CentralizedCryptoMaterialStorage::new(
        FailingRamStorage::new(100),
        RamStorage::new(),
        None,
        HashMap::new(),
    );
    let pub_storage = crypto_storage.inner.public_storage.clone();

    let req_id = derive_request_id("write_central_keys").unwrap();
    let epoch_id: EpochId = derive_request_id("write_central_keys_epoch")
        .unwrap()
        .into();

    let pbs_params: ClassicPBSParameters =
        param.get_params_basics_handle().to_classic_pbs_parameters();
    let sns_params = match param {
        DKGParams::WithoutSnS(_) => panic!("expect sns"),
        DKGParams::WithSnS(dkgparams_sn_s) => dkgparams_sn_s.sns_params,
    };
    let config =
        ConfigBuilder::with_custom_parameters(pbs_params).enable_noise_squashing(sns_params);
    let client_key = tfhe::ClientKey::generate(config);
    let public_key = CompactPublicKey::new(&client_key);
    let server_key = ServerKey::new(&client_key);
    let key_info = KmsFheKeyHandles {
        client_key,
        decompression_key: None,
        public_key_info: dummy_info(),
    };
    let fhe_key_set = FhePubKeySet {
        public_key,
        server_key,
    };

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // write to an empty meta store should fail
    let result = crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            &epoch_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating PK meta store for"),
        "expected PK meta-store update failure when empty, got: {err}"
    );

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            &epoch_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "expected success: {result:?}");

    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    let result = crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            &epoch_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating PK meta store for"),
        "expected PK meta-store conflict on double write, got: {err}"
    );

    // write on a failed storage device should fail
    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }
    let new_req_id = derive_request_id("write_central_keys_2").unwrap();
    let result = crypto_storage
        .write_centralized_keys_with_meta_store(
            &new_req_id,
            &epoch_id,
            key_info,
            fhe_key_set,
            meta_store.clone(),
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Storage write failed for key"),
        "expected underlying storage failure, got: {err}"
    );

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
        assert!(!guard.exists(&new_req_id));
    }
}

#[tokio::test]
async fn write_central_keys_failed_storage_sets_terminal_error() {
    let param = TEST_PARAM;
    let crypto_storage = CentralizedCryptoMaterialStorage::new(
        FailingRamStorage::new(100),
        RamStorage::new(),
        None,
        HashMap::new(),
    );
    let pub_storage = crypto_storage.inner.public_storage.clone();

    let req_id =
        derive_request_id("write_central_keys_failed_storage_sets_terminal_error").unwrap();
    let epoch_id: EpochId =
        derive_request_id("write_central_keys_failed_storage_sets_terminal_error_epoch")
            .unwrap()
            .into();

    let pbs_params: ClassicPBSParameters =
        param.get_params_basics_handle().to_classic_pbs_parameters();
    let sns_params = match param {
        DKGParams::WithoutSnS(_) => panic!("expect sns"),
        DKGParams::WithSnS(dkgparams_sn_s) => dkgparams_sn_s.sns_params,
    };
    let config =
        ConfigBuilder::with_custom_parameters(pbs_params).enable_noise_squashing(sns_params);
    let client_key = tfhe::ClientKey::generate(config);
    let public_key = CompactPublicKey::new(&client_key);
    let server_key = ServerKey::new(&client_key);
    let key_info = KmsFheKeyHandles {
        client_key,
        decompression_key: None,
        public_key_info: dummy_info(),
    };
    let fhe_key_set = FhePubKeySet {
        public_key,
        server_key,
    };

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    {
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }

    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }

    let result = crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            &epoch_id,
            key_info,
            fhe_key_set,
            meta_store.clone(),
        )
        .await;
    assert!(
        result.is_err(),
        "expected storage failure to surface an error, got: {result:?}"
    );

    let status = {
        let guard = meta_store.read().await;
        guard
            .retrieve(&req_id)
            .expect("request should remain tracked in meta store after failure")
    };
    assert!(
        status.get().await.as_ref().is_err(),
        "expected terminal error status in meta store after storage failure"
    );
}

#[tokio::test]
async fn write_threshold_empty_update() {
    let req_id = derive_request_id("write_threshold_empty_update").unwrap();
    let epoch_id = derive_request_id("write_threshold_empty_update_epoch")
        .unwrap()
        .into();
    let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store(&req_id);
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // write to an empty meta store should fail
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating meta store for"),
        "expected meta-store update failure when empty, got: {err}"
    );
    {
        let guard = crypto_storage.inner.public_storage.lock().await;
        let pk_exists = guard
            .data_exists(&req_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        let sk_exists = guard
            .data_exists(&req_id, &PubDataType::ServerKey.to_string())
            .await
            .unwrap();
        assert!(
            !pk_exists && !sk_exists,
            "threshold public material should be purged after meta-store failure"
        );
    }
    {
        let guard = crypto_storage.inner.private_storage.lock().await;
        let key_info_exists = guard
            .data_exists_at_epoch(&req_id, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .unwrap();
        assert!(
            !key_info_exists,
            "threshold private material should be purged after meta-store failure"
        );
    }
    let cache_read = crypto_storage
        .read_guarded_threshold_fhe_keys(&req_id, &epoch_id)
        .await;
    assert!(
        cache_read.is_err(),
        "threshold cache should not retain failed writes"
    );

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "expected success: {result:?}");

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
    }
}

#[tokio::test]
async fn write_threshold_keys_meta_update() {
    let req_id = derive_request_id("write_threshold_keys_meta_update").unwrap();
    let epoch_id: EpochId = derive_request_id("write_threshold_keys_meta_update_epoch")
        .unwrap()
        .into();
    let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store(&req_id);
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "expected success: {result:?}");
    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
    }
    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating meta store for"),
        "expected meta-store conflict on double write, got: {err}"
    );
    {
        let guard = crypto_storage.inner.public_storage.lock().await;
        let pk_exists = guard
            .data_exists(&req_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        let sk_exists = guard
            .data_exists(&req_id, &PubDataType::ServerKey.to_string())
            .await
            .unwrap();
        assert!(
            pk_exists && sk_exists,
            "Already-committed threshold public material should remain on duplicate conflict"
        );
    }
    {
        let guard = crypto_storage.inner.private_storage.lock().await;
        let key_info_exists = guard
            .data_exists_at_epoch(&req_id, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .unwrap();
        assert!(
            key_info_exists,
            "Already-committed threshold private material should remain on duplicate conflict"
        );
    }

    let refreshed = crypto_storage
        .read_guarded_threshold_fhe_keys(&req_id, &epoch_id)
        .await;
    assert!(
        refreshed.is_ok(),
        "threshold read path should still succeed after duplicate conflict"
    );
}

#[tokio::test]
async fn write_threshold_keys_failed_storage() {
    let req_id = derive_request_id("write_threshold_keys_failed_storage").unwrap();
    let epoch_id: EpochId = derive_request_id("write_threshold_keys_failed_storage_epoch")
        .unwrap()
        .into();
    let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store(&req_id);
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let pub_storage = crypto_storage.inner.public_storage.clone();

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "expected success: {result:?}");

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
    }

    // write on a failed storage device should fail
    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }
    let new_req_id = derive_request_id("write_threshold_keys_failed_storage_2").unwrap();
    {
        let mut guard = meta_store.write().await;
        guard.insert(&new_req_id).unwrap();
    }
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store(
            &new_req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Storage write failed for threshold key"),
        "expected underlying storage failure, got: {err}"
    );

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
        assert!(guard.exists(&new_req_id));
    }
}

#[tokio::test]
async fn read_guarded_threshold_fhe_keys_not_found() {
    let req_id = derive_request_id("read_guarded_threshold_fhe_keys_not_found").unwrap();
    let epoch_id: EpochId = derive_request_id("read_guarded_threshold_fhe_keys_not_found_epoch")
        .unwrap()
        .into();

    // Create a threshold storage with no keys in the cache and no keys in storage
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        FailingRamStorage::new(100),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    // Try to read a non-existent key - should return an error
    let result = crypto_storage
        .read_guarded_threshold_fhe_keys(&req_id, &epoch_id)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let expected_msg = format!(
        "Could not find data at (data_type: FheKeyInfo, data_id: {}, epoch_id: {})",
        req_id, epoch_id
    );
    assert!(
        err.to_string().contains(&expected_msg),
        "Unexpected error message: {}",
        err
    );
}

#[tokio::test]
async fn write_threshold_compressed_empty_update_cleans_up() {
    let req_id = derive_request_id("write_threshold_compressed_empty_update").unwrap();
    let epoch_id: EpochId = derive_request_id("write_threshold_compressed_empty_update_epoch")
        .unwrap()
        .into();
    let (crypto_storage, mut threshold_fhe_keys, _fhe_key_set) = setup_threshold_store(&req_id);

    let params = TEST_PARAM;
    let config = params.to_tfhe_config();
    let max_norm_hwt = params
        .get_params_basics_handle()
        .get_sk_deviations()
        .map(|x| x.pmax)
        .unwrap_or(1.0);
    let max_norm_hwt = NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();
    let (_client_key, compressed_keyset) = CompressedXofKeySet::generate(
        config,
        vec![42, 43, 44, 45],
        params.get_params_basics_handle().get_sec() as u32,
        max_norm_hwt,
        req_id.into(),
    )
    .unwrap();
    threshold_fhe_keys.public_material = PublicKeyMaterial::new(compressed_keyset.clone());

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store_compressed(
            &req_id,
            &epoch_id,
            threshold_fhe_keys,
            &compressed_keyset,
            meta_store,
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating meta store for"),
        "expected meta-store update failure when empty, got: {err}"
    );

    {
        let guard = crypto_storage.inner.public_storage.lock().await;
        let compressed_exists = guard
            .data_exists(&req_id, &PubDataType::CompressedXofKeySet.to_string())
            .await
            .unwrap();
        assert!(
            !compressed_exists,
            "compressed public material should be purged after meta-store failure"
        );
    }
    {
        let guard = crypto_storage.inner.private_storage.lock().await;
        let key_info_exists = guard
            .data_exists_at_epoch(&req_id, &epoch_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .unwrap();
        assert!(
            !key_info_exists,
            "compressed private material should be purged after meta-store failure"
        );
    }
    let cache_read = crypto_storage
        .read_guarded_threshold_fhe_keys(&req_id, &epoch_id)
        .await;
    assert!(
        cache_read.is_err(),
        "compressed threshold cache should not retain failed writes"
    );
}

#[tokio::test]
async fn read_guarded_crypto_material_from_cache_not_found() {
    let key_id = derive_request_id("read_guarded_crypto_material_from_cache_not_found").unwrap();
    let epoch_id: EpochId =
        derive_request_id("read_guarded_crypto_material_from_cache_not_found_epoch")
            .unwrap()
            .into();

    // Create an empty cache
    let empty_cache: Arc<RwLock<HashMap<(RequestId, EpochId), ThresholdFheKeys>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Try to read from an empty cache - should return an error
    let result = CryptoMaterialStorage::<FailingRamStorage, RamStorage>::read_guarded_crypto_material_from_cache(
        &key_id,
        &epoch_id,
        empty_cache,
    )
    .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let expected_msg = format!(
        "Failed to find crypto material in cache for request ID {}, epoch ID {}",
        key_id, epoch_id
    );
    assert!(
        err.to_string().contains(&expected_msg),
        "Unexpected error message: {}",
        err
    );
}

fn setup_threshold_store(
    req_id: &RequestId,
) -> (
    ThresholdCryptoMaterialStorage<FailingRamStorage, RamStorage>,
    ThresholdFheKeys,
    FhePubKeySet,
) {
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        FailingRamStorage::new(100),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let pbs_params: ClassicPBSParameters = TEST_PARAM
        .get_params_basics_handle()
        .to_classic_pbs_parameters();

    let mut rng = AesRng::seed_from_u64(100);
    // TODO(dp): should probably switch over to compressed keys here (and below).
    let keyset = gen_uncompressed_key_set(TEST_PARAM, req_id.into(), &mut rng);
    let key_shares =
        keygen_all_party_shares_from_keyset(&keyset, pbs_params, &mut rng, 4, 1).unwrap();

    let fhe_key_set = keyset.public_keys.clone();

    let (integer_server_key, _, _, _, sns_key, _, _, _) =
        keyset.public_keys.server_key.clone().into_raw_parts();

    let threshold_fhe_keys = ThresholdFheKeys::new(
        Arc::new(key_shares[0].to_owned()),
        PublicKeyMaterial::new_uncompressed(
            Arc::new(integer_server_key),
            sns_key.map(Arc::new),
            None,
        ),
        dummy_info(),
    );
    (crypto_storage, threshold_fhe_keys, fhe_key_set)
}
