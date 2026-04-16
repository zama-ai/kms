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
        delete_at_request_id,
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
    let (compact_pk, _sk) = compressed_keyset
        .clone()
        .decompress()
        .unwrap()
        .into_raw_parts();
    threshold_fhe_keys.public_material = PublicKeyMaterial::new(compressed_keyset.clone());

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let result = crypto_storage
        .write_threshold_keys_with_dkg_meta_store_compressed(
            &req_id,
            &epoch_id,
            threshold_fhe_keys,
            &compressed_keyset,
            &compact_pk,
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
async fn compressed_fhe_keys_exist_requires_standalone_public_key() {
    let req_id =
        derive_request_id("compressed_fhe_keys_exist_requires_standalone_public_key").unwrap();
    let epoch_id: EpochId =
        derive_request_id("compressed_fhe_keys_exist_requires_standalone_public_key_epoch")
            .unwrap()
            .into();

    let crypto_storage = CentralizedCryptoMaterialStorage::new(
        FailingRamStorage::new(100),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let params = TEST_PARAM;
    let config = params.to_tfhe_config();
    let max_norm_hwt = params
        .get_params_basics_handle()
        .get_sk_deviations()
        .map(|x| x.pmax)
        .unwrap_or(1.0);
    let max_norm_hwt = NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();
    let (client_key, compressed_keyset) = CompressedXofKeySet::generate(
        config,
        vec![50, 51, 52, 53],
        params.get_params_basics_handle().get_sec() as u32,
        max_norm_hwt,
        req_id.into(),
    )
    .unwrap();
    let (compact_pk, _server_key) = compressed_keyset
        .clone()
        .decompress()
        .unwrap()
        .into_raw_parts();
    let key_info = KmsFheKeyHandles {
        client_key,
        decompression_key: None,
        public_key_info: dummy_info(),
    };

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    {
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }

    crypto_storage
        .write_centralized_compressed_keys_with_meta_store(
            &req_id,
            &epoch_id,
            key_info,
            &compressed_keyset,
            &compact_pk,
            meta_store,
        )
        .await
        .unwrap();

    assert!(
        crypto_storage
            .inner
            .fhe_keys_exist(&req_id, &epoch_id)
            .await
            .unwrap(),
        "sanity check: complete compressed layout should be considered present"
    );

    {
        let mut guard = crypto_storage.inner.public_storage.lock().await;
        delete_at_request_id(&mut *guard, &req_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
    }

    assert!(
        !crypto_storage
            .inner
            .fhe_keys_exist(&req_id, &epoch_id)
            .await
            .unwrap(),
        "compressed keys should be treated as missing when the standalone PublicKey is absent"
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

    let (integer_server_key, _, _, _, sns_key, _, _, _, _) =
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

/// Helper to generate a CompressedXofKeySet and matching ThresholdFheKeys with proper metadata.
/// Takes the `compact_pk` explicitly so tests can reproduce the production invariant that
/// the old CompactPublicKey bytes are preserved at the new key ID during migration.
fn generate_compressed_keyset_and_fhe_keys(
    req_id: &RequestId,
    prep_id: &RequestId,
    private_keys: Arc<threshold_execution::tfhe_internals::private_keysets::PrivateKeySet<4>>,
    compact_pk: &tfhe::CompactPublicKey,
    sk: &crate::cryptography::signatures::PrivateSigKey,
    domain: &alloy_sol_types::Eip712Domain,
) -> (CompressedXofKeySet, ThresholdFheKeys) {
    use crate::engine::base::{DSEP_PUBDATA_KEY, compute_info_compressed_keygen};

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

    let info = compute_info_compressed_keygen(
        sk,
        &DSEP_PUBDATA_KEY,
        prep_id,
        req_id,
        &compressed_keyset,
        compact_pk,
        domain,
        vec![],
    )
    .unwrap();

    let threshold_fhe_keys = ThresholdFheKeys::new(
        private_keys,
        PublicKeyMaterial::new(compressed_keyset.clone()),
        info,
    );
    (compressed_keyset, threshold_fhe_keys)
}

/// Seed an `old_key_id` with a pre-migration uncompressed keyset whose
/// `key_digest_map` covers PublicKey and ServerKey, plus the matching
/// pub-data files. Returns the pre-migration ThresholdFheKeys and the
/// CompactPublicKey stored at `old_key_id` so callers can feed the same
/// bytes into the migrated keyset (mirroring the production invariant
/// that the old compact PK is preserved at `new_key_id`).
async fn setup_pre_migration_uncompressed(
    crypto_storage: &ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
    old_key_id: &RequestId,
    epoch_id: &EpochId,
    sk: &crate::cryptography::signatures::PrivateSigKey,
    prep_id: &RequestId,
    domain: &alloy_sol_types::Eip712Domain,
) -> (ThresholdFheKeys, tfhe::CompactPublicKey) {
    use crate::engine::base::{DSEP_PUBDATA_KEY, compute_info_standard_keygen};
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let (_, fhe_keys_skeleton, fhe_key_set) = setup_threshold_store(old_key_id);
    let compact_pk = fhe_key_set.public_key.clone();

    // Compute real metadata that matches what we'll actually store in pub storage.
    let info = compute_info_standard_keygen(
        sk,
        &DSEP_PUBDATA_KEY,
        prep_id,
        old_key_id,
        &fhe_key_set,
        domain,
        vec![],
    )
    .unwrap();

    let old_fhe_keys = ThresholdFheKeys::new(
        fhe_keys_skeleton.private_keys.clone(),
        fhe_keys_skeleton.public_material.clone(),
        info,
    );

    // Private storage: ThresholdFheKeys at (old_key_id, epoch_id).
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            old_key_id,
            epoch_id,
            &old_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }
    // Public storage: PublicKey + ServerKey at old_key_id.
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            old_key_id,
            &fhe_key_set.public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            old_key_id,
            &fhe_key_set.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
    }

    (old_fhe_keys, compact_pk)
}

#[tokio::test]
async fn test_copy_compressed_key_to_original_success() {
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let old_key_id = derive_request_id("copy_compressed_old_key").unwrap();
    let new_key_id = derive_request_id("copy_compressed_new_key").unwrap();
    let prep_id = derive_request_id("copy_compressed_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_compressed_epoch").unwrap().into();

    let mut rng = AesRng::seed_from_u64(200);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;

    // Generate compressed keyset and store at new_key_id.
    let (compressed_keyset, new_fhe_keys) = generate_compressed_keyset_and_fhe_keys(
        &new_key_id,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
    );
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        // Production path writes the compact PK alongside the compressed keyset
        // at new_key_id (see write_threshold_keys_with_dkg_meta_store_compressed);
        // mirror that here so the new digest map matches what's actually on disk.
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compact_pk,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id,
            &epoch_id,
            &new_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "copy should succeed: {result:?}");

    // CompressedXofKeySet should now exist at old_key_id.
    {
        let pub_storage = crypto_storage.inner.public_storage.lock().await;
        let exists = pub_storage
            .data_exists(&old_key_id, &PubDataType::CompressedXofKeySet.to_string())
            .await
            .unwrap();
        assert!(exists, "CompressedXofKeySet should exist at old_key_id");
    }

    // Stale ServerKey left over from the original uncompressed keyset must be
    // removed. PublicKey is in both the old and new digest maps (the migrate
    // keygen preserves the old compact PK at new_key_id), so it must stay —
    // and its bytes must match the ones at new_key_id so external clients see
    // the same compact PK at either ID.
    {
        let pub_storage = crypto_storage.inner.public_storage.lock().await;
        let server_exists = pub_storage
            .data_exists(&old_key_id, &PubDataType::ServerKey.to_string())
            .await
            .unwrap();
        assert!(
            !server_exists,
            "stale ServerKey should be deleted from old_key_id after migration"
        );
        let pk_exists_old = pub_storage
            .data_exists(&old_key_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        assert!(
            pk_exists_old,
            "PublicKey should be preserved at old_key_id after migration"
        );
        let pk_exists_new = pub_storage
            .data_exists(&new_key_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        assert!(
            pk_exists_new,
            "PublicKey should also exist at new_key_id after migration"
        );
        let old_pk_bytes = pub_storage
            .load_bytes(&old_key_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        let new_pk_bytes = pub_storage
            .load_bytes(&new_key_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        assert_eq!(
            old_pk_bytes, new_pk_bytes,
            "compact PK bytes at old_key_id and new_key_id must be identical"
        );
    }

    // ThresholdFheKeys at (old_key_id, epoch_id) has Compressed public_material
    // and metadata signed under old_key_id.
    {
        let guarded = crypto_storage
            .read_guarded_threshold_fhe_keys(&old_key_id, &epoch_id)
            .await
            .unwrap();
        assert!(
            guarded.is_compressed(),
            "ThresholdFheKeys should have Compressed public_material"
        );
        match &guarded.meta_data {
            KeyGenMetadata::Current(inner) => {
                assert_eq!(
                    inner.key_id, old_key_id,
                    "metadata key_id should be old_key_id"
                );
                assert!(
                    inner
                        .key_digest_map
                        .contains_key(&PubDataType::CompressedXofKeySet),
                    "metadata should contain CompressedXofKeySet digest"
                );
                assert!(
                    inner.key_digest_map.contains_key(&PubDataType::PublicKey),
                    "metadata should contain PublicKey digest"
                );
                assert!(
                    !inner.key_digest_map.contains_key(&PubDataType::ServerKey),
                    "new metadata should not contain ServerKey digest"
                );
            }
            _ => panic!("expected Current metadata"),
        }
    }

    // dkg_pubinfo_meta_store now holds the new metadata for old_key_id.
    {
        let guard = meta_store.read().await;
        let cell = guard
            .get_cell(&old_key_id)
            .expect("meta_store entry should exist");
        let value = cell.try_get().expect("meta_store entry should be set");
        let meta = value.expect("meta_store should hold Ok(metadata)");
        match meta {
            KeyGenMetadata::Current(inner) => {
                assert_eq!(inner.key_id, old_key_id);
                assert!(
                    inner
                        .key_digest_map
                        .contains_key(&PubDataType::CompressedXofKeySet)
                );
            }
            _ => panic!("expected Current metadata in meta_store"),
        }
    }
}

#[tokio::test]
async fn test_copy_compressed_key_overwrite() {
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let old_key_id = derive_request_id("copy_overwrite_old").unwrap();
    let new_key_id_1 = derive_request_id("copy_overwrite_new_1").unwrap();
    let new_key_id_2 = derive_request_id("copy_overwrite_new_2").unwrap();
    let prep_id = derive_request_id("copy_overwrite_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_overwrite_epoch").unwrap().into();

    let mut rng = AesRng::seed_from_u64(300);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    // Set up old_key_id with Uncompressed ThresholdFheKeys.
    let (_, old_fhe_keys, fhe_key_set) = setup_threshold_store(&old_key_id);
    let compact_pk = fhe_key_set.public_key.clone();
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &old_key_id,
            &epoch_id,
            &old_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    // Generate first compressed keyset and store at new_key_id_1.
    let (compressed_1, fhe_keys_1) = generate_compressed_keyset_and_fhe_keys(
        &new_key_id_1,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
    );
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id_1,
            &compressed_1,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id_1,
            &compact_pk,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id_1,
            &epoch_id,
            &fhe_keys_1,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // First copy.
    crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id_1,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await
        .unwrap();

    // Generate second compressed keyset and store at new_key_id_2.
    let (compressed_2, fhe_keys_2) = generate_compressed_keyset_and_fhe_keys(
        &new_key_id_2,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
    );
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id_2,
            &compressed_2,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id_2,
            &compact_pk,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id_2,
            &epoch_id,
            &fhe_keys_2,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    // Second copy should overwrite.
    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id_2,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await;
    assert!(result.is_ok(), "second copy should succeed: {result:?}");

    // Verify metadata key_id is still old_key_id after overwrite.
    {
        let guarded = crypto_storage
            .read_guarded_threshold_fhe_keys(&old_key_id, &epoch_id)
            .await
            .unwrap();
        assert!(guarded.is_compressed());
        match &guarded.meta_data {
            KeyGenMetadata::Current(inner) => {
                assert_eq!(inner.key_id, old_key_id);
            }
            _ => panic!("expected Current metadata"),
        }
    }
}

#[tokio::test]
async fn test_copy_compressed_key_missing_source() {
    let old_key_id = derive_request_id("copy_missing_old").unwrap();
    let new_key_id = derive_request_id("copy_missing_new").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_missing_epoch").unwrap().into();

    let mut rng = AesRng::seed_from_u64(400);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // No CompressedXofKeySet at new_key_id — should fail.
    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await;
    assert!(result.is_err(), "should fail when source key is missing");
}

#[tokio::test]
async fn test_copy_compressed_key_legacy_metadata_fails() {
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let old_key_id = derive_request_id("copy_legacy_old").unwrap();
    let new_key_id = derive_request_id("copy_legacy_new").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_legacy_epoch").unwrap().into();

    let mut rng = AesRng::seed_from_u64(500);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    // We need a pre-existing old_fhe_keys at (old_key_id, epoch_id) so Phase A
    // can read it before hitting the LegacyV0 rejection on the migrated metadata.
    let (_, old_fhe_keys, _) = setup_threshold_store(&old_key_id);
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &old_key_id,
            &epoch_id,
            &old_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    // Generate compressed keyset and create ThresholdFheKeys with LegacyV0 metadata.
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
        new_key_id.into(),
    )
    .unwrap();

    // Create ThresholdFheKeys with LegacyV0 metadata.
    let legacy_fhe_keys = ThresholdFheKeys::new(
        old_fhe_keys.private_keys.clone(),
        PublicKeyMaterial::new(compressed_keyset.clone()),
        KeyGenMetadata::LegacyV0(HashMap::new()),
    );

    // Store compressed keyset at new_key_id.
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
    }
    // Store legacy ThresholdFheKeys at (new_key_id, epoch_id).
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id,
            &epoch_id,
            &legacy_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await;
    assert!(result.is_err(), "should fail with LegacyV0 metadata");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("LegacyV0"),
        "error should mention LegacyV0, got: {err}"
    );
}

/// The migrated ThresholdFheKeys were written by the new keygen at the new
/// keygen's epoch; the target key lives at a *different* epoch. Verify the
/// migrated material lands at (old_key_id, old_epoch_id) and not at the new
/// keygen's epoch.
#[tokio::test]
async fn test_copy_compressed_key_different_epoch() {
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let old_key_id = derive_request_id("copy_diff_epoch_old").unwrap();
    let new_key_id = derive_request_id("copy_diff_epoch_new").unwrap();
    let prep_id = derive_request_id("copy_diff_epoch_prep").unwrap();
    let old_epoch_id: EpochId = derive_request_id("copy_diff_epoch_old_epoch")
        .unwrap()
        .into();
    let new_epoch_id: EpochId = derive_request_id("copy_diff_epoch_new_epoch")
        .unwrap()
        .into();
    assert_ne!(old_epoch_id, new_epoch_id);

    let mut rng = AesRng::seed_from_u64(600);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &old_epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;

    // Migrated keys are stored at (new_key_id, new_epoch_id) — NOT old_epoch_id.
    let (compressed_keyset, new_fhe_keys) = generate_compressed_keyset_and_fhe_keys(
        &new_key_id,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
    );
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compact_pk,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id,
            &new_epoch_id,
            &new_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &new_epoch_id,
            &old_key_id,
            &old_epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await
        .expect("copy should succeed across different epochs");

    // Migrated keys must be at (old_key_id, old_epoch_id)...
    {
        let priv_storage = crypto_storage.inner.private_storage.lock().await;
        let at_old = priv_storage
            .data_exists_at_epoch(
                &old_key_id,
                &old_epoch_id,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .unwrap();
        assert!(
            at_old,
            "ThresholdFheKeys should exist at (old_key_id, old_epoch_id)"
        );
        // ...and must NOT have leaked to (old_key_id, new_epoch_id).
        let at_new_epoch = priv_storage
            .data_exists_at_epoch(
                &old_key_id,
                &new_epoch_id,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .unwrap();
        assert!(
            !at_new_epoch,
            "ThresholdFheKeys must not be written at (old_key_id, new_epoch_id)"
        );
    }
}

/// If Phase A validation fails (missing CompressedXofKeySet digest in the
/// migrated metadata), Phase B must not mutate pub/priv storage at old_key_id.
#[tokio::test]
async fn test_copy_compressed_key_validation_failure_is_atomic() {
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let old_key_id = derive_request_id("copy_atomic_old").unwrap();
    let new_key_id = derive_request_id("copy_atomic_new").unwrap();
    let prep_id = derive_request_id("copy_atomic_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_atomic_epoch").unwrap().into();

    let mut rng = AesRng::seed_from_u64(700);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        None,
        HashMap::new(),
    );

    let (old_fhe_keys, _compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;
    let original_old_meta = old_fhe_keys.meta_data.clone();

    // Generate a valid compressed keyset at new_key_id, but store ThresholdFheKeys
    // with Current metadata whose key_digest_map is empty (no CompressedXofKeySet).
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
        new_key_id.into(),
    )
    .unwrap();

    // Current variant with empty digest map — triggers "missing CompressedXofKeySet digest".
    let bad_fhe_keys = ThresholdFheKeys::new(
        old_fhe_keys.private_keys.clone(),
        PublicKeyMaterial::new(compressed_keyset.clone()),
        KeyGenMetadata::new(new_key_id, prep_id, HashMap::new(), vec![]),
    );
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id,
            &epoch_id,
            &bad_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let result = crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store.clone(),
        )
        .await;
    assert!(
        result.is_err(),
        "copy should fail when migrated metadata is missing the CompressedXofKeySet digest"
    );

    // Pub storage at old_key_id must still hold the original ServerKey/PublicKey
    // and must NOT have received the new CompressedXofKeySet.
    {
        let pub_storage = crypto_storage.inner.public_storage.lock().await;
        assert!(
            pub_storage
                .data_exists(&old_key_id, &PubDataType::ServerKey.to_string())
                .await
                .unwrap(),
            "pre-migration ServerKey must survive a validation failure"
        );
        assert!(
            pub_storage
                .data_exists(&old_key_id, &PubDataType::PublicKey.to_string())
                .await
                .unwrap(),
            "pre-migration PublicKey must survive a validation failure"
        );
        assert!(
            !pub_storage
                .data_exists(&old_key_id, &PubDataType::CompressedXofKeySet.to_string())
                .await
                .unwrap(),
            "CompressedXofKeySet must not be written to old_key_id on validation failure"
        );
    }

    // Priv storage at (old_key_id, epoch_id) must still hold the original
    // ThresholdFheKeys (uncompressed) — unchanged.
    {
        let guarded = crypto_storage
            .read_guarded_threshold_fhe_keys(&old_key_id, &epoch_id)
            .await
            .unwrap();
        assert!(
            !guarded.is_compressed(),
            "original uncompressed ThresholdFheKeys must survive a validation failure"
        );
        // Compare by metadata signature (cheap proxy for "unchanged").
        assert_eq!(
            guarded.meta_data.external_signature(),
            original_old_meta.external_signature(),
        );
    }

    // meta_store must be untouched on validation failure (no entry for old_key_id).
    {
        let guard = meta_store.read().await;
        assert!(
            guard.get_cell(&old_key_id).is_none(),
            "meta_store must not be mutated on validation failure"
        );
    }
}

/// Confirm that the backup vault, when configured, is updated alongside the
/// primary pub/priv storage so a restore brings back the migrated material.
#[tokio::test]
async fn test_copy_compressed_key_updates_backup_vault() {
    use crate::vault::Vault;
    use crate::vault::storage::store_versioned_at_request_and_epoch_id;

    let old_key_id = derive_request_id("copy_backup_old").unwrap();
    let new_key_id = derive_request_id("copy_backup_new").unwrap();
    let prep_id = derive_request_id("copy_backup_prep").unwrap();
    let epoch_id: EpochId = derive_request_id("copy_backup_epoch").unwrap().into();

    let mut rng = AesRng::seed_from_u64(800);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();

    // Construct a Vault backed by RamStorage (no keychain — unencrypted backup).
    let backup_vault = Vault {
        storage: crate::vault::storage::StorageProxy::Ram(RamStorage::new()),
        keychain: None,
    };

    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        Some(backup_vault),
        HashMap::new(),
    );

    let (old_fhe_keys, compact_pk) = setup_pre_migration_uncompressed(
        &crypto_storage,
        &old_key_id,
        &epoch_id,
        &sk,
        &prep_id,
        &domain,
    )
    .await;

    let (compressed_keyset, new_fhe_keys) = generate_compressed_keyset_and_fhe_keys(
        &new_key_id,
        &prep_id,
        old_fhe_keys.private_keys.clone(),
        &compact_pk,
        &sk,
        &domain,
    );
    {
        let mut pub_storage = crypto_storage.inner.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *pub_storage,
            &new_key_id,
            &compact_pk,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }
    {
        let mut priv_storage = crypto_storage.inner.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            &new_key_id,
            &epoch_id,
            &new_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    crypto_storage
        .copy_compressed_key_to_original(
            &new_key_id,
            &epoch_id,
            &old_key_id,
            &epoch_id,
            &sk,
            &domain,
            meta_store,
        )
        .await
        .expect("copy should succeed with backup vault configured");

    // Backup vault must now hold the migrated ThresholdFheKeys at
    // (old_key_id, epoch_id).
    let backup_vault = crypto_storage
        .inner
        .backup_vault
        .as_ref()
        .expect("backup vault should be configured");
    let vault_guard = backup_vault.lock().await;
    let backed_up: ThresholdFheKeys =
        crate::vault::storage::read_versioned_at_request_and_epoch_id(
            &*vault_guard,
            &old_key_id,
            &epoch_id,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .expect("migrated ThresholdFheKeys should exist in backup vault");
    assert!(
        backed_up.is_compressed(),
        "backup vault must hold the migrated (compressed) keys, not the pre-migration uncompressed ones"
    );
    match backed_up.meta_data {
        KeyGenMetadata::Current(inner) => {
            assert_eq!(inner.key_id, old_key_id);
            assert!(
                inner
                    .key_digest_map
                    .contains_key(&PubDataType::CompressedXofKeySet)
            );
        }
        _ => panic!("expected Current metadata in backup vault"),
    }
}
