use crate::{cryptography::internal_crypto_types::gen_sig_keys, engine::base::derive_request_id};
use aes_prng::AesRng;
use kms_grpc::rpc_types::WrappedPublicKey;
use rand::SeedableRng;
use std::collections::HashMap;
use std::sync::Arc;
use tfhe::{shortint::ClassicPBSParameters, CompactPublicKey, ConfigBuilder, ServerKey};
use threshold_fhe::execution::{
    endpoints::keygen::FhePubKeySet,
    tfhe_internals::{
        parameters::DKGParams,
        test_feature::{gen_key_set, keygen_all_party_shares},
    },
};
use tokio::sync::{Mutex, RwLock};

use crate::{
    consts::TEST_PARAM,
    engine::{
        base::KmsFheKeyHandles, centralized::central_kms::async_generate_crs,
        threshold::service::ThresholdFheKeys,
    },
    util::meta_store::MetaStore,
    vault::storage::{
        crypto_material::{
            CentralizedCryptoMaterialStorage, CryptoMaterialStorage, ThresholdCryptoMaterialStorage,
        },
        ram::{FailingRamStorage, RamStorage},
        store_pk_at_request_id, StorageType,
    },
};

#[tokio::test]
#[tracing_test::traced_test]
async fn write_crs() {
    // write the CRS, first try with storage that are functional
    // then try to write into a failing storage and expect an error
    let pub_storage = Arc::new(Mutex::new(FailingRamStorage::new(StorageType::PUB, 100)));
    let crypto_storage = CryptoMaterialStorage {
        public_storage: pub_storage.clone(),
        private_storage: Arc::new(Mutex::new(RamStorage::new(StorageType::PRIV))),
        backup_storage: None as Option<Arc<Mutex<RamStorage>>>,
        pk_cache: Arc::new(RwLock::new(HashMap::new())),
    };

    let mut rng = AesRng::seed_from_u64(100);
    let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
    let (pp, crs_info) = async_generate_crs(&sig_sk, rng, TEST_PARAM, Some(1), None)
        .await
        .unwrap();
    let req_id = derive_request_id("write_crs").unwrap();

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // writing to an empty meta store should fail
    crypto_storage
        .write_crs_with_meta_store(&req_id, pp.clone(), crs_info.clone(), meta_store.clone())
        .await;

    // update the meta store and we should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    crypto_storage
        .write_crs_with_meta_store(&req_id, pp.clone(), crs_info.clone(), meta_store.clone())
        .await;
    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    crypto_storage
        .write_crs_with_meta_store(&req_id, pp.clone(), crs_info.clone(), meta_store.clone())
        .await;

    // writing on a failed storage device should fail
    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }
    let new_req_id = derive_request_id("write_crs_2").unwrap();
    crypto_storage
        .write_crs_with_meta_store(&new_req_id, pp, crs_info, meta_store.clone())
        .await;
    assert!(logs_contain("storage failed!"));
    assert!(logs_contain("Deleted all crs material for request"));

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
        assert!(!guard.exists(&new_req_id));
    }
}

#[tokio::test]
async fn read_public_key() {
    // it doens't matter if we use centralized or threshold
    // the public key reading logic is the same
    let crypto_storage = CentralizedCryptoMaterialStorage::new(
        FailingRamStorage::new(StorageType::PUB, 100),
        RamStorage::new(StorageType::PUB),
        None as Option<RamStorage>,
        HashMap::new(),
        HashMap::new(),
    );

    let pub_storage = crypto_storage.inner.public_storage.clone();
    let pk_cache = crypto_storage.inner.pk_cache.clone();

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
        store_pk_at_request_id(&mut (*s), &req_id, WrappedPublicKey::Compact(&public_key))
            .await
            .unwrap();
    }

    // reading the public key without cache should succeed
    let _pk = crypto_storage.inner.read_cloned_pk(&req_id).await.unwrap();

    // check that there's an item in the cache
    let guard = pk_cache.read().await;
    assert!(guard.contains_key(&req_id));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn write_central_keys() {
    let param = TEST_PARAM;
    let crypto_storage = CentralizedCryptoMaterialStorage::new(
        FailingRamStorage::new(StorageType::PUB, 100),
        RamStorage::new(StorageType::PUB),
        None as Option<RamStorage>,
        HashMap::new(),
        HashMap::new(),
    );
    let pub_storage = crypto_storage.inner.public_storage.clone();

    let req_id = derive_request_id("write_central_keys").unwrap();

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
        public_key_info: HashMap::new(),
    };
    let fhe_key_set = FhePubKeySet {
        public_key,
        server_key,
    };

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // write to an empty meta store should fail
    crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    assert!(!logs_contain("storage failed!"));
    assert!(logs_contain("Deleted all key material for request"));

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;

    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    crypto_storage
        .write_centralized_keys_with_meta_store(
            &req_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
        )
        .await;
    // Check that the approach fails with the expected error message
    assert!(logs_contain("while updating PK meta store for"));

    // write on a failed storage device should fail
    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }
    let new_req_id = derive_request_id("write_central_keys_2").unwrap();
    crypto_storage
        .write_centralized_keys_with_meta_store(
            &new_req_id,
            key_info,
            fhe_key_set,
            meta_store.clone(),
        )
        .await;
    assert!(logs_contain("storage failed!"));
    assert!(logs_contain("Deleted all key material for request"));

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
        assert!(!guard.exists(&new_req_id));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn write_threshold_empty_update() {
    let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store();
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let req_id = derive_request_id("write_threshold_empty_update").unwrap();

    // Check no errors happened
    assert!(!logs_contain(&format!(
        "while updating KeyGen meta store for {}",
        req_id
    )));
    assert!(!logs_contain(&format!(
        "PK already exists in pk_cache for {}",
        req_id
    )));
    assert!(!logs_contain(&format!(
        "Failed to ensure existance of threshold key material for {}.",
        req_id
    )));
    // write to an empty meta store should fail
    crypto_storage
        .write_threshold_keys_with_meta_store(
            &req_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            HashMap::new(),
            meta_store.clone(),
        )
        .await;
    // Check that the expected error happened
    assert!(logs_contain("while updating KeyGen meta store for"));

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    crypto_storage
        .write_threshold_keys_with_meta_store(
            &req_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            HashMap::new(),
            meta_store.clone(),
        )
        .await;

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn write_threshold_keys_meta_update() {
    let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store();
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let req_id = derive_request_id("write_threshold_keys_meta_update").unwrap();

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    crypto_storage
        .write_threshold_keys_with_meta_store(
            &req_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            HashMap::new(),
            meta_store.clone(),
        )
        .await;
    // Check that no errors were logged
    assert!(!logs_contain(&format!(
        "while updating KeyGen meta store for {}",
        req_id
    )));
    assert!(!logs_contain(&format!(
        "PK already exists in pk_cache for {}",
        req_id
    )));
    assert!(logs_contain(&format!(
        "Finished DKG for Request Id {}.",
        req_id
    )));

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
    }

    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    crypto_storage
        .write_threshold_keys_with_meta_store(
            &req_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            HashMap::new(),
            meta_store.clone(),
        )
        .await;
    assert!(logs_contain("while updating KeyGen meta store for"));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn write_threshold_keys_failed_storage() {
    let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store();
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let pub_storage = crypto_storage.inner.public_storage.clone();
    let req_id = derive_request_id("write_threshold_keys_failed_storage").unwrap();

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    crypto_storage
        .write_threshold_keys_with_meta_store(
            &req_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            HashMap::new(),
            meta_store.clone(),
        )
        .await;
    // Check that no errors were logged
    assert!(!logs_contain(&format!(
        "while updating KeyGen meta store for {}",
        req_id
    )));
    assert!(!logs_contain(&format!(
        "PK already exists in pk_cache for {}",
        req_id
    )));
    assert!(logs_contain(&format!(
        "Finished DKG for Request Id {}.",
        req_id
    )));

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
    crypto_storage
        .write_threshold_keys_with_meta_store(
            &new_req_id,
            threshold_fhe_keys.clone(),
            fhe_key_set.clone(),
            HashMap::new(),
            meta_store.clone(),
        )
        .await;
    // Check that no errors were logged
    assert!(!logs_contain(
        "while updating KeyGen meta store for {new_req_id}"
    ));

    // check the meta store is correct
    {
        let guard = meta_store.read().await;
        assert!(guard.exists(&req_id));
        assert!(!guard.exists(&new_req_id));
    }
}

fn setup_threshold_store() -> (
    ThresholdCryptoMaterialStorage<FailingRamStorage, RamStorage, RamStorage>,
    ThresholdFheKeys,
    FhePubKeySet,
) {
    let crypto_storage = ThresholdCryptoMaterialStorage::new(
        FailingRamStorage::new(StorageType::PUB, 100),
        RamStorage::new(StorageType::PUB),
        None as Option<RamStorage>,
        HashMap::new(),
        HashMap::new(),
    );

    let pbs_params: ClassicPBSParameters = TEST_PARAM
        .get_params_basics_handle()
        .to_classic_pbs_parameters();

    let mut rng = AesRng::seed_from_u64(100);
    let key_set = gen_key_set(TEST_PARAM, &mut rng);
    let key_shares = keygen_all_party_shares(
        key_set.get_raw_lwe_client_key(),
        key_set.get_raw_glwe_client_key(),
        key_set.get_raw_glwe_client_sns_key_as_lwe().unwrap(),
        pbs_params,
        &mut rng,
        4,
        1,
    )
    .unwrap();

    let fhe_key_set = key_set.public_keys.clone();

    let (integer_server_key, _, _, _, sns_key, _) =
        key_set.public_keys.server_key.clone().into_raw_parts();

    let threshold_fhe_keys = ThresholdFheKeys {
        private_keys: key_shares[0].to_owned(),
        integer_server_key,
        sns_key,
        decompression_key: None,
        pk_meta_data: HashMap::new(),
    };
    (crypto_storage, threshold_fhe_keys, fhe_key_set)
}
