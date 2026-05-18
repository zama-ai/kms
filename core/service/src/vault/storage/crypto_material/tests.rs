use crate::{
    backup::{
        custodian::{CustodianSetupMessagePayload, HEADER, InternalCustodianContext},
        operator::{InnerOperatorBackupOutput, RecoveryValidationMaterial},
    },
    consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, SAFE_SER_SIZE_LIMIT},
    cryptography::{
        encryption::{Encryption, PkeScheme, PkeSchemeType},
        signatures::{PrivateSigKey, SigningSchemeType, gen_sig_keys},
        signcryption::UnifiedSigncryption,
    },
    dummy_domain,
    engine::base::{CrsGenMetadata, KeyGenMetadata, derive_request_id},
    util::meta_store::{
        add_req_to_meta_store, ensure_meta_store_request_pending, retrieve_from_meta_store,
    },
    vault::{
        Vault,
        storage::{Storage, StorageProxy, crypto_material::PublicKeySet},
    },
};
use aes_prng::AesRng;
use kms_grpc::{
    EpochId, RequestId,
    kms::v1::{CustodianContext, CustodianSetupMessage},
    rpc_types::{PrivDataType, PubDataType},
};
use observability::metrics_names::OP_CRS_GEN_REQUEST;
use rand::SeedableRng;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tfhe::{
    CompactPublicKey, ConfigBuilder, Seed, ServerKey, safe_serialization::safe_serialize,
    shortint::ClassicPBSParameters, xof_key_set::CompressedXofKeySet,
};
use threshold_execution::keyset_config::KeyGenSecretKeyConfig;
use threshold_execution::tfhe_internals::{
    parameters::DKGParams,
    public_keysets::FhePubKeySet,
    test_feature::{gen_uncompressed_key_set, keygen_all_party_shares_from_keyset},
};
use threshold_types::role::Role;
use tokio::sync::{Mutex, RwLock};

use super::base::{StorageError, update_meta_store};
use crate::{
    consts::TEST_PARAM,
    engine::{
        base::KmsFheKeyHandles,
        centralized::central_kms::{async_generate_crs, generate_fhe_keys},
        threshold::service::{PublicKeyMaterial, ThresholdFheKeys},
    },
    util::meta_store::{MetaStore, update_ok_req_in_meta_store},
    vault::storage::{
        StorageReader, StorageReaderExt,
        crypto_material::{
            CentralizedCryptoMaterialStorage, CryptoMaterialStorage,
            ThresholdCryptoMaterialStorage, check_data_exists, check_data_exists_at_epoch,
        },
        delete_at_request_id,
        ram::{FailingRamStorage, RamStorage},
        read_versioned_at_request_and_epoch_id, read_versioned_at_request_id,
        store_versioned_at_request_and_epoch_id, store_versioned_at_request_id,
        tests::TestType,
    },
};

/// Read the public key from `pub_storage` directly, used by the read-path tests.
async fn read_cloned_pk<S>(
    pub_storage: Arc<Mutex<S>>,
    req_id: &RequestId,
) -> anyhow::Result<CompactPublicKey>
where
    S: Storage + Send + Sync + 'static,
{
    let pub_storage = pub_storage.lock().await;
    super::CryptoMaterialReader::read_from_storage(&*pub_storage, req_id).await
}

fn dummy_info() -> KeyGenMetadata {
    let req_id = derive_request_id("dummy_info").unwrap();
    KeyGenMetadata::new(req_id, req_id, HashMap::new(), vec![], vec![])
}

fn ram_threshold_storage(
    backup_vault: Option<crate::vault::Vault>,
) -> ThresholdCryptoMaterialStorage<RamStorage, RamStorage> {
    ThresholdCryptoMaterialStorage::new(
        RamStorage::new(),
        RamStorage::new(),
        backup_vault,
        HashMap::new(),
    )
}

fn generate_compressed_keys(
    req_id: &RequestId,
    prep_id: &RequestId,
    signing_seed: u64,
) -> (
    PrivateSigKey,
    alloy_sol_types::Eip712Domain,
    CompressedXofKeySet,
    CompactPublicKey,
    KmsFheKeyHandles,
) {
    let mut rng = AesRng::seed_from_u64(signing_seed);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let domain = dummy_domain();
    let (compressed_keyset, compact_pk, key_info) = generate_fhe_keys(
        &sk,
        TEST_PARAM,
        KeyGenSecretKeyConfig::GenerateAll,
        req_id,
        prep_id,
        Some(Seed(42)),
        &domain,
        vec![],
    )
    .unwrap();

    (sk, domain, compressed_keyset, compact_pk, key_info)
}

const TEST_METRIC: &str = "test";

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
        .write_crs(
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
        .write_crs(
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
        .write_crs(
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
        .write_crs(
            &new_req_id,
            &default_epoch_id,
            pp,
            crs_info,
            meta_store.clone(),
            OP_CRS_GEN_REQUEST,
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Writing error"),
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
    let _pk = read_cloned_pk(pub_storage.clone(), &req_id).await.unwrap();
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
    let fhe_key_set = PublicKeySet::Uncompressed(Arc::new(FhePubKeySet {
        public_key,
        server_key,
    }));

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // write to an empty meta store should fail
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
            "",
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating meta store for") && err.contains("request is missing"),
        "expected meta-store update failure when empty, got: {err}"
    );

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
            "",
        )
        .await;
    assert!(result.is_ok(), "expected success: {result:?}");

    // writing the same thing should fail because the
    // meta store disallow updating a cell that is set
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            key_info.clone(),
            fhe_key_set.clone(),
            meta_store.clone(),
            "",
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Error while updating meta store for")
            && err.contains("request is already completed"),
        "expected meta-store conflict on double write, got: {err}"
    );

    // write on a failed storage device should fail
    {
        let mut storage_guard = pub_storage.lock().await;
        storage_guard.set_available_writes(0);
    }
    let new_req_id = derive_request_id("write_central_keys_2").unwrap();
    {
        let mut guard = meta_store.write().await;
        guard.insert(&new_req_id).unwrap();
    }
    let result = crypto_storage
        .write_fhe_keys(
            &new_req_id,
            &epoch_id,
            key_info,
            fhe_key_set,
            meta_store.clone(),
            "",
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Writing error"),
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
    let public_key_set = PublicKeySet::Uncompressed(Arc::new(FhePubKeySet {
        public_key,
        server_key,
    }));

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
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            key_info,
            public_key_set,
            meta_store.clone(),
            "",
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
    let boxed_public_key_set = PublicKeySet::Uncompressed(Arc::new(fhe_key_set.clone()));

    // write to an empty meta store should fail
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            boxed_public_key_set.clone(),
            meta_store.clone(),
            "",
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
        .read_guarded_fhe_keys(&req_id, &epoch_id)
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
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            boxed_public_key_set.clone(),
            meta_store.clone(),
            "",
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
    let boxed_public_key_set = PublicKeySet::Uncompressed(Arc::new(fhe_key_set));
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            boxed_public_key_set.clone(),
            meta_store.clone(),
            "",
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
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            boxed_public_key_set.clone(),
            meta_store.clone(),
            "",
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
        .read_guarded_fhe_keys(&req_id, &epoch_id)
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
    let boxed_public_key_set = PublicKeySet::Uncompressed(Arc::new(fhe_key_set));
    // update the meta store and the write should be ok
    {
        let meta_store = meta_store.clone();
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            boxed_public_key_set.clone(),
            meta_store.clone(),
            "",
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
        .write_fhe_keys(
            &new_req_id,
            &epoch_id,
            threshold_fhe_keys.clone(),
            boxed_public_key_set,
            meta_store.clone(),
            "",
        )
        .await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Writing error"),
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
        .read_guarded_fhe_keys(&req_id, &epoch_id)
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
    let (_, _, compressed_keyset, compact_pk, _) = generate_compressed_keys(&req_id, &req_id, 42);
    threshold_fhe_keys.public_material = PublicKeyMaterial::new(compressed_keyset.clone());

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    let result = crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            threshold_fhe_keys,
            PublicKeySet::Compressed {
                compact_public_key: Arc::new(compact_pk),
                compressed_keyset: Arc::new(compressed_keyset),
            },
            meta_store,
            "",
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
        .read_guarded_fhe_keys(&req_id, &epoch_id)
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
    let (_, _, compressed_keyset, compact_pk, key_info) =
        generate_compressed_keys(&req_id, &req_id, 50);

    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    {
        let mut guard = meta_store.write().await;
        guard.insert(&req_id).unwrap();
    }

    crypto_storage
        .write_fhe_keys(
            &req_id,
            &epoch_id,
            key_info,
            PublicKeySet::Compressed {
                compact_public_key: Arc::new(compact_pk),
                compressed_keyset: Arc::new(compressed_keyset),
            },
            meta_store,
            "",
        )
        .await
        .unwrap();

    assert!(
        crypto_storage
            .fhe_keys_exists(&req_id, &epoch_id)
            .await
            .expect("sanity check: existence query should not fail"),
        "complete compressed layout should be considered present"
    );

    {
        let mut guard = crypto_storage.inner.public_storage.lock().await;
        delete_at_request_id(&mut *guard, &req_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
    }

    assert!(
        !crypto_storage
            .fhe_keys_exists(&req_id, &epoch_id)
            .await
            .expect("storage should still be queryable after deleting PublicKey"),
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

fn make_unencrypted_backup_vault() -> Vault {
    Vault {
        storage: StorageProxy::Ram(RamStorage::new()),
        keychain: None,
    }
}

fn dummy_crs_metadata(seed: u8) -> CrsGenMetadata {
    let crs_id = derive_request_id(&format!("crs_meta_{seed}")).unwrap();
    CrsGenMetadata::new(
        crs_id,
        vec![seed; 32],
        128,
        vec![seed; 8],
        format!("extra-{seed}").into_bytes(),
    )
}

/// Build a `RecoveryValidationMaterial` suitable for `write_backup_keys` tests.
/// Mirrors the dummy fixture in `engine/backup_operator.rs` tests.
fn dummy_recovery_material(caller_name: &str) -> RecoveryValidationMaterial {
    let mut rng = AesRng::seed_from_u64(0);
    let (verf_key, sig_key) = gen_sig_keys(&mut rng);
    let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
    let (_dec_key, enc_key) = enc.keygen().unwrap();
    let backup_id = derive_request_id(caller_name).unwrap();

    let mut commitments = BTreeMap::new();
    commitments.insert(Role::indexed_from_one(1), vec![1_u8; 32]);
    commitments.insert(Role::indexed_from_one(2), vec![2_u8; 32]);
    commitments.insert(Role::indexed_from_one(3), vec![3_u8; 32]);

    let payload = CustodianSetupMessagePayload {
        header: HEADER.to_string(),
        random_value: [4_u8; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        public_enc_key: enc_key.clone(),
        verification_key: verf_key,
    };
    let mut payload_serial = Vec::new();
    safe_serialize(&payload, &mut payload_serial, SAFE_SER_SIZE_LIMIT).unwrap();
    let custodian_nodes: Vec<_> = (1..=3)
        .map(|i| CustodianSetupMessage {
            custodian_role: i,
            name: format!("Custodian-{i}"),
            payload: payload_serial.clone(),
        })
        .collect();
    let custodian_context = CustodianContext {
        custodian_nodes,
        custodian_context_id: Some(backup_id.into()),
        threshold: 1,
    };
    let internal_custodian_context =
        InternalCustodianContext::new(custodian_context, enc_key).unwrap();

    let cts_out = InnerOperatorBackupOutput {
        signcryption: UnifiedSigncryption {
            payload: vec![1, 2, 3],
            pke_type: PkeSchemeType::MlKem512,
            signing_type: SigningSchemeType::Ecdsa256k1,
        },
    };
    let mut cts = BTreeMap::new();
    cts.insert(Role::indexed_from_one(1), cts_out.clone());
    cts.insert(Role::indexed_from_one(2), cts_out.clone());
    cts.insert(Role::indexed_from_one(3), cts_out);

    RecoveryValidationMaterial::new(
        cts,
        commitments,
        internal_custodian_context,
        &sig_key,
        *DEFAULT_MPC_CONTEXT,
    )
    .unwrap()
}

fn fresh_ram_storage() -> CryptoMaterialStorage<RamStorage, RamStorage> {
    CryptoMaterialStorage::from(RamStorage::new(), RamStorage::new(), None)
}

#[tokio::test]
async fn data_exists_paths() {
    let storage = fresh_ram_storage();
    let req_id = derive_request_id("data_exists_paths").unwrap();
    let priv_only = derive_request_id("data_exists_priv_only").unwrap();
    let epoch_id: EpochId = derive_request_id("data_exists_paths_epoch").unwrap().into();
    let pub_t = PubDataType::PublicKey;
    let priv_t_non_epoched = PrivDataType::SigningKey;
    let priv_t_epoched = PrivDataType::FhePrivateKey;
    let data = TestType { i: 1 };

    let mut pub_s = storage.public_storage.lock().await;
    let mut priv_s = storage.private_storage.lock().await;

    // Empty stores: both predicates must report `false`.
    assert!(
        !check_data_exists(&*pub_s, &*priv_s, &req_id, &pub_t, &priv_t_non_epoched)
            .await
            .unwrap()
    );
    assert!(
        !check_data_exists_at_epoch(
            &*pub_s,
            &*priv_s,
            &req_id,
            &epoch_id,
            &pub_t,
            &priv_t_epoched,
        )
        .await
        .unwrap()
    );

    // Only public stored: still `false` (private missing).
    store_versioned_at_request_id(&mut *pub_s, &req_id, &data, &pub_t.to_string())
        .await
        .unwrap();
    assert!(
        !check_data_exists(&*pub_s, &*priv_s, &req_id, &pub_t, &priv_t_non_epoched)
            .await
            .unwrap()
    );
    assert!(
        !check_data_exists_at_epoch(
            &*pub_s,
            &*priv_s,
            &req_id,
            &epoch_id,
            &pub_t,
            &priv_t_epoched,
        )
        .await
        .unwrap()
    );

    // Private stored only at a different req_id: short-circuit on missing public yields `false`.
    store_versioned_at_request_id(
        &mut *priv_s,
        &priv_only,
        &data,
        &priv_t_non_epoched.to_string(),
    )
    .await
    .unwrap();
    assert!(
        !check_data_exists(&*pub_s, &*priv_s, &priv_only, &pub_t, &priv_t_non_epoched)
            .await
            .unwrap()
    );

    // Add the matching epoched private entry: check_data_exists_at_epoch now succeeds...
    store_versioned_at_request_and_epoch_id(
        &mut *priv_s,
        &req_id,
        &epoch_id,
        &data,
        &priv_t_epoched.to_string(),
    )
    .await
    .unwrap();
    // ...and add the non-epoched private entry under the same req_id so check_data_exists succeeds too.
    store_versioned_at_request_id(
        &mut *priv_s,
        &req_id,
        &data,
        &priv_t_non_epoched.to_string(),
    )
    .await
    .unwrap();
    assert!(
        check_data_exists(&*pub_s, &*priv_s, &req_id, &pub_t, &priv_t_non_epoched)
            .await
            .unwrap()
    );
    assert!(
        check_data_exists_at_epoch(
            &*pub_s,
            &*priv_s,
            &req_id,
            &epoch_id,
            &pub_t,
            &priv_t_epoched,
        )
        .await
        .unwrap()
    );
}

#[tokio::test]
async fn write_pub_data_and_priv_data_paths() {
    // Sunshine + failure for write_pub_data, plus the three branches of write_priv_data
    // (non-epoched, epoched, and the epoched-type-without-epoch_id rejection).
    let storage = fresh_ram_storage();
    let req_id = derive_request_id("write_data_paths").unwrap();
    let epoch_id: EpochId = derive_request_id("write_data_paths_epoch").unwrap().into();
    let pub_data = TestType { i: 7 };
    let priv_non_epoched = TestType { i: 13 };
    let priv_epoched = TestType { i: 21 };
    let priv_orphan = TestType { i: 0 };

    // Sunshine: write_pub_data persists the value.
    assert!(
        storage
            .write_pub_data(&req_id, &pub_data, &PubDataType::PublicKey)
            .await
    );
    // Sunshine: write_priv_data with a non-epoched type.
    assert!(
        storage
            .write_priv_data(&req_id, None, &priv_non_epoched, &PrivDataType::SigningKey)
            .await
    );
    // Sunshine: write_priv_data with an epoched type + epoch_id.
    assert!(
        storage
            .write_priv_data(
                &req_id,
                Some(&epoch_id),
                &priv_epoched,
                &PrivDataType::FhePrivateKey,
            )
            .await
    );
    // Negative: epoched type without epoch_id must return false and store nothing.
    assert!(
        !storage
            .write_priv_data(&req_id, None, &priv_orphan, &PrivDataType::FhePrivateKey)
            .await
    );

    let pub_s = storage.public_storage.lock().await;
    let priv_s = storage.private_storage.lock().await;

    // Verify the three sunshine writes round-trip.
    let read: TestType =
        read_versioned_at_request_id(&*pub_s, &req_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
    assert_eq!(read, pub_data);

    let non_epoched: TestType =
        read_versioned_at_request_id(&*priv_s, &req_id, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    assert_eq!(non_epoched, priv_non_epoched);
    let epoched: TestType = read_versioned_at_request_and_epoch_id(
        &*priv_s,
        &req_id,
        &epoch_id,
        &PrivDataType::FhePrivateKey.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(epoched, priv_epoched);

    // The orphan write (epoched type without epoch_id) must not have created a stray
    // non-epoched entry under FhePrivateKey.
    assert!(
        priv_s
            .all_data_ids(&PrivDataType::FhePrivateKey.to_string())
            .await
            .unwrap()
            .is_empty()
    );

    // Failure path needs its own storage, since FailingRamStorage is the public side.
    let failing = CryptoMaterialStorage::from(FailingRamStorage::new(0), RamStorage::new(), None);
    assert!(
        !failing
            .write_pub_data(&req_id, &pub_data, &PubDataType::PublicKey)
            .await
    );
}

#[tokio::test]
async fn purge_material_paths() {
    // Sunshine deletion of pub + epoched/non-epoched priv, plus the three boundary cases:
    // empty lists (no-op), missing entries (still success), and epoched-type-without-epoch_id (failure).
    let storage = fresh_ram_storage();
    let req_id = derive_request_id("purge_paths").unwrap();
    let epoch_id: EpochId = derive_request_id("purge_paths_epoch").unwrap().into();
    let data = TestType { i: 5 };

    {
        let mut pub_s = storage.public_storage.lock().await;
        let mut priv_s = storage.private_storage.lock().await;

        store_versioned_at_request_id(
            &mut *pub_s,
            &req_id,
            &data,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_and_epoch_id(
            &mut *priv_s,
            &req_id,
            &epoch_id,
            &data,
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            &mut *priv_s,
            &req_id,
            &data,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
    }
    // Empty input lists: trivially succeeds without touching storage.
    assert!(storage.purge_material(&req_id, None, &[], &[]).await);

    // Sunshine: delete pub + both private layouts.
    assert!(
        storage
            .purge_material(
                &req_id,
                Some(&epoch_id),
                &[PubDataType::PublicKey],
                &[PrivDataType::FhePrivateKey, PrivDataType::SigningKey],
            )
            .await,
        "purge_material should report success when entries existed"
    );

    {
        let pub_s = storage.public_storage.lock().await;
        let priv_s = storage.private_storage.lock().await;
        assert!(
            !pub_s
                .data_exists(&req_id, &PubDataType::PublicKey.to_string())
                .await
                .unwrap()
        );

        assert!(
            !priv_s
                .data_exists_at_epoch(&req_id, &epoch_id, &PrivDataType::FhePrivateKey.to_string())
                .await
                .unwrap()
        );
        assert!(
            !priv_s
                .data_exists(&req_id, &PrivDataType::SigningKey.to_string())
                .await
                .unwrap()
        );
    }
    // Asking to delete already-missing entries is a non-fatal info log in `delete_at_request_id`,
    // so purge_material still reports success.
    assert!(
        storage
            .purge_material(
                &req_id,
                None,
                &[PubDataType::PublicKey],
                &[PrivDataType::SigningKey],
            )
            .await
    );

    // Negative: an epoched private type without epoch_id must return false.
    assert!(
        !storage
            .purge_material(&req_id, None, &[], &[PrivDataType::FhePrivateKey])
            .await
    );
}

#[tokio::test]
async fn write_all_no_overwrite_of_existing_data() {
    let storage = fresh_ram_storage();
    let req_id = derive_request_id("handle_all_dup").unwrap();
    let epoch_id: EpochId = derive_request_id("handle_all_dup_epoch").unwrap().into();
    let original = TestType { i: 1 };
    let attempted_overwrite = TestType { i: 2 };

    storage
        .write_all(
            &req_id,
            Some(&epoch_id),
            Some((&original, PubDataType::PublicKey)),
            Some((&original, PrivDataType::FhePrivateKey)),
            false,
            TEST_METRIC,
        )
        .await
        .unwrap();

    // Initial entries are present.
    {
        let pub_s = storage.public_storage.lock().await;
        let priv_s = storage.private_storage.lock().await;
        assert!(
            pub_s
                .data_exists(&req_id, &PubDataType::PublicKey.to_string())
                .await
                .unwrap()
        );
        assert!(
            priv_s
                .data_exists_at_epoch(&req_id, &epoch_id, &PrivDataType::FhePrivateKey.to_string())
                .await
                .unwrap()
        );
    }

    // Duplicate call must not purge the original entries.
    assert!(matches!(
        storage
            .write_all(
                &req_id,
                Some(&epoch_id),
                Some((&attempted_overwrite, PubDataType::PublicKey)),
                Some((&attempted_overwrite, PrivDataType::FhePrivateKey)),
                false,
                TEST_METRIC,
            )
            .await
            .unwrap_err(),
        StorageError::Duplicate
    ));
    // Initial entries are still there and unchanged.
    {
        let pub_s = storage.public_storage.lock().await;
        let priv_s = storage.private_storage.lock().await;
        let pub_read: TestType =
            read_versioned_at_request_id(&*pub_s, &req_id, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert_eq!(pub_read, original);

        let priv_read: TestType = read_versioned_at_request_and_epoch_id(
            &*priv_s,
            &req_id,
            &epoch_id,
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(priv_read, original);
    }
}

#[tokio::test]
async fn write_all_purges_on_write_failure() {
    // Public storage rejects every write; the private write succeeds, so write_all
    // must purge the orphan and report `WritingError`.
    let storage = CryptoMaterialStorage::from(FailingRamStorage::new(0), RamStorage::new(), None);
    let req_id = derive_request_id("handle_all_purge").unwrap();
    let data = TestType { i: 11 };

    let res = storage
        .write_all(
            &req_id,
            None,
            Some((&data, PubDataType::PublicKey)),
            Some((&data, PrivDataType::SigningKey)),
            false,
            TEST_METRIC,
        )
        .await;
    assert_eq!(res, Err(StorageError::Writing));

    let priv_g = storage.private_storage.lock().await;
    assert!(
        !priv_g
            .data_exists(&req_id, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap(),
        "successful private write must be purged when public write fails"
    );
}

#[tokio::test]
async fn write_all_updates_backup_vault() {
    let storage = CryptoMaterialStorage::from(
        RamStorage::new(),
        RamStorage::new(),
        Some(make_unencrypted_backup_vault()),
    );
    let req_id = derive_request_id("handle_all_backup").unwrap();
    let mut rng = AesRng::seed_from_u64(123);
    let (_pk, sk) = gen_sig_keys(&mut rng);

    storage
        .write_all::<TestType, PrivateSigKey>(
            &req_id,
            None,
            None,
            Some((&sk, PrivDataType::SigningKey)),
            true,
            TEST_METRIC,
        )
        .await
        .unwrap();

    let vault = storage.get_backup_vault().unwrap();
    let backup_v = vault.lock().await;
    let backup_sk: PrivateSigKey = backup_v
        .read_data(&req_id, &PrivDataType::SigningKey.to_string())
        .await
        .unwrap();
    assert_eq!(backup_sk.signing_key_id(), sk.signing_key_id());
}

#[tokio::test]
async fn handle_fhe_keys_compressed_writes_and_caches() {
    // Compressed layout: stores CompressedXofKeySet + PublicKey, no ServerKey.
    let req_id = derive_request_id("handle_fhe_keys_compressed").unwrap();
    let epoch_id: EpochId = derive_request_id("handle_fhe_keys_compressed_epoch")
        .unwrap()
        .into();
    let storage = fresh_ram_storage();

    let (_sk, _domain, compressed_keyset, compact_pk, key_info) =
        generate_compressed_keys(&req_id, &req_id, 7);
    let public_key_set = PublicKeySet::Compressed {
        compact_public_key: Arc::new(compact_pk),
        compressed_keyset: Arc::new(compressed_keyset),
    };

    let cache = Arc::new(RwLock::new(HashMap::new()));
    storage
        .handle_fhe_keys(
            &req_id,
            &epoch_id,
            key_info,
            PrivDataType::FhePrivateKey,
            public_key_set,
            cache.clone(),
            false,
            TEST_METRIC,
        )
        .await
        .unwrap();

    let cache_guard = cache.read().await;
    assert!(cache_guard.contains_key(&(req_id, epoch_id)));
    let pub_s = storage.public_storage.lock().await;
    assert!(
        pub_s
            .data_exists(&req_id, &PubDataType::CompressedXofKeySet.to_string())
            .await
            .unwrap()
    );
    assert!(
        pub_s
            .data_exists(&req_id, &PubDataType::PublicKey.to_string())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn write_backup_keys() {
    let storage = CryptoMaterialStorage::from(
        RamStorage::new(),
        RamStorage::new(),
        Some(make_unencrypted_backup_vault()),
    );
    let recovery = dummy_recovery_material("write_backup_keys");
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    // Fails when meta store entry is missing, even though vault is present.
    let err = storage
        .write_backup_keys(recovery.clone(), Arc::clone(&meta_store))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::MetaStore(_)),
        "expected MetaStoreError when meta store entry is missing, got: {err:?}"
    );

    let req_id = recovery.custodian_context().context_id;
    add_req_to_meta_store(&mut meta_store.write().await, &req_id, TEST_METRIC).unwrap();
    // Validate that writing works, when entry is present in meta store
    storage
        .write_backup_keys(recovery, Arc::clone(&meta_store))
        .await
        .unwrap();
    let pub_s = storage.public_storage.lock().await;
    assert!(
        pub_s
            .data_exists(&req_id, &PubDataType::RecoveryMaterial.to_string())
            .await
            .unwrap()
    );
    // Request is no longer pending
    assert!(
        ensure_meta_store_request_pending(&meta_store, &req_id)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn write_backup_keys_no_vault() {
    let storage = fresh_ram_storage();
    let recovery = dummy_recovery_material("write_backup_keys_no_vault");
    let req_id = recovery.custodian_context().context_id;
    let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    add_req_to_meta_store(&mut meta_store.write().await, &req_id, TEST_METRIC).unwrap();
    assert_eq!(
        storage.write_backup_keys(recovery, meta_store).await,
        Err(StorageError::Backup),
    );
}

#[tokio::test]
async fn update_meta_store_storage_outcomes() {
    // All three "happy" paths through update_meta_store, sharing one meta store with three req_ids:
    //   - storage Ok                     -> meta cell becomes Ok and call returns Ok;
    //   - storage Err(BackupError)       -> meta cell becomes Ok (we don't fail on backup errors)
    //                                       but the original storage error is forwarded;
    //   - storage Err(WritingError)      -> meta cell becomes Err and the same error is forwarded.
    let req_ok = derive_request_id("ums_ok").unwrap();
    let req_backup = derive_request_id("ums_backup").unwrap();
    let req_writing = derive_request_id("ums_writing").unwrap();
    let meta_store: Arc<RwLock<MetaStore<u32>>> = Arc::new(RwLock::new(MetaStore::new_unlimited()));

    {
        let mut write_guard = meta_store.write().await;
        add_req_to_meta_store(&mut write_guard, &req_ok, TEST_METRIC).unwrap();
        add_req_to_meta_store(&mut write_guard, &req_backup, TEST_METRIC).unwrap();
        add_req_to_meta_store(&mut write_guard, &req_writing, TEST_METRIC).unwrap();
        assert!(
            update_meta_store(Ok(()), &req_ok, 42_u32, &mut write_guard, TEST_METRIC)
                .await
                .is_ok()
        );
        assert_eq!(
            update_meta_store(
                Err(StorageError::Backup),
                &req_backup,
                7_u32,
                &mut write_guard,
                TEST_METRIC,
            )
            .await,
            Err(StorageError::Backup),
        );
        assert_eq!(
            update_meta_store(
                Err(StorageError::Writing),
                &req_writing,
                0_u32,
                &mut write_guard,
                TEST_METRIC,
            )
            .await,
            Err(StorageError::Writing),
        );
    }
    assert_eq!(
        retrieve_from_meta_store::<u32>(meta_store.read().await, &req_ok, TEST_METRIC)
            .await
            .unwrap(),
        42
    );
    assert_eq!(
        retrieve_from_meta_store::<u32>(meta_store.read().await, &req_backup, TEST_METRIC)
            .await
            .unwrap(),
        7
    );
    assert!(
        retrieve_from_meta_store::<u32>(meta_store.read().await, &req_writing, TEST_METRIC)
            .await
            .is_err(),
    );
}

#[tokio::test]
async fn update_meta_store_failure_paths() {
    // Failure paths: meta store update itself fails, in three flavours:
    //   - storage Ok + missing entry         -> MetaStoreError "but storage succeeded";
    //   - storage Err + missing entry        -> MetaStoreError "Also failed to store data";
    //   - storage Ok + already-set entry     -> MetaStoreError (cell.is_set() rejects update).
    let missing = derive_request_id("ums_missing").unwrap();
    let already_set = derive_request_id("ums_already_set").unwrap();
    let meta_store: Arc<RwLock<MetaStore<u32>>> = Arc::new(RwLock::new(MetaStore::new_unlimited()));
    add_req_to_meta_store(&mut meta_store.write().await, &already_set, TEST_METRIC).unwrap();
    assert!(update_ok_req_in_meta_store(
        &mut meta_store.write().await,
        &already_set,
        99_u32,
        TEST_METRIC,
    ));

    let mut guard = meta_store.write().await;
    match update_meta_store(Ok(()), &missing, 1_u32, &mut guard, TEST_METRIC)
        .await
        .unwrap_err()
    {
        StorageError::MetaStore(msg) => assert!(
            msg.contains("but storage succeeded"),
            "expected 'but storage succeeded' in: {msg}"
        ),
        other => panic!("expected MetaStoreError, got {other:?}"),
    }
    match update_meta_store(
        Err(StorageError::Writing),
        &missing,
        2_u32,
        &mut guard,
        TEST_METRIC,
    )
    .await
    .unwrap_err()
    {
        StorageError::MetaStore(msg) => assert!(
            msg.contains("Also failed to store data"),
            "expected combined error in: {msg}"
        ),
        other => panic!("expected MetaStoreError, got {other:?}"),
    }
    assert!(matches!(
        update_meta_store(Ok(()), &already_set, 1_u32, &mut guard, TEST_METRIC).await,
        Err(StorageError::MetaStore(_)),
    ));
}

#[tokio::test]
async fn inner_update_backup_vault_paths() {
    // No vault -> Ok no-op.
    fresh_ram_storage()
        .inner_update_backup_vault(false)
        .await
        .unwrap();

    // Vault present but private storage empty -> Ok no-op (vault stays empty).
    let storage = CryptoMaterialStorage::from(
        RamStorage::new(),
        RamStorage::new(),
        Some(make_unencrypted_backup_vault()),
    );
    assert!(storage.inner_update_backup_vault(false).await.is_ok());

    // Vault present + a SigningKey in private storage -> the entry is mirrored to the vault.
    let mut rng = AesRng::seed_from_u64(7);
    let (_pk, sk) = gen_sig_keys(&mut rng);
    let req_id = derive_request_id("inner_backup_signing").unwrap();
    {
        let mut priv_s = storage.private_storage.lock().await;
        store_versioned_at_request_id(
            &mut *priv_s,
            &req_id,
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
    }
    storage.inner_update_backup_vault(false).await.unwrap();
    let vault = storage.get_backup_vault().unwrap();
    let vault_g = vault.lock().await;
    let restored: PrivateSigKey = vault_g
        .read_data(&req_id, &PrivDataType::SigningKey.to_string())
        .await
        .unwrap();
    assert_eq!(restored, sk);
}

#[tokio::test]
async fn refresh_fhe_private_material_paths() {
    // Cover all three branches:
    //   - cache miss + data in private storage -> cache populated;
    //   - cache hit                            -> no-op (cache unchanged, private storage untouched);
    //   - cache miss + nothing in storage      -> Err with the expected message.
    let storage = fresh_ram_storage();
    let load_req = derive_request_id("refresh_fhe_load").unwrap();
    let load_epoch: EpochId = derive_request_id("refresh_fhe_load_epoch").unwrap().into();
    let hit_req = derive_request_id("refresh_fhe_hit").unwrap();
    let hit_epoch: EpochId = derive_request_id("refresh_fhe_hit_epoch").unwrap().into();
    let miss_req = derive_request_id("refresh_fhe_missing").unwrap();
    let miss_epoch: EpochId = derive_request_id("refresh_fhe_missing_epoch")
        .unwrap()
        .into();
    let load_meta = dummy_crs_metadata(1);
    let hit_meta = dummy_crs_metadata(2);

    {
        let mut priv_s = storage.private_storage.lock().await;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_s,
            &load_req,
            &load_epoch,
            &load_meta,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
    }

    let cache: Arc<RwLock<HashMap<(RequestId, EpochId), CrsGenMetadata>>> =
        Arc::new(RwLock::new(HashMap::new()));
    {
        let mut cache_guard = cache.write().await;
        cache_guard.insert((hit_req, hit_epoch), hit_meta.clone());
    }

    // Miss + data present: cache gets populated.
    storage
        .refresh_fhe_private_material(cache.clone(), &load_req, &load_epoch)
        .await
        .unwrap();

    // Cache hit: returns Ok without touching private storage (which has no entry for hit_req).
    storage
        .refresh_fhe_private_material(cache.clone(), &hit_req, &hit_epoch)
        .await
        .unwrap();

    // Miss + no data: error.
    let res = storage
        .refresh_fhe_private_material(cache.clone(), &miss_req, &miss_epoch)
        .await;
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("Failed to refresh crypto material from storage"),
        "got: {err}"
    );

    let cache_guard = cache.read().await;
    assert_eq!(
        cache_guard.get(&(load_req, load_epoch)).unwrap().digest(),
        load_meta.digest(),
    );
    assert_eq!(
        cache_guard.get(&(hit_req, hit_epoch)).unwrap().digest(),
        hit_meta.digest(),
    );
    assert!(cache_guard.get(&(miss_req, miss_epoch)).is_none());
}

mod migration;
