use crate::consts::{AMOUNT_PARTIES, THRESHOLD};
#[cfg(test)]
use crate::consts::{KEY_PATH_PREFIX, TMP_PATH_PREFIX};
use crate::kms::{FheType, RequestId};
use crate::rpc::rpc_types::PubDataType;
use crate::rpc::rpc_types::{Plaintext, PrivDataType};
use crate::storage::Storage;
use crate::storage::StorageReader;
use crate::storage::{store_at_request_id, FileStorage, StorageType};
use crate::threshold::threshold_kms::compute_all_info;
use crate::threshold::threshold_kms::ThresholdFheKeys;
use crate::util::file_handling::read_as_json;
use crate::util::key_setup::FhePublicKey;
use aes_prng::AesRng;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use distributed_decryption::execution::tfhe_internals::test_feature::{
    gen_key_set, keygen_all_party_shares,
};
use itertools::Itertools;
use kms_core_common::Versionize;
use rand::SeedableRng;
use std::path::Path;
use strum::IntoEnumIterator;
use tfhe::{prelude::*, FheBool, FheUint2048, FheUint256};
use tfhe::{FheUint128, FheUint16, FheUint160, FheUint32, FheUint64, FheUint8};

// TODD The code here should be split s.t. that generation code stays in production and everything else goes to the test package

macro_rules! serialize_ct {
    ($msg:expr,$pk:expr,$t1:ident) => {{
        let ct = $t1::encrypt($msg, $pk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
        serialized_ct
    }};
}

pub fn compute_cipher(msg: TypedPlaintext, pk: &FhePublicKey) -> (Vec<u8>, FheType) {
    let fhe_type = msg.to_fhe_type();
    (
        match msg {
            TypedPlaintext::Bool(x) => {
                serialize_ct!(x, pk, FheBool)
            }
            TypedPlaintext::U8(x) => {
                serialize_ct!(x, pk, FheUint8)
            }
            TypedPlaintext::U16(x) => {
                serialize_ct!(x, pk, FheUint16)
            }
            TypedPlaintext::U32(x) => {
                serialize_ct!(x, pk, FheUint32)
            }
            TypedPlaintext::U64(x) => {
                serialize_ct!(x, pk, FheUint64)
            }
            TypedPlaintext::U128(x) => {
                serialize_ct!(x, pk, FheUint128)
            }
            TypedPlaintext::U160(x) => {
                serialize_ct!(x, pk, FheUint160)
            }
            TypedPlaintext::U256(x) => {
                serialize_ct!(x, pk, FheUint256)
            }
            TypedPlaintext::U2048(x) => {
                serialize_ct!(x, pk, FheUint2048)
            }
        },
        fhe_type,
    )
}

// TODO not sure how to deal with that clippy warning
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
pub enum TypedPlaintext {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U160(tfhe::integer::U256),
    U256(tfhe::integer::U256),
    U2048(tfhe::integer::bigint::U2048),
}

impl TypedPlaintext {
    /// Convert [self] to [FheType].
    pub fn to_fhe_type(&self) -> FheType {
        match self {
            TypedPlaintext::Bool(_) => FheType::Ebool,
            TypedPlaintext::U8(_) => FheType::Euint8,
            TypedPlaintext::U16(_) => FheType::Euint16,
            TypedPlaintext::U32(_) => FheType::Euint32,
            TypedPlaintext::U64(_) => FheType::Euint64,
            TypedPlaintext::U128(_) => FheType::Euint128,
            TypedPlaintext::U160(_) => FheType::Euint160,
            TypedPlaintext::U256(_) => FheType::Euint256,
            TypedPlaintext::U2048(_) => FheType::Euint2048,
        }
    }

    pub fn to_plaintext(&self) -> Plaintext {
        match self {
            TypedPlaintext::Bool(x) => Plaintext::from_bool(*x),
            TypedPlaintext::U8(x) => Plaintext::from_u8(*x),
            TypedPlaintext::U16(x) => Plaintext::from_u16(*x),
            TypedPlaintext::U32(x) => Plaintext::from_u32(*x),
            TypedPlaintext::U64(x) => Plaintext::from_u64(*x),
            TypedPlaintext::U128(x) => Plaintext::from_u128(*x),
            TypedPlaintext::U160(x) => Plaintext::from_u160(*x),
            TypedPlaintext::U256(x) => Plaintext::from_u256(*x),
            TypedPlaintext::U2048(x) => Plaintext::from_u2048(*x),
        }
    }

    /// Return the number of bits in the plaintext.
    pub fn bits(&self) -> usize {
        match self {
            TypedPlaintext::Bool(_) => 1,
            TypedPlaintext::U8(_) => 8,
            TypedPlaintext::U16(_) => 16,
            TypedPlaintext::U32(_) => 32,
            TypedPlaintext::U64(_) => 64,
            TypedPlaintext::U128(_) => 128,
            TypedPlaintext::U160(_) => 160,
            TypedPlaintext::U256(_) => 256,
            TypedPlaintext::U2048(_) => 2048,
        }
    }
}

macro_rules! impl_from_for_typed_ptxt {
    ($t1:ident,$t2:ident) => {
        impl From<$t1> for TypedPlaintext {
            fn from(value: $t1) -> Self {
                Self::$t2(value)
            }
        }
    };
}

impl_from_for_typed_ptxt!(bool, Bool);
impl_from_for_typed_ptxt!(u8, U8);
impl_from_for_typed_ptxt!(u16, U16);
impl_from_for_typed_ptxt!(u32, U32);
impl_from_for_typed_ptxt!(u64, U64);
impl_from_for_typed_ptxt!(u128, U128);

impl From<tfhe::integer::U256> for TypedPlaintext {
    fn from(value: tfhe::integer::U256) -> Self {
        let max_u160 = tfhe::integer::U256::from((u128::MAX, u32::MAX as u128));
        if value > max_u160 {
            panic!("value is greater than U160::MAX");
        }
        Self::U160(value)
    }
}

/// This function should be used for testing only and it can panic.
pub async fn compute_cipher_from_storage(
    pub_path: Option<&Path>,
    msg: TypedPlaintext,
    key_id: &str,
) -> (Vec<u8>, FheType) {
    // Try first with centralized storage
    let storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    let url = storage
        .compute_url(key_id, &PubDataType::PublicKey.to_string())
        .unwrap();
    let pk = if storage.data_exists(&url).await.unwrap() {
        storage.read_data(&url).await.unwrap()
    } else {
        // Try with the threshold storage
        let storage = FileStorage::new_threshold(pub_path, StorageType::PUB, 1).unwrap();
        let url = storage
            .compute_url(key_id, &PubDataType::PublicKey.to_string())
            .unwrap();
        storage.read_data(&url).await.unwrap()
    };
    compute_cipher(msg, &pk)
}

/// Purge any kind of data, regardless of type, for a specific request ID.
///
/// This function should be used for testing only and it can panic.
pub async fn purge(pub_path: Option<&Path>, priv_path: Option<&Path>, id: &str) {
    let mut pub_storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    for cur_type in PubDataType::iter() {
        let _ = pub_storage
            .delete_data(&pub_storage.compute_url(id, &cur_type.to_string()).unwrap())
            .await;
    }

    let mut priv_storage = FileStorage::new_centralized(priv_path, StorageType::PRIV).unwrap();
    for cur_type in PrivDataType::iter() {
        let _ = priv_storage
            .delete_data(&priv_storage.compute_url(id, &cur_type.to_string()).unwrap())
            .await;
    }
    for i in 1..=AMOUNT_PARTIES {
        let mut threshold_pub = FileStorage::new_threshold(pub_path, StorageType::PUB, i).unwrap();
        let mut threshold_priv =
            FileStorage::new_threshold(priv_path, StorageType::PRIV, i).unwrap();
        for cur_type in PrivDataType::iter() {
            let _ = threshold_priv
                .delete_data(
                    &threshold_priv
                        .compute_url(id, &cur_type.to_string())
                        .unwrap(),
                )
                .await;
        }
        for cur_type in PubDataType::iter() {
            let _ = threshold_pub
                .delete_data(
                    &threshold_pub
                        .compute_url(id, &cur_type.to_string())
                        .unwrap(),
                )
                .await;
        }
    }
}

#[cfg(test)]
pub async fn ensure_dir_exist() {
    tokio::fs::create_dir_all(TMP_PATH_PREFIX).await.unwrap();
    tokio::fs::create_dir_all(KEY_PATH_PREFIX).await.unwrap();
}

/// NOTE: this is insecure!
pub async fn ensure_threshold_keys_exist<S>(
    pub_storages: &mut [S],
    priv_storages: &mut [S],
    param_path: &str,
    key_id: &RequestId,
    deterministic: bool,
) where
    S: Storage,
{
    // TODO generalize setup for multiple keys
    let mut rng = if deterministic {
        AesRng::seed_from_u64(AMOUNT_PARTIES as u64)
    } else {
        AesRng::from_entropy()
    };
    let signing_keys = super::ensure_threshold_server_signing_keys_exist(
        pub_storages,
        priv_storages,
        deterministic,
        AMOUNT_PARTIES,
    )
    .await;
    if pub_storages[0]
        .data_exists(
            &pub_storages[0]
                .compute_url(&key_id.to_string(), &PubDataType::PublicKey.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
    {
        return;
    }

    let params: NoiseFloodParameters = match read_as_json(param_path).await {
        Ok(x) => x,
        Err(e) => panic!("Error opening params at {}: {}", param_path, e),
    };

    let key_set = gen_key_set(params, &mut rng);
    let key_shares = keygen_all_party_shares(
        key_set.get_raw_lwe_client_key(),
        key_set.get_raw_glwe_client_key(),
        key_set.sns_secret_key.key,
        params.ciphertext_parameters,
        &mut rng,
        AMOUNT_PARTIES,
        THRESHOLD,
    )
    .unwrap();
    let sns_key = key_set.public_keys.sns_key.to_owned().unwrap();
    for i in 1..=AMOUNT_PARTIES {
        println!("Generating key for party {i}");
        // Get first signing key
        let sk = signing_keys[i - 1]
            .values()
            .collect_vec()
            .first()
            .unwrap()
            .to_owned()
            .to_owned();
        let info = compute_all_info(&sk, &key_set.public_keys).unwrap();
        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: key_shares[i - 1].to_owned(),
            sns_key: sns_key.clone(),
            pk_meta_data: info,
        };
        store_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            &key_set.public_keys.public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
        store_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            &key_set.public_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
        store_at_request_id(
            &mut priv_storages[i - 1],
            key_id,
            &threshold_fhe_keys.versionize(),
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{
        AMOUNT_PARTIES, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID, TEST_CRS_ID, TEST_PARAM_PATH,
        TEST_THRESHOLD_KEY_ID,
    };
    use crate::storage::{FileStorage, StorageType};
    use crate::util::key_setup::{
        ensure_central_crs_store_exists, ensure_central_keys_exist, ensure_client_keys_exist,
    };
    use tokio::runtime::Runtime;

    async fn testing_material() {
        ensure_dir_exist().await;
        ensure_client_keys_exist(None, true).await;
        let mut central_pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let mut central_priv_storage =
            FileStorage::new_centralized(None, StorageType::PRIV).unwrap();
        let mut threshold_pub_storages = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            threshold_pub_storages
                .push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
        }
        let mut threshold_priv_storages = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            threshold_priv_storages
                .push(FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap());
        }

        ensure_central_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            TEST_PARAM_PATH,
            &TEST_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_TEST_ID,
            true,
            false,
        )
        .await;
        ensure_central_crs_store_exists(
            &mut central_pub_storage,
            &mut central_priv_storage,
            TEST_PARAM_PATH,
            &TEST_CRS_ID,
            true,
        )
        .await;
        ensure_threshold_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            TEST_PARAM_PATH,
            &TEST_THRESHOLD_KEY_ID,
            true,
        )
        .await;
    }

    #[ctor::ctor]
    fn ensure_testing_material_exists() {
        let rt = Runtime::new().unwrap();
        rt.block_on(testing_material());
    }

    #[cfg(feature = "slow_tests")]
    async fn default_material() {
        use crate::consts::{
            DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, DEFAULT_PARAM_PATH, DEFAULT_THRESHOLD_KEY_ID,
            OTHER_CENTRAL_DEFAULT_ID,
        };
        ensure_dir_exist().await;
        let mut central_pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let mut central_priv_storage =
            FileStorage::new_centralized(None, StorageType::PRIV).unwrap();
        let mut threshold_pub_storages = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            threshold_pub_storages
                .push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
        }
        let mut threshold_priv_storages = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            threshold_priv_storages
                .push(FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap());
        }

        ensure_client_keys_exist(None, true).await;
        ensure_central_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_DEFAULT_ID,
            true,
            false,
        )
        .await;
        ensure_central_crs_store_exists(
            &mut central_pub_storage,
            &mut central_priv_storage,
            DEFAULT_PARAM_PATH,
            &DEFAULT_CRS_ID,
            true,
        )
        .await;
        ensure_threshold_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            DEFAULT_PARAM_PATH,
            &DEFAULT_THRESHOLD_KEY_ID,
            true,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[ctor::ctor]
    fn ensure_default_material_exists() {
        let rt = Runtime::new().unwrap();
        rt.block_on(default_material());
    }
}
