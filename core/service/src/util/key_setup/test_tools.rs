use crate::backup::BackupCiphertext;
use crate::conf::{self, Keychain};
use crate::util::file_handling::safe_read_element_versioned;
use crate::util::key_setup::FhePublicKey;
use crate::vault::keychain::make_keychain_proxy;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{
    delete_all_at_request_id, delete_at_request_and_epoch_id, make_storage,
    read_versioned_at_request_id, StorageReader, StorageReaderExt,
};
use crate::vault::storage::{read_pk_at_request_id, StorageType};
use crate::vault::{Vault, VaultDataType};
use kms_grpc::kms::v1::{CiphertextFormat, TypedPlaintext};
use kms_grpc::rpc_types::{PrivDataType, PubDataType, WrappedPublicKeyOwned};
use kms_grpc::RequestId;
use serde::de::DeserializeOwned;
use std::path::Path;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::named::Named;
use tfhe::prelude::SquashNoise;
use tfhe::prelude::Tagged;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{
    FheBool, FheTypes, FheUint128, FheUint16, FheUint160, FheUint256, FheUint32, FheUint64,
    FheUint8, HlCompactable, HlCompressible, HlExpandable, HlSquashedNoiseCompressible, ServerKey,
    Unversionize, Versionize,
};
use threshold_fhe::execution::tfhe_internals::utils::expanded_encrypt;

fn enc_and_serialize_ctxt<M, T>(
    msg: M,
    num_bits: usize,
    pk: &FhePublicKey,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat)
where
    M: HlCompactable + Numeric,
    T: HlExpandable + HlCompressible + Tagged + Versionize + Named + serde::Serialize + SquashNoise,
    <T as tfhe::prelude::SquashNoise>::Output:
        Named + Versionize + serde::Serialize + HlSquashedNoiseCompressible,
{
    let ct: T = expanded_encrypt(pk, msg, num_bits).unwrap();
    let ct_format = enc_config.try_into_ciphertext_format().unwrap();
    match ct_format {
        CiphertextFormat::SmallCompressed => (
            crate::cryptography::decompression::test_tools::compress_serialize_versioned(ct),
            ct_format,
        ),
        CiphertextFormat::SmallExpanded => {
            let mut serialized_ct = Vec::new();
            safe_serialize(&ct, &mut serialized_ct, crate::consts::SAFE_SER_SIZE_LIMIT).unwrap();
            (serialized_ct, ct_format)
        }
        CiphertextFormat::BigCompressed => {
            let squashed = ct.squash_noise().unwrap();
            let ct_list = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
                .push(squashed)
                .build()
                .unwrap();
            let mut serialized_ct = Vec::new();
            safe_serialize(
                &ct_list,
                &mut serialized_ct,
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .unwrap();
            (serialized_ct, ct_format)
        }
        CiphertextFormat::BigExpanded => {
            let squashed = ct.squash_noise().unwrap();
            let mut serialized_ct = Vec::new();
            safe_serialize(
                &squashed,
                &mut serialized_ct,
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .unwrap();
            (serialized_ct, ct_format)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptionConfig {
    pub compression: bool,
    pub precompute_sns: bool,
}

impl EncryptionConfig {
    pub fn try_into_ciphertext_format(self) -> anyhow::Result<CiphertextFormat> {
        match (self.compression, self.precompute_sns) {
            (true, true) => Ok(CiphertextFormat::BigCompressed),
            (true, false) => Ok(CiphertextFormat::SmallCompressed),
            (false, true) => Ok(CiphertextFormat::BigExpanded),
            (false, false) => Ok(CiphertextFormat::SmallExpanded),
        }
    }
}

pub fn compute_cipher(
    msg: TestingPlaintext,
    pk: &FhePublicKey,
    server_key: Option<&ServerKey>,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat, FheTypes) {
    if let Some(s) = server_key {
        // TODO is there a way to do this without cloning?
        // wait until context is ready and use that instead
        tfhe::set_server_key(s.clone());
    }

    let fhe_type = msg.into();
    let (ct_buf, ct_format) = match msg {
        TestingPlaintext::Bool(x) => {
            enc_and_serialize_ctxt::<_, FheBool>(x as u8, FheBool::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U8(x) => {
            enc_and_serialize_ctxt::<_, FheUint8>(x, FheUint8::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U16(x) => {
            enc_and_serialize_ctxt::<_, FheUint16>(x, FheUint16::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U32(x) => {
            enc_and_serialize_ctxt::<_, FheUint32>(x, FheUint32::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U64(x) => {
            enc_and_serialize_ctxt::<_, FheUint64>(x, FheUint64::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U128(x) => {
            enc_and_serialize_ctxt::<_, FheUint128>(x, FheUint128::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U160(x) => {
            enc_and_serialize_ctxt::<_, FheUint160>(x, FheUint160::num_bits(), pk, enc_config)
        }
        TestingPlaintext::U256(x) => {
            enc_and_serialize_ctxt::<_, FheUint256>(x, FheUint256::num_bits(), pk, enc_config)
        }
    };
    (ct_buf, ct_format, fhe_type)
}

/// This is a plaintext type that's exclusive for testing purposes
/// i.e., it should only be available when we use cfg(test) or cfg(feature = "testing").
/// It is a convenient wrapper around the native types
/// and lets us convert to it to the grpc plaintext type.
/// It should match what is supported by the FHEVM. A full list can be found here:
/// https://github.com/zama-ai/fhevm/blob/main/host-contracts/contracts/FHEVMExecutor.sol#L627-L634
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPlaintext {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U160(tfhe::integer::bigint::U256),
    U256(tfhe::integer::bigint::U256),
}

impl From<TestingPlaintext> for FheTypes {
    fn from(val: TestingPlaintext) -> FheTypes {
        match val {
            TestingPlaintext::Bool(_) => FheTypes::Bool,
            TestingPlaintext::U8(_) => FheTypes::Uint8,
            TestingPlaintext::U16(_) => FheTypes::Uint16,
            TestingPlaintext::U32(_) => FheTypes::Uint32,
            TestingPlaintext::U64(_) => FheTypes::Uint64,
            TestingPlaintext::U128(_) => FheTypes::Uint128,
            TestingPlaintext::U160(_) => FheTypes::Uint160,
            TestingPlaintext::U256(_) => FheTypes::Uint256,
        }
    }
}

impl From<TestingPlaintext> for TypedPlaintext {
    fn from(val: TestingPlaintext) -> TypedPlaintext {
        match val {
            TestingPlaintext::Bool(x) => TypedPlaintext::from_bool(x),
            TestingPlaintext::U8(x) => TypedPlaintext::from_u8(x),
            TestingPlaintext::U16(x) => TypedPlaintext::from_u16(x),
            TestingPlaintext::U32(x) => TypedPlaintext::from_u32(x),
            TestingPlaintext::U64(x) => TypedPlaintext::from_u64(x),
            TestingPlaintext::U128(x) => TypedPlaintext::from_u128(x),
            TestingPlaintext::U160(x) => TypedPlaintext::from_u160(x),
            TestingPlaintext::U256(x) => TypedPlaintext::from_u256(x),
        }
    }
}

impl TestingPlaintext {
    /// Return the number of bits in the plaintext.
    pub fn bits(&self) -> usize {
        match self {
            TestingPlaintext::Bool(_) => 1,
            TestingPlaintext::U8(_) => 8,
            TestingPlaintext::U16(_) => 16,
            TestingPlaintext::U32(_) => 32,
            TestingPlaintext::U64(_) => 64,
            TestingPlaintext::U128(_) => 128,
            TestingPlaintext::U160(_) => 160,
            TestingPlaintext::U256(_) => 256,
        }
    }

    pub fn fhe_type(&self) -> FheTypes {
        (*self).into()
    }
}

impl TryFrom<TypedPlaintext> for TestingPlaintext {
    type Error = anyhow::Error;
    fn try_from(value: TypedPlaintext) -> anyhow::Result<Self> {
        match value.fhe_type()? {
            FheTypes::Bool => Ok(TestingPlaintext::Bool(value.as_bool())),
            FheTypes::Uint8 => Ok(TestingPlaintext::U8(value.as_u8())),
            FheTypes::Uint16 => Ok(TestingPlaintext::U16(value.as_u16())),
            FheTypes::Uint32 => Ok(TestingPlaintext::U32(value.as_u32())),
            FheTypes::Uint64 => Ok(TestingPlaintext::U64(value.as_u64())),
            FheTypes::Uint128 => Ok(TestingPlaintext::U128(value.as_u128())),
            FheTypes::Uint160 => Ok(TestingPlaintext::U160(value.as_u160())),
            FheTypes::Uint256 => Ok(TestingPlaintext::U256(value.as_u256())),
            unsupported_fhe_type => {
                anyhow::bail!("Unsupported fhe_type in TypledPlaintext {unsupported_fhe_type:?}")
            }
        }
    }
}

impl From<(String, FheTypes)> for TestingPlaintext {
    fn from(value: (String, FheTypes)) -> Self {
        TypedPlaintext {
            bytes: value.0.into(),
            fhe_type: value.1 as i32,
        }
        .try_into()
        .unwrap()
    }
}

impl From<(Vec<u8>, FheTypes)> for TestingPlaintext {
    fn from(value: (Vec<u8>, FheTypes)) -> Self {
        TypedPlaintext {
            bytes: value.0,
            fhe_type: value.1 as i32,
        }
        .try_into()
        .unwrap()
    }
}

/// Implement from native type
macro_rules! impl_from_for_typed_ptxt {
    ($t1:ident,$t2:ident) => {
        impl From<$t1> for TestingPlaintext {
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

impl From<tfhe::integer::bigint::U256> for TestingPlaintext {
    fn from(value: tfhe::integer::U256) -> Self {
        let max_u160 = tfhe::integer::U256::from((u128::MAX, u32::MAX as u128));
        if value > max_u160 {
            panic!("value is greater than U160::MAX");
        }
        Self::U160(value)
    }
}

async fn get_pub_storage(
    pub_path: Option<&Path>,
    data_id: &RequestId,
    data_type: &str,
    storage_prefix: Option<&str>,
) -> FileStorage {
    // Try first with centralized storage
    let storage = FileStorage::new(pub_path, StorageType::PUB, storage_prefix).unwrap();
    if !storage.data_exists(data_id, data_type).await.unwrap() {
        tracing::error!(
            "Data does not exist for id={}, type={}, prefix={:?}",
            data_id,
            data_type,
            storage_prefix
        );
    }
    storage
}

pub async fn load_material_from_pub_storage<T>(
    pub_path: Option<&Path>,
    key_id: &RequestId,
    data_type: PubDataType,
    storage_prefix: Option<&str>,
) -> T
where
    T: DeserializeOwned + Unversionize + Named + Send,
    <T as tfhe_versionable::VersionizeOwned>::VersionedOwned: Send,
{
    let storage = get_pub_storage(pub_path, key_id, &data_type.to_string(), storage_prefix).await;
    let material: T = read_versioned_at_request_id(&storage, key_id, &data_type.to_string())
        .await
        .unwrap();
    material
}

pub async fn load_pk_from_pub_storage(
    pub_path: Option<&Path>,
    key_id: &RequestId,
    storage_prefix: Option<&str>,
) -> FhePublicKey {
    let storage = get_pub_storage(
        pub_path,
        key_id,
        &PubDataType::PublicKey.to_string(),
        storage_prefix,
    )
    .await;
    tracing::info!("loading pk from storage root dir: {:?}", storage.root_dir());
    let wrapped_pk = read_pk_at_request_id(&storage, key_id)
        .await
        .expect("load_pk_from_pub_storage failed");
    let WrappedPublicKeyOwned::Compact(pk) = wrapped_pk;
    pk
}

/// This function should be used for testing only and it can panic.
pub async fn compute_cipher_from_stored_key(
    pub_path: Option<&Path>,
    msg: TestingPlaintext,
    key_id: &RequestId,
    storage_prefix: Option<&str>,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat, FheTypes) {
    let pk = load_pk_from_pub_storage(pub_path, key_id, storage_prefix).await;
    //Setting the server key as we may need id to expand the ciphertext during compute_cipher
    let server_key: ServerKey =
        load_material_from_pub_storage(pub_path, key_id, PubDataType::ServerKey, storage_prefix)
            .await;

    // compute_cipher can take a long time since it may do SnS
    let (send, recv) = tokio::sync::oneshot::channel();
    rayon::spawn_fifo(move || {
        let _ = send.send(compute_cipher(msg, &pk, Some(&server_key), enc_config));
    });
    recv.await.unwrap()
}

/// Purge any kind of public or private data, regardless of type, for a specific request ID.
///
/// This function should be used for testing only and it can panic.
pub async fn purge(
    pub_path: Option<&Path>,
    priv_path: Option<&Path>,
    id: &RequestId,
    public_storage_prefixes: &[Option<String>],
    priv_storage_prefixes: &[Option<String>],
) {
    for storage_prefix in public_storage_prefixes.iter() {
        let mut threshold_pub =
            FileStorage::new(pub_path, StorageType::PUB, storage_prefix.as_deref()).unwrap();
        delete_all_at_request_id(&mut threshold_pub, id)
            .await
            .unwrap();
    }
    for storage_prefix in priv_storage_prefixes.iter() {
        let mut threshold_priv =
            FileStorage::new(priv_path, StorageType::PRIV, storage_prefix.as_deref()).unwrap();
        delete_all_at_request_id(&mut threshold_priv, id)
            .await
            .unwrap();

        // Also delete epoch-specific data types that delete_all_at_request_id skips
        for data_type in [PrivDataType::FhePrivateKey, PrivDataType::FheKeyInfo] {
            let data_type_str = data_type.to_string();
            if let Ok(epoch_ids) = threshold_priv.all_epoch_ids_for_data(&data_type_str).await {
                for epoch_id in epoch_ids {
                    let _ = delete_at_request_and_epoch_id(
                        &mut threshold_priv,
                        id,
                        &epoch_id,
                        &data_type_str,
                    )
                    .await;
                }
            }
        }
    }
}

/// Purge the entire content of the private storage.
/// This is useful for testing backup
pub async fn purge_priv(priv_path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    // Purge for the max amount of parties we may have in tests
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(priv_path, StorageType::PRIV, storage_prefix.as_deref()).unwrap();
        // Ignore if the dir does not exist
        let _ = tokio::fs::remove_dir_all(&storage.root_dir()).await;
    }
}

/// Purge the entire content of the public storage.
/// This is useful for testing backup
pub async fn purge_pub(pub_path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    // Purge for the max amount of parties we may have in tests
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(pub_path, StorageType::PUB, storage_prefix.as_deref()).unwrap();
        // Ignore if the dir does not exist
        let _ = tokio::fs::remove_dir_all(&storage.root_dir()).await;
    }
}

/// Purge _all_ backed up data. Both custodian and non-custodian based backups.
/// Note however that this method does _not_ purge anything in the private or public storage.
/// Thus, if you want to avoid new custodian backups being constructed at boot ensure that `purge_recovery_material`
/// is also called, as it deletes all the custodian recovery info.
pub async fn purge_backup(backup_path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(backup_path, StorageType::BACKUP, storage_prefix.as_deref()).unwrap();
        // Ignore if the dir does not exist
        let _ = tokio::fs::remove_dir_all(&storage.root_dir()).await;
    }
}

/// Validate that a backup exists
pub async fn backup_exists(
    backup_path: Option<&Path>,
    storage_prefixes: &[Option<String>],
) -> bool {
    let mut backup_exists = true;
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(backup_path, StorageType::BACKUP, storage_prefix.as_deref()).unwrap();
        let base_path = storage.root_dir();
        let mut files = tokio::fs::read_dir(base_path).await.unwrap();
        if files.next_entry().await.unwrap().is_none() {
            backup_exists = false;
        }
    }
    backup_exists
}

/// Helper method to construct a backup vault for testing. That is either without encryption (no `Keychain`) or using custodians.
pub async fn file_backup_vault(
    keychain_conf: Option<&Keychain>,
    pub_path: Option<&Path>,
    backup_path: Option<&Path>,
    pub_storage_prefix: Option<&str>,
    backup_storage_prefix: Option<&str>,
) -> Vault {
    let create_storage_conf =
        |path: Option<&Path>, storage_prefix: Option<&str>| match (path, storage_prefix) {
            (None, None) => None,
            (None, Some(prefix)) => Some(conf::Storage::File(conf::FileStorage {
                path: std::env::current_dir()
                    .unwrap()
                    .join(crate::consts::KEY_PATH_PREFIX),
                prefix: Some(prefix.to_string()),
            })),
            (Some(path), None) => Some(conf::Storage::File(conf::FileStorage {
                path: path.to_path_buf(),
                prefix: None,
            })),
            (Some(path), Some(prefix)) => Some(conf::Storage::File(conf::FileStorage {
                path: path.to_path_buf(),
                prefix: Some(prefix.to_string()),
            })),
        };
    let backup_storage_conf = create_storage_conf(backup_path, backup_storage_prefix);
    let pub_storage_conf = create_storage_conf(pub_path, pub_storage_prefix);

    let pub_proxy_storage = make_storage(pub_storage_conf, StorageType::PUB, None, None).unwrap();
    let backup_proxy_storage =
        make_storage(backup_storage_conf, StorageType::BACKUP, None, None).unwrap();
    let keychain = match keychain_conf {
        Some(conf) => Some(
            make_keychain_proxy(conf, None, None, Some(&pub_proxy_storage))
                .await
                .unwrap(),
        ),
        None => None,
    };
    Vault {
        storage: backup_proxy_storage,
        keychain,
    }
}

/// Helper method for tests to read the plain custodian backup files without going through the Vault API, and hence decryption.
pub async fn read_custodian_backup_files(
    test_path: Option<&Path>,
    backup_id: &RequestId,
    file_req: &RequestId,
    data_type: &str,
    storage_prefixes: &[Option<String>],
) -> Vec<BackupCiphertext> {
    let mut files = Vec::new();
    for storage_prefix in storage_prefixes.iter() {
        let storage =
            FileStorage::new(test_path, StorageType::BACKUP, storage_prefix.as_deref()).unwrap();
        let coerced_path = storage
            .root_dir()
            .join(
                VaultDataType::CustodianBackupData(*backup_id, data_type.try_into().unwrap())
                    .to_string(),
            )
            .join(file_req.to_string());
        // Attempt to read the file
        if let Ok(file) = safe_read_element_versioned(coerced_path).await {
            files.push(file);
        }
    }
    files
}

/// Remove all the data needed to perform custodian backups.
/// This then allows your to prevent the automatic backup being done at boot
/// when the system is configured with custodian backups.
/// TODO currently not used anywhere
pub async fn purge_recovery_material(path: Option<&Path>, storage_prefixes: &[Option<String>]) {
    for storage_prefix in storage_prefixes {
        // Next purge recovery info
        let storage = FileStorage::new(
            path,
            StorageType::PUB,
            storage_prefix.as_ref().map(|x| x.as_str()),
        )
        .unwrap();
        let base_dir = storage.root_dir();
        let _ =
            tokio::fs::remove_dir_all(&base_dir.join(PubDataType::RecoveryMaterial.to_string()))
                .await;
    }
}

#[cfg(any(test, feature = "testing"))]
pub(crate) mod setup {
    use crate::consts::DEFAULT_EPOCH_ID;
    use crate::consts::{
        PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
    };
    #[cfg(feature = "slow_tests")]
    use crate::consts::{TEST_THRESHOLD_CRS_ID_13P, TEST_THRESHOLD_KEY_ID_13P};
    use crate::util::key_setup::{
        ensure_central_crs_exists, ensure_central_keys_exist, ensure_client_keys_exist,
        ThresholdSigningKeyConfig,
    };
    use crate::{
        consts::{
            KEY_PATH_PREFIX, OTHER_CENTRAL_TEST_ID, SIGNING_KEY_ID, TEST_CENTRAL_CRS_ID,
            TEST_CENTRAL_KEY_ID, TEST_PARAM, TEST_THRESHOLD_CRS_ID_10P, TEST_THRESHOLD_CRS_ID_4P,
            TEST_THRESHOLD_KEY_ID_10P, TEST_THRESHOLD_KEY_ID_4P, TMP_PATH_PREFIX,
        },
        util::key_setup::ensure_central_server_signing_keys_exist,
    };
    use crate::{
        util::key_setup::{
            ensure_threshold_crs_exists, ensure_threshold_keys_exist,
            ensure_threshold_server_signing_keys_exist,
        },
        vault::storage::{file::FileStorage, StorageType},
    };
    use kms_grpc::identifiers::EpochId;
    use kms_grpc::RequestId;
    use std::path::Path;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;

    pub async fn ensure_dir_exist(path: Option<&Path>) {
        match path {
            Some(p) => {
                tokio::fs::create_dir_all(p.join(TMP_PATH_PREFIX))
                    .await
                    .unwrap();
                tokio::fs::create_dir_all(p.join(KEY_PATH_PREFIX))
                    .await
                    .unwrap();
            }
            None => {
                tokio::fs::create_dir_all(TMP_PATH_PREFIX).await.unwrap();
                tokio::fs::create_dir_all(KEY_PATH_PREFIX).await.unwrap();
            }
        }
    }

    async fn testing_material(path: Option<&Path>) {
        ensure_dir_exist(path).await;
        let epoch_id = *DEFAULT_EPOCH_ID;
        ensure_client_keys_exist(path, &SIGNING_KEY_ID, true).await;
        central_material(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_TEST_ID,
            &TEST_CENTRAL_CRS_ID,
            &epoch_id,
            path,
        )
        .await;
        let epoch_id = *DEFAULT_EPOCH_ID;
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_4P,
            &TEST_THRESHOLD_CRS_ID_4P,
            &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..4],
            &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..4],
            &epoch_id,
            path,
        )
        .await;
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_10P,
            &TEST_THRESHOLD_CRS_ID_10P,
            &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..10],
            &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..10],
            &epoch_id,
            path,
        )
        .await;
        #[cfg(feature = "slow_tests")]
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_13P,
            &TEST_THRESHOLD_CRS_ID_13P,
            &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..13],
            &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..13],
            &epoch_id,
            path,
        )
        .await;
    }

    pub async fn ensure_testing_material_exists(path: Option<&Path>) {
        testing_material(path).await;
    }

    #[cfg(feature = "slow_tests")]
    async fn default_material() {
        use crate::consts::{
            DEFAULT_CENTRAL_CRS_ID, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM,
            DEFAULT_THRESHOLD_CRS_ID_10P, DEFAULT_THRESHOLD_CRS_ID_13P,
            DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_KEY_ID_10P,
            DEFAULT_THRESHOLD_KEY_ID_13P, DEFAULT_THRESHOLD_KEY_ID_4P, OTHER_CENTRAL_DEFAULT_ID,
        };
        ensure_dir_exist(None).await;
        let epoch_id = *DEFAULT_EPOCH_ID;
        ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;
        central_material(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_DEFAULT_ID,
            &DEFAULT_CENTRAL_CRS_ID,
            &epoch_id,
            None,
        )
        .await;
        threshold_material(
            &DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID_4P,
            &DEFAULT_THRESHOLD_CRS_ID_4P,
            &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..4],
            &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..4],
            &epoch_id,
            None,
        )
        .await;
        threshold_material(
            &DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID_10P,
            &DEFAULT_THRESHOLD_CRS_ID_10P,
            &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..10],
            &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..10],
            &epoch_id,
            None,
        )
        .await;
        threshold_material(
            &DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID_13P,
            &DEFAULT_THRESHOLD_CRS_ID_13P,
            &PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0..13],
            &PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0..13],
            &epoch_id,
            None,
        )
        .await;
    }

    async fn central_material(
        params: &DKGParams,
        fhe_key_id: &RequestId,
        other_fhe_key_id: &RequestId,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        path: Option<&Path>,
    ) {
        let mut central_pub_storage = FileStorage::new(path, StorageType::PUB, None).unwrap();
        let mut central_priv_storage = FileStorage::new(path, StorageType::PRIV, None).unwrap();

        ensure_central_server_signing_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await;
        ensure_central_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            params.to_owned(),
            fhe_key_id,
            other_fhe_key_id,
            epoch_id,
            true,
            false,
        )
        .await;
        ensure_central_crs_exists(
            &mut central_pub_storage,
            &mut central_priv_storage,
            params.to_owned(),
            crs_id,
            true,
        )
        .await;
    }

    async fn threshold_material(
        params: &DKGParams,
        fhe_key_id: &RequestId,
        crs_id: &RequestId,
        public_storage_prefixes: &[Option<String>],
        private_storage_prefixes: &[Option<String>],
        epoch_id: &EpochId,
        path: Option<&Path>,
    ) {
        assert_eq!(
            public_storage_prefixes.len(),
            private_storage_prefixes.len()
        );
        let amount_parties = public_storage_prefixes.len();
        let mut threshold_pub_storages = Vec::with_capacity(amount_parties);
        for storage_prefix in public_storage_prefixes.iter() {
            threshold_pub_storages
                .push(FileStorage::new(path, StorageType::PUB, storage_prefix.as_deref()).unwrap());
        }
        let mut threshold_priv_storages = Vec::with_capacity(amount_parties);
        for storage_prefix in private_storage_prefixes.iter() {
            threshold_priv_storages.push(
                FileStorage::new(path, StorageType::PRIV, storage_prefix.as_deref()).unwrap(),
            );
        }

        let _ = ensure_threshold_server_signing_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            &SIGNING_KEY_ID,
            true,
            ThresholdSigningKeyConfig::AllParties(
                (1..=amount_parties).map(|i| format!("party-{i}")).collect(),
            ),
            false,
        )
        .await;
        ensure_threshold_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            params.to_owned(),
            fhe_key_id,
            epoch_id,
            true,
        )
        .await;
        ensure_threshold_crs_exists(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            params.to_owned(),
            crs_id,
            true,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    pub async fn ensure_default_material_exists() {
        default_material().await;
    }
}

// NOTE: this test stays out of the setup module
// because we don't want it to have the "testing" feature
#[tokio::test]
async fn test_purge() {
    use crate::consts::SIGNING_KEY_ID;
    use kms_grpc::rpc_types::PrivDataType;

    let temp_dir = tempfile::tempdir().unwrap();
    let test_prefix = Some(temp_dir.path());
    let mut central_pub_storage = FileStorage::new(test_prefix, StorageType::PUB, None).unwrap();
    let mut central_priv_storage = FileStorage::new(test_prefix, StorageType::PRIV, None).unwrap();

    // Check no keys exist
    assert!(central_pub_storage
        .all_data_ids(&PubDataType::VerfKey.to_string())
        .await
        .unwrap()
        .is_empty());
    assert!(central_priv_storage
        .all_data_ids(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap()
        .is_empty());
    // Create keys to be deleted
    assert!(
        crate::util::key_setup::ensure_central_server_signing_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            &SIGNING_KEY_ID,
            true,
        )
        .await
    );
    // Validate the keys were made
    let pub_ids = central_pub_storage
        .all_data_ids(&PubDataType::VerfKey.to_string())
        .await
        .unwrap();
    assert_eq!(pub_ids.len(), 1);
    let priv_ids = central_priv_storage
        .all_data_ids(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap();
    assert_eq!(priv_ids.len(), 1);
    purge(
        test_prefix,
        test_prefix,
        &pub_ids.into_iter().next().unwrap(),
        &[None],
        &[None],
    )
    .await;
    // Check the keys were deleted
    assert!(central_pub_storage
        .all_data_ids(&PubDataType::VerfKey.to_string())
        .await
        .unwrap()
        .is_empty());
    assert!(central_priv_storage
        .all_data_ids(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap()
        .is_empty());
}
