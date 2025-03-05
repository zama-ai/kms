use crate::util::key_setup::FhePublicKey;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{
    delete_all_at_request_id, read_versioned_at_request_id, StorageReader,
};
use crate::vault::storage::{read_pk_at_request_id, StorageType};
use distributed_decryption::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use distributed_decryption::execution::tfhe_internals::utils::expanded_encrypt;
use kms_grpc::kms::v1::{CiphertextFormat, FheType, RequestId, TypedPlaintext};
use kms_grpc::rpc_types::{PubDataType, WrappedPublicKeyOwned};
use serde::de::DeserializeOwned;
use std::path::Path;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::IntegerCiphertext;
use tfhe::named::Named;
use tfhe::prelude::Tagged;
use tfhe::safe_serialization::safe_serialize;
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32,
    FheUint4, FheUint512, FheUint64, FheUint8, HlCompactable, HlCompressible, HlExpandable,
    ServerKey, Unversionize, Versionize,
};

trait IntoRawParts {
    fn into_raw_parts(self) -> BaseRadixCiphertext<tfhe::shortint::Ciphertext>;
}

impl IntoRawParts for FheBool {
    fn into_raw_parts(self) -> BaseRadixCiphertext<tfhe::shortint::Ciphertext> {
        BaseRadixCiphertext::from_blocks(vec![self.into_raw_parts()])
    }
}

macro_rules! impl_into_raw_parts {
    ($t:ty) => {
        impl IntoRawParts for $t {
            fn into_raw_parts(self) -> BaseRadixCiphertext<tfhe::shortint::Ciphertext> {
                let (radix_ct, _, _) = self.into_raw_parts();
                radix_ct
            }
        }
    };
}

impl_into_raw_parts!(FheUint4);
impl_into_raw_parts!(FheUint8);
impl_into_raw_parts!(FheUint16);
impl_into_raw_parts!(FheUint32);
impl_into_raw_parts!(FheUint64);
impl_into_raw_parts!(FheUint128);
impl_into_raw_parts!(FheUint160);
impl_into_raw_parts!(FheUint256);
impl_into_raw_parts!(FheUint512);
impl_into_raw_parts!(FheUint1024);
impl_into_raw_parts!(FheUint2048);

fn enc_and_serialize_ctxt<M, T>(
    msg: M,
    num_bits: usize,
    pk: &FhePublicKey,
    server_key: Option<&ServerKey>,
    sns_key: Option<&SwitchAndSquashKey>,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat)
where
    M: HlCompactable + Numeric,
    T: HlExpandable
        + HlCompressible
        + Tagged
        + IntoRawParts
        + Versionize
        + Named
        + serde::Serialize,
{
    let ct: T = expanded_encrypt(pk, msg, num_bits).unwrap();
    let ct_format = enc_config
        .try_into_ciphertext_format(server_key, sns_key)
        .unwrap();
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
            panic!("cannot compress 128-bit ciphertext")
        }
        CiphertextFormat::BigExpanded => {
            let sns_key = sns_key.expect("expected to find sns key");
            // .into_raw_parts is not from any trait, so we have to write this as a macro
            let radix_ct = ct.into_raw_parts();
            let large_ct = sns_key.to_large_ciphertext(&radix_ct).unwrap();
            let mut serialized_ct = Vec::new();
            safe_serialize(
                &large_ct,
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
    pub fn try_into_ciphertext_format(
        self,
        server_key: Option<&ServerKey>,
        sns_key: Option<&SwitchAndSquashKey>,
    ) -> anyhow::Result<CiphertextFormat> {
        match (self.compression, self.precompute_sns) {
            (true, true) => anyhow::bail!("compression is not supported with sns precompute"),
            (true, false) => {
                if server_key.is_none() {
                    anyhow::bail!("compression is enabled but server key is missing");
                }
                Ok(CiphertextFormat::SmallCompressed)
            }
            (false, true) => {
                if sns_key.is_none() {
                    anyhow::bail!("sns precompute is enabled but sns key is missing");
                }
                Ok(CiphertextFormat::BigExpanded)
            }
            (false, false) => Ok(CiphertextFormat::SmallExpanded),
        }
    }
}

pub fn compute_cipher(
    msg: TestingPlaintext,
    pk: &FhePublicKey,
    server_key: Option<&ServerKey>,
    sns_key: Option<&SwitchAndSquashKey>,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat, FheType) {
    if let Some(s) = server_key {
        // TODO is there a way to do this without cloning?
        // wait until context is ready and use that instead
        tfhe::set_server_key(s.clone());
    }

    let fhe_type = msg.into();
    let (ct_buf, ct_format) = match msg {
        TestingPlaintext::Bool(x) => enc_and_serialize_ctxt::<_, FheBool>(
            x as u8,
            FheBool::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U4(x) => enc_and_serialize_ctxt::<_, FheUint4>(
            x,
            FheUint4::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U8(x) => enc_and_serialize_ctxt::<_, FheUint8>(
            x,
            FheUint8::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U16(x) => enc_and_serialize_ctxt::<_, FheUint16>(
            x,
            FheUint16::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U32(x) => enc_and_serialize_ctxt::<_, FheUint32>(
            x,
            FheUint32::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U64(x) => enc_and_serialize_ctxt::<_, FheUint64>(
            x,
            FheUint64::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U128(x) => enc_and_serialize_ctxt::<_, FheUint128>(
            x,
            FheUint128::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U160(x) => enc_and_serialize_ctxt::<_, FheUint160>(
            x,
            FheUint160::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U256(x) => enc_and_serialize_ctxt::<_, FheUint256>(
            x,
            FheUint256::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U512(x) => enc_and_serialize_ctxt::<_, FheUint512>(
            x,
            FheUint512::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U1024(x) => enc_and_serialize_ctxt::<_, FheUint1024>(
            x,
            FheUint1024::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
        TestingPlaintext::U2048(x) => enc_and_serialize_ctxt::<_, FheUint2048>(
            x,
            FheUint2048::num_bits(),
            pk,
            server_key,
            sns_key,
            enc_config,
        ),
    };
    (ct_buf, ct_format, fhe_type)
}

/// This is a plaintext type that's exclusive for testing purposes
/// i.e., it should only be available when we use cfg(test) or cfg(feature = "testing").
/// It is a convenient wrapper around the native types
/// and lets us convert to it to the grpc plaintext type.
// TODO not sure how to deal with that clippy warning
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPlaintext {
    Bool(bool),
    U8(u8),
    U4(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U160(tfhe::integer::bigint::U256),
    U256(tfhe::integer::bigint::U256),
    U512(tfhe::integer::bigint::U512),
    U1024(tfhe::integer::bigint::U1024),
    U2048(tfhe::integer::bigint::U2048),
}

impl From<TestingPlaintext> for FheType {
    fn from(val: TestingPlaintext) -> FheType {
        match val {
            TestingPlaintext::Bool(_) => FheType::Ebool,
            TestingPlaintext::U4(_) => FheType::Euint4,
            TestingPlaintext::U8(_) => FheType::Euint8,
            TestingPlaintext::U16(_) => FheType::Euint16,
            TestingPlaintext::U32(_) => FheType::Euint32,
            TestingPlaintext::U64(_) => FheType::Euint64,
            TestingPlaintext::U128(_) => FheType::Euint128,
            TestingPlaintext::U160(_) => FheType::Euint160,
            TestingPlaintext::U256(_) => FheType::Euint256,
            TestingPlaintext::U512(_) => FheType::Euint512,
            TestingPlaintext::U1024(_) => FheType::Euint1024,
            TestingPlaintext::U2048(_) => FheType::Euint2048,
        }
    }
}

impl From<TestingPlaintext> for TypedPlaintext {
    fn from(val: TestingPlaintext) -> TypedPlaintext {
        match val {
            TestingPlaintext::Bool(x) => TypedPlaintext::from_bool(x),
            TestingPlaintext::U4(x) => TypedPlaintext::from_u4(x),
            TestingPlaintext::U8(x) => TypedPlaintext::from_u8(x),
            TestingPlaintext::U16(x) => TypedPlaintext::from_u16(x),
            TestingPlaintext::U32(x) => TypedPlaintext::from_u32(x),
            TestingPlaintext::U64(x) => TypedPlaintext::from_u64(x),
            TestingPlaintext::U128(x) => TypedPlaintext::from_u128(x),
            TestingPlaintext::U160(x) => TypedPlaintext::from_u160(x),
            TestingPlaintext::U256(x) => TypedPlaintext::from_u256(x),
            TestingPlaintext::U512(x) => TypedPlaintext::from_u512(x),
            TestingPlaintext::U1024(x) => TypedPlaintext::from_u1024(x),
            TestingPlaintext::U2048(x) => TypedPlaintext::from_u2048(x),
        }
    }
}

impl TestingPlaintext {
    /// Return the number of bits in the plaintext.
    pub fn bits(&self) -> usize {
        match self {
            TestingPlaintext::Bool(_) => 1,
            TestingPlaintext::U4(_) => 4,
            TestingPlaintext::U8(_) => 8,
            TestingPlaintext::U16(_) => 16,
            TestingPlaintext::U32(_) => 32,
            TestingPlaintext::U64(_) => 64,
            TestingPlaintext::U128(_) => 128,
            TestingPlaintext::U160(_) => 160,
            TestingPlaintext::U256(_) => 256,
            TestingPlaintext::U512(_) => 512,
            TestingPlaintext::U1024(_) => 1024,
            TestingPlaintext::U2048(_) => 2048,
        }
    }
}

impl From<TypedPlaintext> for TestingPlaintext {
    fn from(value: TypedPlaintext) -> Self {
        match value.fhe_type() {
            FheType::Ebool => TestingPlaintext::Bool(value.as_bool()),
            FheType::Euint4 => TestingPlaintext::U4(value.as_u4()),
            FheType::Euint8 => TestingPlaintext::U8(value.as_u8()),
            FheType::Euint16 => TestingPlaintext::U16(value.as_u16()),
            FheType::Euint32 => TestingPlaintext::U32(value.as_u32()),
            FheType::Euint64 => TestingPlaintext::U64(value.as_u64()),
            FheType::Euint128 => TestingPlaintext::U128(value.as_u128()),
            FheType::Euint160 => TestingPlaintext::U160(value.as_u160()),
            FheType::Euint256 => TestingPlaintext::U256(value.as_u256()),
            FheType::Euint512 => TestingPlaintext::U512(value.as_u512()),
            FheType::Euint1024 => TestingPlaintext::U1024(value.as_u1024()),
            FheType::Euint2048 => TestingPlaintext::U2048(value.as_u2048()),
        }
    }
}

impl TryFrom<(String, String)> for TestingPlaintext {
    type Error = anyhow::Error;
    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        let ptx = TypedPlaintext {
            bytes: value.0.into(),
            fhe_type: FheType::from_str_name(&value.1)
                .ok_or(anyhow::anyhow!("Conversion failed for {}", &value.1))?
                as i32,
        };
        Ok(ptx.into())
    }
}

impl From<(String, FheType)> for TestingPlaintext {
    fn from(value: (String, FheType)) -> Self {
        TypedPlaintext {
            bytes: value.0.into(),
            fhe_type: value.1 as i32,
        }
        .into()
    }
}

impl From<(Vec<u8>, FheType)> for TestingPlaintext {
    fn from(value: (Vec<u8>, FheType)) -> Self {
        TypedPlaintext {
            bytes: value.0,
            fhe_type: value.1 as i32,
        }
        .into()
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

async fn get_storage(pub_path: Option<&Path>, data_id: &str, data_type: &str) -> FileStorage {
    // Try first with centralized storage
    let mut storage = FileStorage::new(pub_path, StorageType::PUB, None).unwrap();
    let url = storage.compute_url(data_id, data_type).unwrap();
    if storage.data_exists(&url).await.unwrap() {
        tracing::info!("Using centralized storage at url {}", url);
    } else {
        // Try with the threshold storage
        storage = FileStorage::new(pub_path, StorageType::PUB, Some(1)).unwrap();
        tracing::info!(
            "Fallback to threshold file storage with path {:?}",
            storage.root_dir()
        );
    }
    storage
}

async fn load_material_from_storage<T>(
    pub_path: Option<&Path>,
    key_id: &str,
    data_type: PubDataType,
) -> T
where
    T: DeserializeOwned + Unversionize + Named + Send,
    <T as tfhe_versionable::VersionizeOwned>::VersionedOwned: Send,
{
    let storage = get_storage(pub_path, key_id, &data_type.to_string()).await;
    let material: T = read_versioned_at_request_id(
        &storage,
        &RequestId {
            request_id: key_id.to_string(),
        },
        &data_type.to_string(),
    )
    .await
    .unwrap();
    material
}

pub async fn load_server_key_from_storage(
    pub_path: Option<&Path>,
    key_id: &str,
) -> tfhe::ServerKey {
    load_material_from_storage(pub_path, key_id, PubDataType::ServerKey).await
}

pub async fn load_sns_key_from_storage(
    pub_path: Option<&Path>,
    key_id: &str,
) -> SwitchAndSquashKey {
    load_material_from_storage(pub_path, key_id, PubDataType::SnsKey).await
}

pub async fn load_pk_from_storage(pub_path: Option<&Path>, key_id: &str) -> FhePublicKey {
    let storage = get_storage(pub_path, key_id, &PubDataType::PublicKey.to_string()).await;
    let wrapped_pk = read_pk_at_request_id(
        &storage,
        &RequestId {
            request_id: key_id.to_string(),
        },
    )
    .await
    .unwrap();
    let WrappedPublicKeyOwned::Compact(pk) = wrapped_pk;
    pk
}

pub async fn load_crs_from_storage(pub_path: Option<&Path>, crs_id: &str) -> CompactPkeCrs {
    load_material_from_storage(pub_path, crs_id, PubDataType::CRS).await
}

async fn load_material_from_any_pub_storage<T>(
    pub_path: Option<&Path>,
    key_id: &str,
    data_type: PubDataType,
) -> T
where
    T: DeserializeOwned + Unversionize + Named + Send,
{
    let storage = FileStorage::new(pub_path, StorageType::PUB, None).unwrap();
    let url = storage.compute_url(key_id, &data_type.to_string()).unwrap();
    if storage.data_exists(&url).await.unwrap() {
        tracing::info!(
            "Server key exists at {} for type {}",
            url,
            data_type.to_string()
        );
        storage.read_data(&url).await.unwrap()
    } else {
        // Try with the threshold storage
        let storage = FileStorage::new(pub_path, StorageType::PUB, Some(1)).unwrap();
        let url = storage.compute_url(key_id, &data_type.to_string()).unwrap();
        tracing::info!(
            "Fallback to threshold file storage for server key at {} for data type {}",
            url,
            data_type.to_string()
        );
        storage.read_data(&url).await.unwrap()
    }
}

async fn load_server_key_from_any_pub_storage(pub_path: Option<&Path>, key_id: &str) -> ServerKey {
    load_material_from_any_pub_storage(pub_path, key_id, PubDataType::ServerKey).await
}

async fn load_sns_key_from_any_pub_storage(
    pub_path: Option<&Path>,
    key_id: &str,
) -> SwitchAndSquashKey {
    load_material_from_any_pub_storage(pub_path, key_id, PubDataType::SnsKey).await
}

/// This function should be used for testing only and it can panic.
pub async fn compute_cipher_from_stored_key(
    pub_path: Option<&Path>,
    msg: TestingPlaintext,
    key_id: &str,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat, FheType) {
    let pk = load_pk_from_storage(pub_path, key_id).await;
    //Setting the server key as we may need id to expand the ciphertext during compute_cipher
    let server_key = load_server_key_from_any_pub_storage(pub_path, key_id).await;

    // compute_cipher can take a long time since it may do SnS
    if enc_config.precompute_sns {
        let sns_key = load_sns_key_from_any_pub_storage(pub_path, key_id).await;
        let (send, recv) = tokio::sync::oneshot::channel();
        rayon::spawn_fifo(move || {
            let _ = send.send(compute_cipher(
                msg,
                &pk,
                Some(&server_key),
                Some(&sns_key),
                enc_config,
            ));
        });
        recv.await.unwrap()
    } else {
        let (send, recv) = tokio::sync::oneshot::channel();
        rayon::spawn_fifo(move || {
            let _ = send.send(compute_cipher(
                msg,
                &pk,
                Some(&server_key),
                None,
                enc_config,
            ));
        });
        recv.await.unwrap()
    }
}

/// Purge any kind of data, regardless of type, for a specific request ID.
///
/// This function should be used for testing only and it can panic.
pub async fn purge(
    pub_path: Option<&Path>,
    priv_path: Option<&Path>,
    id: &str,
    amount_parties: usize,
) {
    let req_id: RequestId = id.to_string().try_into().unwrap();
    let mut pub_storage = FileStorage::new(pub_path, StorageType::PUB, None).unwrap();
    delete_all_at_request_id(&mut pub_storage, &req_id).await;
    let mut priv_storage = FileStorage::new(priv_path, StorageType::PRIV, None).unwrap();
    delete_all_at_request_id(&mut priv_storage, &req_id).await;

    for i in 1..=amount_parties {
        let mut threshold_pub = FileStorage::new(pub_path, StorageType::PUB, Some(i)).unwrap();
        let mut threshold_priv = FileStorage::new(priv_path, StorageType::PRIV, Some(i)).unwrap();
        delete_all_at_request_id(&mut threshold_pub, &req_id).await;
        delete_all_at_request_id(&mut threshold_priv, &req_id).await;
    }
}

#[cfg(any(test, feature = "testing"))]
pub(crate) mod setup {
    use crate::consts::{
        TEST_THRESHOLD_CRS_ID_10P, TEST_THRESHOLD_CRS_ID_13P, TEST_THRESHOLD_KEY_ID_10P,
        TEST_THRESHOLD_KEY_ID_13P,
    };
    use crate::util::key_setup::{
        ensure_central_crs_exists, ensure_central_keys_exist, ensure_client_keys_exist,
        ThresholdSigningKeyConfig,
    };
    use crate::{
        consts::{
            KEY_PATH_PREFIX, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_CRS_ID, TEST_CENTRAL_KEY_ID,
            TEST_PARAM, TEST_THRESHOLD_CRS_ID_4P, TEST_THRESHOLD_KEY_ID_4P, TMP_PATH_PREFIX,
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
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    use kms_grpc::kms::v1::RequestId;
    use kms_grpc::rpc_types::SIGNING_KEY_ID;

    pub async fn ensure_dir_exist() {
        tokio::fs::create_dir_all(TMP_PATH_PREFIX).await.unwrap();
        tokio::fs::create_dir_all(KEY_PATH_PREFIX).await.unwrap();
    }

    async fn testing_material() {
        ensure_dir_exist().await;
        ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;
        central_material(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_TEST_ID,
            &TEST_CENTRAL_CRS_ID,
        )
        .await;
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_4P,
            &TEST_THRESHOLD_CRS_ID_4P,
            4,
        )
        .await;
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_10P,
            &TEST_THRESHOLD_CRS_ID_10P,
            10,
        )
        .await;
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_13P,
            &TEST_THRESHOLD_CRS_ID_13P,
            13,
        )
        .await;
    }

    pub(crate) async fn ensure_testing_material_exists() {
        testing_material().await;
    }

    #[cfg(feature = "slow_tests")]
    async fn default_material() {
        use crate::consts::{
            DEFAULT_CENTRAL_CRS_ID, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM,
            DEFAULT_THRESHOLD_CRS_ID_10P, DEFAULT_THRESHOLD_CRS_ID_13P,
            DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_KEY_ID_10P,
            DEFAULT_THRESHOLD_KEY_ID_13P, DEFAULT_THRESHOLD_KEY_ID_4P, OTHER_CENTRAL_DEFAULT_ID,
        };
        ensure_dir_exist().await;
        ensure_client_keys_exist(None, &SIGNING_KEY_ID, true).await;
        central_material(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_DEFAULT_ID,
            &DEFAULT_CENTRAL_CRS_ID,
        )
        .await;
        threshold_material(
            &DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID_4P,
            &DEFAULT_THRESHOLD_CRS_ID_4P,
            4,
        )
        .await;
        threshold_material(
            &DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID_10P,
            &DEFAULT_THRESHOLD_CRS_ID_10P,
            10,
        )
        .await;
        threshold_material(
            &DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID_13P,
            &DEFAULT_THRESHOLD_CRS_ID_13P,
            13,
        )
        .await;
    }

    async fn central_material(
        params: &DKGParams,
        fhe_key_id: &RequestId,
        other_fhe_key_id: &RequestId,
        crs_id: &RequestId,
    ) {
        let mut central_pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
        let mut central_priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();

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
        amount_parties: usize,
    ) {
        let mut threshold_pub_storages = Vec::with_capacity(amount_parties);
        for i in 1..=amount_parties {
            threshold_pub_storages.push(FileStorage::new(None, StorageType::PUB, Some(i)).unwrap());
        }
        let mut threshold_priv_storages = Vec::with_capacity(amount_parties);
        for i in 1..=amount_parties {
            threshold_priv_storages
                .push(FileStorage::new(None, StorageType::PRIV, Some(i)).unwrap());
        }

        ensure_threshold_server_signing_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            &SIGNING_KEY_ID,
            true,
            ThresholdSigningKeyConfig::AllParties(amount_parties),
        )
        .await;
        ensure_threshold_keys_exist(
            &mut threshold_pub_storages,
            &mut threshold_priv_storages,
            params.to_owned(),
            fhe_key_id,
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
    pub(crate) async fn ensure_default_material_exists() {
        default_material().await;
    }
}

// NOTE: this test stays out of the setup module
// because we don't want it to have the "testing" feature
#[tokio::test]
async fn test_purge() {
    use itertools::Itertools;
    use kms_grpc::rpc_types::PrivDataType;

    let temp_dir = tempfile::tempdir().unwrap();
    let test_prefix = Some(temp_dir.path());
    let mut central_pub_storage = FileStorage::new(test_prefix, StorageType::PUB, None).unwrap();
    let mut central_priv_storage = FileStorage::new(test_prefix, StorageType::PRIV, None).unwrap();
    // Check no keys exist
    assert!(central_pub_storage
        .all_urls(&PubDataType::VerfKey.to_string())
        .await
        .unwrap()
        .is_empty());
    assert!(central_priv_storage
        .all_urls(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap()
        .is_empty());
    // Create keys to be deleted
    assert!(
        crate::util::key_setup::ensure_central_server_signing_keys_exist(
            &mut central_pub_storage,
            &mut central_priv_storage,
            &kms_grpc::rpc_types::SIGNING_KEY_ID,
            true,
        )
        .await
    );
    // Validate the keys were made
    let pub_urls = central_pub_storage
        .all_urls(&PubDataType::VerfKey.to_string())
        .await
        .unwrap();
    assert_eq!(pub_urls.len(), 1);
    let priv_urls = central_priv_storage
        .all_urls(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap();
    assert_eq!(priv_urls.len(), 1);
    purge(
        test_prefix,
        test_prefix,
        pub_urls.keys().collect_vec()[0],
        1,
    )
    .await;
    // Check the keys were deleted
    assert!(central_pub_storage
        .all_urls(&PubDataType::VerfKey.to_string())
        .await
        .unwrap()
        .is_empty());
    assert!(central_priv_storage
        .all_urls(&PrivDataType::SigningKey.to_string())
        .await
        .unwrap()
        .is_empty());
}
