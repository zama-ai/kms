use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::kms::{FheType, RequestId};
use crate::rpc::rpc_types::Plaintext;
use crate::rpc::rpc_types::{PubDataType, WrappedPublicKeyOwned};
use crate::util::key_setup::FhePublicKey;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{
    delete_all_at_request_id, read_versioned_at_request_id, StorageReader,
};
use crate::vault::storage::{read_pk_at_request_id, StorageType};
use distributed_decryption::expanded_encrypt;
use std::path::Path;
use tfhe::safe_serialization::safe_serialize;
use tfhe::zk::CompactPkePublicParams;
use tfhe::{
    set_server_key, FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048,
    FheUint256, FheUint32, FheUint4, FheUint512, FheUint64, FheUint8, ProvenCompactCiphertextList,
    ServerKey,
};

macro_rules! serialize_ctxt {
    ($t:ty,$msg:expr,$pk:expr,$server_key:expr,$num_bits:expr,$compression:expr) => {{
        let ct: $t = expanded_encrypt!($pk, $msg, $num_bits);
        let compression_key = $server_key.and_then(|k| k.clone().into_raw_parts().2);
        if let Some(compression_key) = compression_key {
            if $compression {
                crate::cryptography::decompression::test_tools::compress_serialize_versioned(
                    ct,
                    &compression_key,
                )
            } else {
                // NOTE: we have to copy this chunk of code because we can't write
                // if let Some(x) = y && z
                let mut serialized_ct = Vec::new();
                safe_serialize(&ct, &mut serialized_ct, crate::consts::SAFE_SER_SIZE_LIMIT)
                    .unwrap();
                serialized_ct
            }
        } else {
            let mut serialized_ct = Vec::new();
            safe_serialize(&ct, &mut serialized_ct, crate::consts::SAFE_SER_SIZE_LIMIT).unwrap();
            serialized_ct
        }
    }};
}

pub fn compute_cipher(
    msg: TypedPlaintext,
    pk: &FhePublicKey,
    server_key: Option<&ServerKey>,
    compression: bool,
) -> (Vec<u8>, FheType) {
    let fhe_type = msg.into();
    (
        match msg {
            TypedPlaintext::Bool(x) => serialize_ctxt!(
                FheBool,
                x as u8,
                pk,
                server_key,
                FheBool::num_bits(),
                compression
            ),
            TypedPlaintext::U4(x) => {
                serialize_ctxt!(
                    FheUint4,
                    x,
                    pk,
                    server_key,
                    FheUint4::num_bits(),
                    compression
                )
            }
            TypedPlaintext::U8(x) => {
                serialize_ctxt!(
                    FheUint8,
                    x,
                    pk,
                    server_key,
                    FheUint8::num_bits(),
                    compression
                )
            }
            TypedPlaintext::U16(x) => serialize_ctxt!(
                FheUint16,
                x,
                pk,
                server_key,
                FheUint16::num_bits(),
                compression
            ),
            TypedPlaintext::U32(x) => serialize_ctxt!(
                FheUint32,
                x,
                pk,
                server_key,
                FheUint32::num_bits(),
                compression
            ),
            TypedPlaintext::U64(x) => serialize_ctxt!(
                FheUint64,
                x,
                pk,
                server_key,
                FheUint64::num_bits(),
                compression
            ),
            TypedPlaintext::U128(x) => serialize_ctxt!(
                FheUint128,
                x,
                pk,
                server_key,
                FheUint128::num_bits(),
                compression
            ),
            TypedPlaintext::U160(x) => serialize_ctxt!(
                FheUint160,
                x,
                pk,
                server_key,
                FheUint160::num_bits(),
                compression
            ),
            TypedPlaintext::U256(x) => serialize_ctxt!(
                FheUint256,
                x,
                pk,
                server_key,
                FheUint256::num_bits(),
                compression
            ),
            TypedPlaintext::U512(x) => serialize_ctxt!(
                FheUint512,
                x,
                pk,
                server_key,
                FheUint512::num_bits(),
                compression
            ),
            TypedPlaintext::U1024(x) => serialize_ctxt!(
                FheUint1024,
                x,
                pk,
                server_key,
                FheUint1024::num_bits(),
                compression
            ),
            TypedPlaintext::U2048(x) => serialize_ctxt!(
                FheUint2048,
                x,
                pk,
                server_key,
                FheUint2048::num_bits(),
                compression
            ),
        },
        fhe_type,
    )
}

// TODO not sure how to deal with that clippy warning
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedPlaintext {
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

impl From<TypedPlaintext> for FheType {
    fn from(val: TypedPlaintext) -> FheType {
        match val {
            TypedPlaintext::Bool(_) => FheType::Ebool,
            TypedPlaintext::U4(_) => FheType::Euint4,
            TypedPlaintext::U8(_) => FheType::Euint8,
            TypedPlaintext::U16(_) => FheType::Euint16,
            TypedPlaintext::U32(_) => FheType::Euint32,
            TypedPlaintext::U64(_) => FheType::Euint64,
            TypedPlaintext::U128(_) => FheType::Euint128,
            TypedPlaintext::U160(_) => FheType::Euint160,
            TypedPlaintext::U256(_) => FheType::Euint256,
            TypedPlaintext::U512(_) => FheType::Euint512,
            TypedPlaintext::U1024(_) => FheType::Euint1024,
            TypedPlaintext::U2048(_) => FheType::Euint2048,
        }
    }
}

impl From<TypedPlaintext> for Plaintext {
    fn from(val: TypedPlaintext) -> Plaintext {
        match val {
            TypedPlaintext::Bool(x) => Plaintext::from_bool(x),
            TypedPlaintext::U4(x) => Plaintext::from_u4(x),
            TypedPlaintext::U8(x) => Plaintext::from_u8(x),
            TypedPlaintext::U16(x) => Plaintext::from_u16(x),
            TypedPlaintext::U32(x) => Plaintext::from_u32(x),
            TypedPlaintext::U64(x) => Plaintext::from_u64(x),
            TypedPlaintext::U128(x) => Plaintext::from_u128(x),
            TypedPlaintext::U160(x) => Plaintext::from_u160(x),
            TypedPlaintext::U256(x) => Plaintext::from_u256(x),
            TypedPlaintext::U512(x) => Plaintext::from_u512(x),
            TypedPlaintext::U1024(x) => Plaintext::from_u1024(x),
            TypedPlaintext::U2048(x) => Plaintext::from_u2048(x),
        }
    }
}

impl TypedPlaintext {
    /// Return the number of bits in the plaintext.
    pub fn bits(&self) -> usize {
        match self {
            TypedPlaintext::Bool(_) => 1,
            TypedPlaintext::U4(_) => 4,
            TypedPlaintext::U8(_) => 8,
            TypedPlaintext::U16(_) => 16,
            TypedPlaintext::U32(_) => 32,
            TypedPlaintext::U64(_) => 64,
            TypedPlaintext::U128(_) => 128,
            TypedPlaintext::U160(_) => 160,
            TypedPlaintext::U256(_) => 256,
            TypedPlaintext::U512(_) => 512,
            TypedPlaintext::U1024(_) => 1024,
            TypedPlaintext::U2048(_) => 2048,
        }
    }
}

impl From<Plaintext> for TypedPlaintext {
    fn from(value: Plaintext) -> Self {
        match value.fhe_type {
            FheType::Ebool => TypedPlaintext::Bool(value.as_bool()),
            FheType::Euint4 => TypedPlaintext::U4(value.as_u4()),
            FheType::Euint8 => TypedPlaintext::U8(value.as_u8()),
            FheType::Euint16 => TypedPlaintext::U16(value.as_u16()),
            FheType::Euint32 => TypedPlaintext::U32(value.as_u32()),
            FheType::Euint64 => TypedPlaintext::U64(value.as_u64()),
            FheType::Euint128 => TypedPlaintext::U128(value.as_u128()),
            FheType::Euint160 => TypedPlaintext::U160(value.as_u160()),
            FheType::Euint256 => TypedPlaintext::U256(value.as_u256()),
            FheType::Euint512 => TypedPlaintext::U512(value.as_u512()),
            FheType::Euint1024 => TypedPlaintext::U1024(value.as_u1024()),
            FheType::Euint2048 => TypedPlaintext::U2048(value.as_u2048()),
        }
    }
}

impl TryFrom<(String, String)> for Plaintext {
    type Error = anyhow::Error;
    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        let ptx = Plaintext {
            bytes: value.0.into(),
            fhe_type: FheType::try_from(value.1)?,
        };
        Ok(ptx)
    }
}

impl From<(String, FheType)> for Plaintext {
    fn from(value: (String, FheType)) -> Self {
        Plaintext {
            bytes: value.0.into(),
            fhe_type: value.1,
        }
    }
}

impl TryFrom<(String, String)> for TypedPlaintext {
    type Error = anyhow::Error;
    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        let ptx = Plaintext {
            bytes: value.0.into(),
            fhe_type: FheType::try_from(value.1)?,
        };
        Ok(ptx.into())
    }
}

impl From<(String, FheType)> for TypedPlaintext {
    fn from(value: (String, FheType)) -> Self {
        Plaintext {
            bytes: value.0.into(),
            fhe_type: value.1,
        }
        .into()
    }
}

impl From<(Vec<u8>, FheType)> for TypedPlaintext {
    fn from(value: (Vec<u8>, FheType)) -> Self {
        Plaintext {
            bytes: value.0,
            fhe_type: value.1,
        }
        .into()
    }
}

/// Implement from native type
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

impl From<tfhe::integer::bigint::U256> for TypedPlaintext {
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
        tracing::info!("Trying centralized storage at url {}", url);
    } else {
        // Try with the threshold storage
        tracing::info!("Fallback to threshold file storage with url {}", url);
        storage = FileStorage::new(pub_path, StorageType::PUB, Some(1)).unwrap();
    }
    storage
}

pub async fn load_server_key_from_storage(
    pub_path: Option<&Path>,
    key_id: &str,
) -> tfhe::ServerKey {
    let storage = get_storage(pub_path, key_id, &PubDataType::ServerKey.to_string()).await;
    let sk: tfhe::ServerKey = read_versioned_at_request_id(
        &storage,
        &RequestId {
            request_id: key_id.to_string(),
        },
        &PubDataType::ServerKey.to_string(),
    )
    .await
    .unwrap();
    sk
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

pub async fn load_crs_from_storage(
    pub_path: Option<&Path>,
    crs_id: &str,
) -> CompactPkePublicParams {
    let storage = get_storage(pub_path, crs_id, &PubDataType::CRS.to_string()).await;
    let crs: CompactPkePublicParams = read_versioned_at_request_id(
        &storage,
        &RequestId {
            request_id: crs_id.to_string(),
        },
        &PubDataType::CRS.to_string(),
    )
    .await
    .unwrap();
    crs
}

pub async fn compute_proven_ct_from_stored_key_and_serialize(
    pub_path: Option<&Path>,
    msgs: Vec<TypedPlaintext>,
    key_id: &str,
    crs_id: &str,
    metadata: &[u8],
) -> Vec<u8> {
    let ctlist = compute_proven_ct_from_stored_key(pub_path, msgs, key_id, crs_id, metadata).await;
    let mut out = Vec::new();
    safe_serialize(&ctlist, &mut out, SAFE_SER_SIZE_LIMIT).unwrap();
    out
}

/// This function should be used for testing only and it can panic.
pub async fn compute_proven_ct_from_stored_key(
    pub_path: Option<&Path>,
    msgs: Vec<TypedPlaintext>,
    key_id: &str,
    crs_id: &str,
    metadata: &[u8],
) -> ProvenCompactCiphertextList {
    // Try first with centralized storage
    let storage = FileStorage::new(pub_path, StorageType::PUB, None).unwrap();
    let key_url = storage
        .compute_url(key_id, &PubDataType::PublicKey.to_string())
        .unwrap();
    let crs_url = storage
        .compute_url(crs_id, &PubDataType::CRS.to_string())
        .unwrap();
    let (pk, pp) = if storage.data_exists(&key_url).await.unwrap() {
        let wrapped_pk = read_pk_at_request_id(
            &storage,
            &RequestId {
                request_id: key_id.to_owned(),
            },
        )
        .await
        .unwrap();
        let WrappedPublicKeyOwned::Compact(pk) = wrapped_pk;
        let pp: CompactPkePublicParams = storage.read_data(&crs_url).await.unwrap();
        (pk, pp)
    } else {
        // Try with the threshold storage
        let storage = FileStorage::new(pub_path, StorageType::PUB, Some(1)).unwrap();
        let crs_url = storage
            .compute_url(crs_id, &PubDataType::CRS.to_string())
            .unwrap();
        let wrapped_pk = read_pk_at_request_id(
            &storage,
            &RequestId {
                request_id: key_id.to_owned(),
            },
        )
        .await
        .unwrap();
        let WrappedPublicKeyOwned::Compact(pk) = wrapped_pk;
        let pp: CompactPkePublicParams = storage.read_data(&crs_url).await.unwrap();
        (pk, pp)
    };

    let mut compact_list_builder = ProvenCompactCiphertextList::builder(&pk);
    for msg in msgs {
        let msg_as_ptx: Plaintext = msg.into();
        match msg.into() {
            FheType::Ebool => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u8(), msg.bits())
                .unwrap(),
            FheType::Euint4 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u4(), msg.bits())
                .unwrap(),
            FheType::Euint8 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u8(), msg.bits())
                .unwrap(),
            FheType::Euint16 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u16(), msg.bits())
                .unwrap(),
            FheType::Euint32 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u32(), msg.bits())
                .unwrap(),
            FheType::Euint64 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u64(), msg.bits())
                .unwrap(),
            FheType::Euint128 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u128(), msg.bits())
                .unwrap(),
            FheType::Euint160 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u160(), msg.bits())
                .unwrap(),
            FheType::Euint256 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u256(), msg.bits())
                .unwrap(),
            FheType::Euint512 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u512(), msg.bits())
                .unwrap(),
            FheType::Euint1024 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u1024(), msg.bits())
                .unwrap(),
            FheType::Euint2048 => compact_list_builder
                .push_with_num_bits(msg_as_ptx.as_u2048(), msg.bits())
                .unwrap(),
        };
    }
    compact_list_builder
        .build_with_proof_packed(&pp, metadata, tfhe::zk::ZkComputeLoad::Proof)
        .unwrap()
}

pub async fn get_server_key_from_storage(pub_path: Option<&Path>, key_id: &str) -> ServerKey {
    let storage = FileStorage::new(pub_path, StorageType::PUB, None).unwrap();
    let url = storage
        .compute_url(key_id, &PubDataType::ServerKey.to_string())
        .unwrap();
    tracing::info!("🚧 Using key: {}", url);
    if storage.data_exists(&url).await.unwrap() {
        tracing::info!("Trying centralized storage");
        storage.read_data(&url).await.unwrap()
    } else {
        // Try with the threshold storage
        tracing::info!("Fallback to threshold file storage");
        let storage = FileStorage::new(pub_path, StorageType::PUB, Some(1)).unwrap();
        let url = storage
            .compute_url(key_id, &PubDataType::ServerKey.to_string())
            .unwrap();
        storage.read_data(&url).await.unwrap()
    }
}

/// This function should be used for testing only and it can panic.
async fn compute_generic_cipher_from_stored_key(
    pub_path: Option<&Path>,
    msg: TypedPlaintext,
    key_id: &str,
    compression: bool,
) -> (Vec<u8>, FheType) {
    let pk = load_pk_from_storage(pub_path, key_id).await;
    //Setting the server key as we may need id to expand the ciphertext during compute_cipher
    let server_key = get_server_key_from_storage(pub_path, key_id).await;
    set_server_key(server_key.clone());
    compute_cipher(msg, &pk, Some(&server_key), compression)
}

pub async fn compute_cipher_from_stored_key(
    pub_path: Option<&Path>,
    msg: TypedPlaintext,
    key_id: &str,
) -> (Vec<u8>, FheType) {
    compute_generic_cipher_from_stored_key(pub_path, msg, key_id, false).await
}

pub async fn compute_compressed_cipher_from_stored_key(
    pub_path: Option<&Path>,
    msg: TypedPlaintext,
    key_id: &str,
) -> (Vec<u8>, FheType) {
    compute_generic_cipher_from_stored_key(pub_path, msg, key_id, true).await
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
    use crate::consts::TEST_THRESHOLD_KEY_ID_7P;
    use crate::kms::RequestId;
    use crate::util::key_setup::{
        ensure_central_crs_exists, ensure_central_keys_exist, ensure_client_keys_exist,
        ThresholdSigningKeyConfig,
    };
    use crate::{
        consts::{
            KEY_PATH_PREFIX, OTHER_CENTRAL_TEST_ID, SIGNING_KEY_ID, TEST_CENTRAL_CRS_ID,
            TEST_CENTRAL_KEY_ID, TEST_PARAM, TEST_THRESHOLD_CRS_ID_4P, TEST_THRESHOLD_CRS_ID_7P,
            TEST_THRESHOLD_KEY_ID_4P, TMP_PATH_PREFIX,
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
        // Generate for 10 parties with a different key ID
        threshold_material(
            &TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_7P,
            &TEST_THRESHOLD_CRS_ID_7P,
            7,
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
            DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_CRS_ID_7P, DEFAULT_THRESHOLD_KEY_ID_4P,
            DEFAULT_THRESHOLD_KEY_ID_7P, OTHER_CENTRAL_DEFAULT_ID,
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
            &DEFAULT_THRESHOLD_KEY_ID_7P,
            &DEFAULT_THRESHOLD_CRS_ID_7P,
            7,
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
    use crate::rpc::rpc_types::PrivDataType;
    use itertools::Itertools;

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
            &crate::consts::SIGNING_KEY_ID,
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
