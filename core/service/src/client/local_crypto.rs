use crate::cryptography::decompression::test_tools::compress_serialize_versioned;
use crate::util::key_setup::FhePublicKey;
use crate::vault::storage::file::FileStorage;
use crate::vault::storage::{StorageReader, StorageType, read_versioned_at_request_id};
use kms_grpc::RequestId;
use kms_grpc::kms::v1::{CiphertextFormat, TypedPlaintext};
use kms_grpc::rpc_types::PubDataType;
use serde::de::DeserializeOwned;
use std::path::Path;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::named::Named;
use tfhe::prelude::SquashNoise;
use tfhe::prelude::Tagged;
use tfhe::safe_serialization::safe_serialize;
use tfhe::xof_key_set::CompressedXofKeySet;
use tfhe::{
    FheBool, FheTypes, FheUint8, FheUint16, FheUint32, FheUint64, FheUint128, FheUint160,
    FheUint256, HlCompactable, HlCompressible, HlExpandable, HlSquashedNoiseCompressible,
    ServerKey, Unversionize, Versionize,
};
use threshold_execution::tfhe_internals::utils::expanded_encrypt;

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
        CiphertextFormat::SmallCompressed => (compress_serialize_versioned(ct), ct_format),
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

/// Controls how client-side encryption serializes ciphertexts for the KMS.
#[derive(Clone, Copy, Debug)]
pub struct EncryptionConfig {
    pub compression: bool,
    pub precompute_sns: bool,
}

impl EncryptionConfig {
    /// Maps the client-side encryption toggles to the corresponding wire format.
    pub fn try_into_ciphertext_format(self) -> anyhow::Result<CiphertextFormat> {
        match (self.compression, self.precompute_sns) {
            (true, true) => Ok(CiphertextFormat::BigCompressed),
            (true, false) => Ok(CiphertextFormat::SmallCompressed),
            (false, true) => Ok(CiphertextFormat::BigExpanded),
            (false, false) => Ok(CiphertextFormat::SmallExpanded),
        }
    }
}

/// Encrypts a plaintext using locally available public key material.
pub fn compute_cipher(
    msg: TestingPlaintext,
    pk: &FhePublicKey,
    server_key: Option<ServerKey>,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat, FheTypes) {
    if let Some(s) = server_key {
        tfhe::set_server_key(s);
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

/// Plaintext wrapper used by `core-client` for local encryption and result validation.
///
/// The name is retained for compatibility with existing callers even though these
/// conversions are now part of the non-test client support surface.
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
    /// Returns the bit width of the plaintext type.
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

    /// Returns the FHE wire type associated with the plaintext.
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

/// Loads versioned public material from a local public storage tree.
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
    read_versioned_at_request_id(&storage, key_id, &data_type.to_string())
        .await
        .unwrap()
}

/// Loads the public key associated with a key id from local public storage.
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
    read_versioned_at_request_id(&storage, key_id, &PubDataType::PublicKey.to_string())
        .await
        .expect("load_pk_from_pub_storage failed")
}

/// Encrypts against the public material already downloaded to local storage.
///
/// Probes the local public storage for the key id and loads whichever layout is
/// present: the default `CompressedXofKeySet`, or the legacy `PublicKey` +
/// `ServerKey` pair. Panics if neither is present.
pub async fn compute_cipher_from_stored_key(
    pub_path: Option<&Path>,
    msg: TestingPlaintext,
    key_id: &RequestId,
    storage_prefix: Option<&str>,
    enc_config: EncryptionConfig,
) -> (Vec<u8>, CiphertextFormat, FheTypes) {
    let probe = FileStorage::new(pub_path, StorageType::PUB, storage_prefix).unwrap();
    let compressed_type = PubDataType::CompressedXofKeySet.to_string();
    let public_key_type = PubDataType::PublicKey.to_string();

    let (pk, server_key) = if probe.data_exists(key_id, &compressed_type).await.unwrap() {
        let compressed_keyset: CompressedXofKeySet = load_material_from_pub_storage(
            pub_path,
            key_id,
            PubDataType::CompressedXofKeySet,
            storage_prefix,
        )
        .await;
        compressed_keyset
            .decompress()
            .expect("decompress of CompressedXofKeySet is infallible")
            .into_raw_parts()
    } else if probe.data_exists(key_id, &public_key_type).await.unwrap() {
        let pk = load_pk_from_pub_storage(pub_path, key_id, storage_prefix).await;
        let server_key: ServerKey = load_material_from_pub_storage(
            pub_path,
            key_id,
            PubDataType::ServerKey,
            storage_prefix,
        )
        .await;
        (pk, server_key)
    } else {
        panic!("no compressed or uncompressed key material for key_id {key_id}");
    };

    let (send, recv) = tokio::sync::oneshot::channel();
    rayon::spawn_fifo(move || {
        let _ = send.send(compute_cipher(msg, &pk, Some(server_key), enc_config));
    });
    recv.await.unwrap()
}

#[cfg(test)]
mod tests {
    use super::{EncryptionConfig, TestingPlaintext};
    use kms_grpc::kms::v1::{CiphertextFormat, TypedPlaintext};

    #[test]
    fn encryption_config_maps_to_wire_formats() {
        assert_eq!(
            EncryptionConfig {
                compression: true,
                precompute_sns: true,
            }
            .try_into_ciphertext_format()
            .unwrap(),
            CiphertextFormat::BigCompressed
        );
        assert_eq!(
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            }
            .try_into_ciphertext_format()
            .unwrap(),
            CiphertextFormat::SmallCompressed
        );
        assert_eq!(
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            }
            .try_into_ciphertext_format()
            .unwrap(),
            CiphertextFormat::BigExpanded
        );
        assert_eq!(
            EncryptionConfig {
                compression: false,
                precompute_sns: false,
            }
            .try_into_ciphertext_format()
            .unwrap(),
            CiphertextFormat::SmallExpanded
        );
    }

    #[test]
    fn testing_plaintext_round_trips_from_typed_plaintext() {
        let typed = TypedPlaintext::from_u32(42);
        let plaintext = TestingPlaintext::try_from(typed.clone()).unwrap();

        assert_eq!(plaintext, TestingPlaintext::U32(42));
        assert_eq!(plaintext.bits(), 32);
        assert_eq!(TypedPlaintext::from(plaintext), typed);
    }

    #[test]
    fn testing_plaintext_rejects_unknown_fhe_type() {
        let result = TestingPlaintext::try_from(TypedPlaintext {
            bytes: vec![0],
            fhe_type: -1,
        });

        assert!(result.is_err());
    }
}
